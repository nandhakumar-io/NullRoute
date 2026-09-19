"""Deterministic, vendor-aware application of remediation CLI onto a running
configuration.

Why this exists
---------------
A remediation is a *delta* -- a handful of CLI commands such as::

    conf t
    line vty 0 4
    transport input ssh
    end

A device's running configuration is the *whole* thing. Before this module,
the Change Request flow compared / validated the two directly, which meant:

  * the "current vs proposed" diff showed the entire running config as
    removed and four lines as added (nothing lined up, nothing was "what
    changed");
  * OPA and Batfish validated the four-line snippet as if it were a device,
    so almost every parameter came back null / NOT_APPLICABLE;
  * post-deployment verification compared the hash of the full running
    config with the hash of the four-line snippet -- which can never match,
    so every deployment ended up "DRIFTED".

`apply_commands()` fixes the root cause: it produces the configuration the
device is *expected to have after the change*. That single artifact is what
we diff for the reviewer, what OPA/Batfish validate, and what post-deploy
verification is compared against. The delta itself is still what gets pushed.

Design notes
------------
* Pure functions, no I/O, no AI. The same input always yields the same
  output, so it is testable and auditable.
* Four merge styles, chosen from the vendor / config shape:
    ios      hierarchical, indentation based (Cisco IOS/IOS-XE, Arista EOS)
    set      flat `set ...` / `delete ...` (Junos display-set, PAN-OS)
    fortios  config/edit/next/end blocks
    append   fallback: the delta is appended under a marker and the result is
             flagged LOW confidence so the UI never presents it as exact.
* The merge is a *preview* of the intended end state. It is deliberately not
  the source of truth for compliance: after deployment the real device is
  re-collected and re-evaluated by OPA/Batfish. Where the engine cannot be
  exact it says so through `MergeResult.confidence` and `warnings`.
"""
from __future__ import annotations

import difflib
import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Vendor -> merge style
# ---------------------------------------------------------------------------

_IOS_LIKE = ("cisco", "arista")
_SET_LIKE = ("juniper", "paloalto")


def normalize_vendor_key(vendor: Optional[str]) -> str:
    """Collapse the many spellings the platform sees ("Cisco IOS-XE",
    "cisco_systems", "Palo Alto Networks", "FortiOS" ...) to one key."""
    v = re.sub(r"[^a-z0-9]+", "_", (vendor or "").strip().lower()).strip("_")
    if not v or v in ("ad_hoc", "adhoc", "unknown", "none"):
        return ""
    if v.startswith("cisco") or v in ("ios", "ios_xe", "iosxe"):
        return "cisco"
    if v.startswith("arista") or v == "eos":
        return "arista"
    if v.startswith("juniper") or v == "junos":
        return "juniper"
    if v.startswith(("fortinet", "fortigate", "fortios")):
        return "fortigate"
    if v.startswith("palo") or v in ("pan_os", "panos"):
        return "paloalto"
    return v


def detect_style(vendor: Optional[str], current_text: Optional[str] = None) -> str:
    key = normalize_vendor_key(vendor)
    text = current_text or ""
    if key in _IOS_LIKE:
        return "ios"
    if key == "fortigate":
        return "fortios"
    if key in _SET_LIKE:
        # Junos can be stored in hierarchical `{ }` form; we can only merge
        # the flat display-set form exactly.
        if key == "juniper" and re.search(r"^\s*[\w\-\[\] ]+\s*\{\s*$", text, re.M):
            return "append"
        return "set"
    # Unknown vendor: infer from the shape of the current config if we can.
    if re.search(r"^\s*set\s+\S+", text, re.M) and not re.search(r"^\s*config\s+\S+", text, re.M):
        return "set"
    if re.search(r"^\s*config\s+\S+", text, re.M) and re.search(r"^\s*end\s*$", text, re.M):
        return "fortios"
    if re.search(r"^\s*(hostname|interface|line vty|ip ssh)\b", text, re.M):
        return "ios"
    return "append"


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class AppliedCommand:
    command: str
    action: str            # added | replaced | removed | unchanged | appended | created_context
    context: Optional[str] = None
    detail: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {"command": self.command, "action": self.action,
                "context": self.context, "detail": self.detail}


@dataclass
class MergeResult:
    merged_text: str
    style: str
    confidence: str                              # HIGH | MEDIUM | LOW
    applied: List[AppliedCommand] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    commands: List[str] = field(default_factory=list)      # normalized, deployable

    @property
    def changed(self) -> bool:
        return any(a.action not in ("unchanged",) for a in self.applied)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "style": self.style,
            "confidence": self.confidence,
            "applied": [a.to_dict() for a in self.applied],
            "warnings": list(self.warnings),
            "commands": list(self.commands),
            "changed": self.changed,
        }


# ---------------------------------------------------------------------------
# Placeholders (<SYSLOG_HOST> ...)
# ---------------------------------------------------------------------------

_PLACEHOLDER_RE = re.compile(r"<([A-Z][A-Z0-9_]{1,40})>")


def find_placeholders(text: str) -> List[str]:
    """Unresolved `<UPPER_SNAKE>` site-value placeholders, in first-seen order."""
    seen: List[str] = []
    for m in _PLACEHOLDER_RE.finditer(text or ""):
        if m.group(1) not in seen:
            seen.append(m.group(1))
    return seen


def fill_placeholders(text: str, values: Optional[Dict[str, str]]) -> str:
    if not values:
        return text

    def _sub(m: "re.Match[str]") -> str:
        v = values.get(m.group(1))
        return str(v) if v not in (None, "") else m.group(0)

    return _PLACEHOLDER_RE.sub(_sub, text)


# ---------------------------------------------------------------------------
# Snippet normalisation
# ---------------------------------------------------------------------------

# Lines that only make sense when typing at a console, never as a pushed
# command. `send_config_set` (netmiko) enters config mode itself, so sending
# `conf t` from inside config mode is an error and `end` would drop us to
# exec mode so that every later line silently fails.
_WRAPPER_RE = re.compile(
    r"^(conf(?:igure)?(?:\s+t(?:erminal)?)?|end|"
    r"wr(?:ite)?(?:\s+mem(?:ory)?)?|copy\s+run\S*\s+start\S*|commit(?:\s+.*)?|save|"
    r"exit\s+configuration-mode|top)$",
    re.I,
)

_IOS_CONTEXT_RE = re.compile(
    r"^(line\s+(vty|con|console|aux|tty)\b.*|line\s+\d+.*|interface\s+\S+.*|router\s+\S+.*|"
    r"ip(v6)?\s+access-list\s+\S+.*|management\s+\S+.*|radius\s+server\s+\S+.*|"
    r"tacacs\s+server\s+\S+.*|aaa\s+group\s+server\s+\S+.*|class-map\s+.+|policy-map\s+.+|"
    r"vlan\s+\d+.*|control-plane\b.*|crypto\s+(map|isakmp|ikev2|pki)\s+.+|route-map\s+.+|"
    r"vrf\s+definition\s+\S+.*|ip\s+vrf\s+\S+.*)$",
    re.I,
)


def _is_comment(s: str) -> bool:
    return s.startswith("!") or s.startswith("#")


def _clean(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip())


def snippet_lines(snippet: str) -> List[str]:
    return [ln.rstrip() for ln in (snippet or "").replace("\r\n", "\n").split("\n")]


def is_full_config(text: str) -> bool:
    """Heuristic: is `text` a whole device configuration rather than a delta?"""
    lines = [l for l in snippet_lines(text) if l.strip() and not _is_comment(l.strip())]
    if len(lines) < 8:
        return False
    return bool(
        re.search(r"^\s*(hostname\s+\S+|version\s+\d|set\s+system\s+host-name|"
                  r"config\s+system\s+global|set\s+deviceconfig\s+system)", text, re.M | re.I)
    )


# ---------------------------------------------------------------------------
# IOS-style hierarchical config
# ---------------------------------------------------------------------------

@dataclass
class _Node:
    text: str                                   # header/leaf text, stripped
    children: List["_Node"] = field(default_factory=list)
    raw_block: Optional[List[str]] = None       # verbatim lines for banner blocks


_BANNER_RE = re.compile(r"^banner\s+(\w[\w\-]*)\s+(\S.*)?$", re.I)


def _banner_delim(rest: str) -> Optional[str]:
    rest = rest.strip()
    if not rest:
        return None
    if rest.startswith("^C"):
        return "^C"
    return rest[0]


def _parse_ios(text: str) -> List[_Node]:
    lines = text.replace("\r\n", "\n").split("\n")
    roots: List[_Node] = []
    i = 0
    while i < len(lines):
        raw = lines[i]
        if not raw.strip():
            i += 1
            continue
        indent = len(raw) - len(raw.lstrip(" \t"))
        stripped = raw.strip()

        if indent == 0:
            node = _Node(text=stripped)
            # Multi-line banner: keep verbatim until the closing delimiter.
            bm = _BANNER_RE.match(stripped)
            if bm and bm.group(2):
                delim = _banner_delim(bm.group(2))
                body = bm.group(2).strip()
                if delim and body.count(delim) < 2:
                    block = [raw]
                    i += 1
                    while i < len(lines):
                        block.append(lines[i])
                        if delim in lines[i]:
                            break
                        i += 1
                    node.raw_block = block
            roots.append(node)
        else:
            if roots:
                roots[-1].children.append(_Node(text=stripped))
            else:  # stray indented line before any header; treat as top level
                roots.append(_Node(text=stripped))
        i += 1
    return roots


def _emit_ios(roots: Sequence[_Node]) -> str:
    out: List[str] = []
    for n in roots:
        if n.raw_block is not None:
            out.extend(n.raw_block)
        else:
            out.append(n.text)
        for c in n.children:
            out.append(f" {c.text}")
    return "\n".join(out).rstrip("\n") + "\n"


# Single-valued commands: a new value REPLACES the existing line that shares
# this prefix (in the same context) instead of adding a second line.
_SINGLE_VALUED_PREFIXES: Tuple[str, ...] = (
    "ip ssh version", "ip ssh time-out", "ip ssh authentication-retries",
    "exec-timeout", "session-timeout", "transport input", "transport output",
    "transport preferred", "logging trap", "logging buffered", "logging source-interface",
    "logging facility", "logging console", "logging monitor",
    "aaa authentication login", "aaa authentication enable", "aaa authorization exec",
    "aaa authorization commands", "aaa accounting exec", "aaa accounting commands",
    "hostname", "banner motd", "banner login", "banner exec", "enable secret", "enable password",
    "login authentication", "authorization exec", "accounting exec", "access-class",
    "ip domain-name", "ip domain name", "clock timezone", "service timestamps log",
    "service timestamps debug", "snmp-server location", "snmp-server contact",
    "ip http authentication", "ip http port", "ip http secure-port", "idle-timeout",
    "privilege level", "protocol", "login",
)

# `no X` prints back as `no X` in the running config on IOS-family devices
# (the feature is default-on, so the *negation* is what is stored).
_SHOWN_AS_NO = {
    "ip http server", "ip domain-lookup", "ip domain lookup", "ip source-route",
    "ip bootp server", "ip finger", "service pad", "ip http secure-server",
}

# `no <prefix> <value>` removes one token from a space separated value list.
_LIST_VALUED_PREFIXES: Tuple[str, ...] = ("transport input", "transport output", "transport preferred")


def _single_prefix(cmd: str) -> Optional[str]:
    lc = cmd.lower()
    best: Optional[str] = None
    for p in _SINGLE_VALUED_PREFIXES:
        if lc == p or lc.startswith(p + " "):
            if best is None or len(p) > len(best):
                best = p
    return best


def _list_prefix(cmd: str) -> Optional[str]:
    lc = cmd.lower()
    for p in _LIST_VALUED_PREFIXES:
        if lc == p or lc.startswith(p + " "):
            return p
    return None


def _ctx_key(header: str) -> str:
    return _clean(header).lower()


def _is_vty_header(header: str) -> bool:
    return bool(re.match(r"^line\s+vty\b", header.strip(), re.I))


@dataclass
class _Cmd:
    context: Optional[str]   # header text, or None for a global command
    command: str             # stripped; may start with "no "
    is_header: bool = False  # a context opener with no leaf of its own


def _parse_snippet_ios(snippet: str) -> Tuple[List[_Cmd], List[str]]:
    """Turn a (possibly flat, possibly indented) IOS snippet into
    (context, command) pairs.

    * Indented snippet: nesting is taken from the indentation.
    * Flat snippet (what the validated templates use): a line matching a
      known context opener (`line vty ...`, `interface ...`) opens a context
      that lasts until a wrapper (`conf t` / `end`), `exit`, a lone `!`, or
      the next opener.
    """
    lines = snippet_lines(snippet)
    uses_indent = any(
        l[:1] in (" ", "\t") and l.strip() and not _is_comment(l.strip()) for l in lines
    )
    body = [(l, l.strip()) for l in lines if l.strip() and not _is_comment(l.strip()) or l.strip() == "!"]
    out: List[_Cmd] = []

    if uses_indent:
        stack: List[Tuple[int, str]] = []
        seq = [(len(r) - len(r.lstrip(" \t")), s) for r, s in body if s != "!"]
        for k, (indent, s) in enumerate(seq):
            if _WRAPPER_RE.match(s) or s.lower() == "exit":
                stack = []
                continue
            while stack and stack[-1][0] >= indent:
                stack.pop()
            context = stack[0][1] if stack else None
            nxt_indent = seq[k + 1][0] if k + 1 < len(seq) else -1
            out.append(_Cmd(context=context, command=s, is_header=nxt_indent > indent))
            stack.append((indent, s))
        return out, []

    ctx: Optional[str] = None
    for _raw, s in body:
        if s == "!":
            ctx = None
            continue
        if _WRAPPER_RE.match(s) or s.lower() == "exit":
            ctx = None
            continue
        if _IOS_CONTEXT_RE.match(s) and not s.lower().startswith("no "):
            ctx = s
            out.append(_Cmd(context=None, command=s, is_header=True))
            continue
        out.append(_Cmd(context=ctx, command=s))
    return out, []


def _find_root(roots: List[_Node], header: str) -> List[int]:
    key = _ctx_key(header)
    idx = [i for i, n in enumerate(roots) if _ctx_key(n.text) == key]
    if idx:
        return idx
    if _is_vty_header(header):
        return [i for i, n in enumerate(roots) if _is_vty_header(n.text)]
    return []


def _insert_position_global(roots: List[_Node], cmd: str) -> int:
    first = cmd.split()[0].lower() if cmd.split() else ""
    last = -1
    for i, n in enumerate(roots):
        if n.text.split() and n.text.split()[0].lower() == first and n.text != "!":
            last = i
    if last >= 0:
        return last + 1
    # before a trailing `end`, else at the very end
    if roots and roots[-1].text.lower() == "end":
        return len(roots) - 1
    return len(roots)


def _apply_ios(current: str, snippet: str) -> MergeResult:
    roots = _parse_ios(current)
    cmds, warnings = _parse_snippet_ios(snippet)
    applied: List[AppliedCommand] = []

    for c in cmds:
        cmd = c.command
        neg = cmd.lower().startswith("no ")
        body = cmd[3:].strip() if neg else cmd

        # A context opener carries no leaf of its own; the context is created
        # lazily below, only when a child command actually needs it.
        if c.is_header:
            continue

        # ---- locate the container list ---------------------------------
        if c.context:
            targets = _find_root(roots, c.context)
            if not targets:
                node = _Node(text=c.context)
                pos = len(roots) - 1 if roots and roots[-1].text.lower() == "end" else len(roots)
                roots.insert(pos, node)
                targets = [pos]
                applied.append(AppliedCommand(c.context, "created_context", None,
                                              "Context did not exist on the device and was created."))
            containers = [(roots[i].children, roots[i].text) for i in targets]
        else:
            containers = [(roots, None)]

        for container, ctxname in containers:
            is_global = ctxname is None
            texts = [n.text for n in container]

            if neg:
                # ---- removal ---------------------------------------------
                lp = _list_prefix(body)
                if lp is not None and body.lower() != lp:
                    tokens_remove = body[len(lp):].split()
                    hit = False
                    for n in list(container):
                        if n.text.lower().startswith(lp + " ") or n.text.lower() == lp:
                            cur_tokens = n.text[len(lp):].split()
                            keep = [t for t in cur_tokens if t.lower() not in {x.lower() for x in tokens_remove}]
                            if keep != cur_tokens:
                                hit = True
                                if keep:
                                    n.text = f"{lp} {' '.join(keep)}"
                                else:
                                    container.remove(n)
                    applied.append(AppliedCommand(cmd, "removed" if hit else "unchanged", ctxname,
                                                  None if hit else "Value was not present."))
                    continue

                doomed = [n for n in container
                          if n.text.lower() == body.lower() or n.text.lower().startswith(body.lower() + " ")]
                for n in doomed:
                    container.remove(n)
                if body.lower() in _SHOWN_AS_NO and is_global:
                    if not any(n.text.lower() == cmd.lower() for n in container):
                        container.insert(_insert_position_global(container, cmd) if is_global else len(container),
                                         _Node(text=cmd))
                        applied.append(AppliedCommand(cmd, "replaced" if doomed else "added", ctxname))
                    else:
                        applied.append(AppliedCommand(cmd, "unchanged", ctxname, "Already disabled."))
                elif doomed:
                    applied.append(AppliedCommand(cmd, "removed", ctxname))
                else:
                    applied.append(AppliedCommand(cmd, "unchanged", ctxname, "Nothing to remove."))
                continue

            # ---- positive command -----------------------------------------
            if any(t.lower() == cmd.lower() for t in texts):
                applied.append(AppliedCommand(cmd, "unchanged", ctxname, "Already present."))
                continue

            # `X` supersedes an explicit `no X`
            for n in list(container):
                if n.text.lower() == f"no {cmd}".lower():
                    container.remove(n)

            sp = _single_prefix(cmd)
            replaced = False
            if sp is not None:
                for n in container:
                    if n.text.lower() == sp or n.text.lower().startswith(sp + " "):
                        # `login` alone must not clobber `login local`-style siblings
                        if sp == "login" and n.text.lower() != "login" and cmd.lower() != "login":
                            pass
                        n.text = cmd
                        replaced = True
                        break
            if replaced:
                applied.append(AppliedCommand(cmd, "replaced", ctxname))
                continue

            new = _Node(text=cmd)
            if is_global:
                container.insert(_insert_position_global(container, cmd), new)
            else:
                container.append(new)
            applied.append(AppliedCommand(cmd, "added", ctxname))

    return MergeResult(
        merged_text=_emit_ios(roots), style="ios", confidence="HIGH",
        applied=applied, warnings=warnings,
    )


# ---------------------------------------------------------------------------
# set-style (Junos display-set / PAN-OS)
# ---------------------------------------------------------------------------

def _apply_set(current: str, snippet: str) -> MergeResult:
    lines = [l.rstrip() for l in current.replace("\r\n", "\n").split("\n") if l.strip()]
    applied: List[AppliedCommand] = []
    for raw in snippet_lines(snippet):
        s = raw.strip()
        if not s or _is_comment(s) or _WRAPPER_RE.match(s):
            continue
        low = s.lower()
        if low.startswith("delete "):
            path = _clean(s[7:]).lower()
            keep, gone = [], 0
            for ln in lines:
                body = _clean(ln)
                b = body.lower()
                if b.startswith("set "):
                    b2 = b[4:]
                    if b2 == path or b2.startswith(path + " "):
                        gone += 1
                        continue
                keep.append(ln)
            lines = keep
            applied.append(AppliedCommand(s, "removed" if gone else "unchanged", None,
                                          None if gone else "Nothing matched."))
        elif low.startswith("set "):
            if any(_clean(l).lower() == _clean(s).lower() for l in lines):
                applied.append(AppliedCommand(s, "unchanged", None, "Already present."))
            else:
                lines.append(s)
                applied.append(AppliedCommand(s, "added"))
        else:
            applied.append(AppliedCommand(s, "unchanged", None, "Unrecognised set-style command; ignored."))
    return MergeResult("\n".join(lines) + "\n", "set", "HIGH", applied, [])


# ---------------------------------------------------------------------------
# FortiOS blocks
# ---------------------------------------------------------------------------

@dataclass
class _FNode:
    kind: str                 # config | edit
    name: str
    leaves: List[Tuple[str, str]] = field(default_factory=list)   # (key, value-string)
    children: List["_FNode"] = field(default_factory=list)


def _parse_fortios(text: str) -> List[_FNode]:
    root = _FNode("root", "")
    stack = [root]
    for raw in text.replace("\r\n", "\n").split("\n"):
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        low = s.lower()
        if low.startswith("config "):
            n = _FNode("config", s[7:].strip())
            stack[-1].children.append(n)
            stack.append(n)
        elif low.startswith("edit "):
            n = _FNode("edit", s[5:].strip())
            stack[-1].children.append(n)
            stack.append(n)
        elif low in ("next", "end"):
            if len(stack) > 1:
                stack.pop()
        elif low.startswith("set "):
            parts = s[4:].split(None, 1)
            k, v = parts[0], (parts[1] if len(parts) > 1 else "")
            leaves = stack[-1].leaves
            for i, (ek, _) in enumerate(leaves):
                if ek == k:
                    leaves[i] = (k, v)
                    break
            else:
                leaves.append((k, v))
        elif low.startswith("unset "):
            k = s[6:].split()[0]
            stack[-1].leaves = [(ek, ev) for ek, ev in stack[-1].leaves if ek != k]
    return root.children


def _emit_fortios(nodes: Sequence[_FNode], depth: int = 0) -> List[str]:
    pad = "    " * depth
    out: List[str] = []
    for n in nodes:
        out.append(f"{pad}{n.kind} {n.name}")
        for k, v in n.leaves:
            out.append(f"{pad}    set {k} {v}".rstrip())
        out.extend(_emit_fortios(n.children, depth + 1))
        out.append(f"{pad}{'next' if n.kind == 'edit' else 'end'}")
    return out


def _apply_fortios(current: str, snippet: str) -> MergeResult:
    tree = _parse_fortios(current)
    applied: List[AppliedCommand] = []
    stack: List[_FNode] = []
    top = tree

    def _child(container: List[_FNode], kind: str, name: str) -> _FNode:
        for c in container:
            if c.kind == kind and c.name.strip('"').lower() == name.strip('"').lower():
                return c
        n = _FNode(kind, name)
        container.append(n)
        return n

    for raw in snippet_lines(snippet):
        s = raw.strip()
        if not s or _is_comment(s):
            continue
        low = s.lower()
        if low.startswith("config "):
            container = stack[-1].children if stack else top
            stack.append(_child(container, "config", s[7:].strip()))
        elif low.startswith("edit "):
            if stack:
                stack.append(_child(stack[-1].children, "edit", s[5:].strip()))
        elif low in ("next", "end"):
            if stack:
                stack.pop()
        elif low.startswith("set ") and stack:
            parts = s[4:].split(None, 1)
            k, v = parts[0], (parts[1] if len(parts) > 1 else "")
            leaves = stack[-1].leaves
            existing = next(((i, ev) for i, (ek, ev) in enumerate(leaves) if ek == k), None)
            path = " / ".join(n.name for n in stack)
            if existing and existing[1] == v:
                applied.append(AppliedCommand(s, "unchanged", path, "Already set."))
            elif existing:
                leaves[existing[0]] = (k, v)
                applied.append(AppliedCommand(s, "replaced", path))
            else:
                leaves.append((k, v))
                applied.append(AppliedCommand(s, "added", path))
        elif low.startswith("unset ") and stack:
            parts = s[6:].split()
            k = parts[0]
            vals = parts[1:]
            leaves = stack[-1].leaves
            path = " / ".join(n.name for n in stack)
            existing = next(((i, ev) for i, (ek, ev) in enumerate(leaves) if ek == k), None)
            if not existing:
                applied.append(AppliedCommand(s, "unchanged", path, "Not set."))
            elif vals:
                keep = [t for t in existing[1].split() if t.strip('"') not in {v.strip('"') for v in vals}]
                if keep:
                    leaves[existing[0]] = (k, " ".join(keep))
                else:
                    leaves.pop(existing[0])
                applied.append(AppliedCommand(s, "removed", path))
            else:
                leaves.pop(existing[0])
                applied.append(AppliedCommand(s, "removed", path))
    return MergeResult("\n".join(_emit_fortios(tree)) + "\n", "fortios", "MEDIUM", applied, [
        "FortiOS merge re-serialises the whole block tree; ordering/indentation may differ from the device's own output."
    ])


# ---------------------------------------------------------------------------
# Fallback
# ---------------------------------------------------------------------------

def _apply_append(current: str, snippet: str, style_hint: str = "append") -> MergeResult:
    cmds = [ln.strip() for ln in snippet_lines(snippet)
            if ln.strip() and not _is_comment(ln.strip()) and not _WRAPPER_RE.match(ln.strip())]
    body = (current.rstrip("\n") + "\n") if current.strip() else ""
    merged = body + "! ---- proposed change (appended; exact placement unknown for this platform) ----\n"
    merged += "\n".join(cmds) + ("\n" if cmds else "")
    applied = [AppliedCommand(c, "appended") for c in cmds]
    return MergeResult(
        merged, "append", "LOW", applied,
        ["The platform's configuration syntax cannot be merged exactly; the change is shown appended. "
         "The real post-change state is confirmed only after deployment by re-collecting the device."],
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def apply_commands(current_config: Optional[str], snippet: str, vendor: Optional[str] = None) -> MergeResult:
    """Return the configuration expected after applying `snippet` to
    `current_config` for `vendor`."""
    current = (current_config or "").replace("\r\n", "\n")
    style = detect_style(vendor, current)
    if not current.strip():
        # Nothing to merge onto: the "resulting" config is just the delta.
        res = _apply_append("", snippet)
        res.warnings = ["No current configuration is on record for this device, so only the change itself is shown."]
        res.commands = deployable_commands(snippet, vendor)
        return res
    if style == "ios":
        res = _apply_ios(current, snippet)
    elif style == "set":
        res = _apply_set(current, snippet)
    elif style == "fortios":
        res = _apply_fortios(current, snippet)
    else:
        res = _apply_append(current, snippet)
    res.commands = deployable_commands(snippet, vendor)
    return res


def deployable_commands(snippet: str, vendor: Optional[str] = None) -> List[str]:
    """The exact, ordered lines to push in configuration mode.

    * strips console-only wrappers (`conf t`, `end`, `write memory`, `commit`)
      -- the deployer enters config mode, saves, and commits itself;
    * strips comments / blank lines;
    * for hierarchical (IOS-like) syntax, inserts `exit` when a context
      block ends, so a snippet made of several blocks still lands each
      command in the right mode (previously `end` between blocks dropped the
      session to exec mode and every later block failed silently).
    """
    style = detect_style(vendor, snippet)
    out: List[str] = []
    if style != "ios":
        for raw in snippet_lines(snippet):
            s = raw.strip()
            if not s or _is_comment(s) or _WRAPPER_RE.match(s):
                continue
            out.append(s)
        return out

    in_ctx = False
    uses_indent = any(l[:1] in (" ", "\t") and l.strip() and not _is_comment(l.strip()) for l in snippet_lines(snippet))
    for raw in snippet_lines(snippet):
        s = raw.strip()
        if not s:
            continue
        if _is_comment(s):
            if s == "!" and in_ctx and not uses_indent:
                out.append("exit")
                in_ctx = False
            continue
        if _WRAPPER_RE.match(s):
            if in_ctx:
                out.append("exit")
                in_ctx = False
            continue
        if s.lower() == "exit":
            if in_ctx:
                out.append("exit")
                in_ctx = False
            continue
        if uses_indent:
            indent = len(raw) - len(raw.lstrip(" \t"))
            if indent == 0 and in_ctx:
                out.append("exit")
                in_ctx = False
            out.append(s)
            # a non-indented line followed by indented ones becomes a context;
            # emit an exit lazily on the next indent==0 line / end of input.
            if indent == 0:
                in_ctx = True
            continue
        if _IOS_CONTEXT_RE.match(s) and not s.lower().startswith("no "):
            if in_ctx:
                out.append("exit")
            out.append(s)
            in_ctx = True
        else:
            out.append(s)
    if in_ctx:
        out.append("exit")
    return out


def expand_vty_contexts(snippet: str, current_config: Optional[str]) -> str:
    """If the snippet configures `line vty A B` but the device also has other
    `line vty` blocks (e.g. `line vty 5 15`), repeat the block for each so
    the pushed change matches what the merge preview shows."""
    if not current_config or not snippet:
        return snippet
    headers: List[str] = []
    for ln in current_config.replace("\r\n", "\n").split("\n"):
        if ln and ln[0] not in " \t" and _is_vty_header(ln):
            h = ln.strip()
            if h not in headers:
                headers.append(h)
    if len(headers) <= 1:
        return snippet

    lines = snippet_lines(snippet)
    out: List[str] = []
    i = 0
    while i < len(lines):
        s = lines[i].strip()
        if _is_vty_header(s) and not s.lower().startswith("no "):
            block: List[str] = []
            j = i + 1
            while j < len(lines):
                t = lines[j].strip()
                if not t or _is_comment(t) and t != "!":
                    j += 1
                    continue
                if _WRAPPER_RE.match(t) or t.lower() == "exit" or t == "!" or _IOS_CONTEXT_RE.match(t):
                    break
                block.append(t)
                j += 1
            for h in headers:
                out.append(h)
                out.extend(block)
                out.append("exit")
            i = j
            if i < len(lines) and lines[i].strip().lower() == "exit":
                i += 1
            continue
        out.append(lines[i])
        i += 1
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Canonicalisation & hashing (volatile lines removed)
# ---------------------------------------------------------------------------

_VOLATILE_RE = re.compile(
    r"^(building configuration|current configuration\s*:|using \d+ out of \d+ bytes|"
    r"!\s*(last configuration change|nvram config last updated|no configuration change since|time:|"
    r"command:|running configuration last done at)|"
    r"ntp clock-period|##\s*last (changed|commit)|#config-version|#conf_file_ver|"
    r"! ?device:|! ?boot system|end$)",
    re.I,
)


def canonical_lines(text: Optional[str]) -> List[str]:
    out: List[str] = []
    for ln in (text or "").replace("\r\n", "\n").split("\n"):
        s = ln.rstrip()
        if not s.strip():
            continue
        st = s.strip()
        if st == "!" or (st.startswith("!") and _VOLATILE_RE.match(st)):
            continue
        if _VOLATILE_RE.match(st):
            continue
        out.append(s)
    return out


def canonical_text(text: Optional[str]) -> str:
    return "\n".join(canonical_lines(text))


def config_hash(text: Optional[str]) -> str:
    return hashlib.sha256(canonical_text(text).encode("utf-8")).hexdigest()


def raw_hash(text: Optional[str]) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Diff helpers
# ---------------------------------------------------------------------------

def diff_stats(before: Optional[str], after: Optional[str]) -> Dict[str, int]:
    a = canonical_lines(before)
    b = canonical_lines(after)
    added = removed = 0
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(a=a, b=b, autojunk=False).get_opcodes():
        if tag in ("replace", "delete"):
            removed += i2 - i1
        if tag in ("replace", "insert"):
            added += j2 - j1
    return {"added": added, "removed": removed, "unchanged": max(0, len(a) - removed), "total_after": len(b)}


def line_delta(before: Optional[str], after: Optional[str]) -> Dict[str, List[str]]:
    """Order-insensitive multiset delta of canonical lines."""
    from collections import Counter
    cb, ca = Counter(canonical_lines(before)), Counter(canonical_lines(after))
    added = list((ca - cb).elements())
    removed = list((cb - ca).elements())
    return {"added": added, "removed": removed}


def missing_expected(expected_text: Optional[str], actual_text: Optional[str]) -> List[str]:
    """Lines present in `expected_text` but absent from `actual_text`
    (order-insensitive)."""
    return line_delta(actual_text, expected_text)["added"]
