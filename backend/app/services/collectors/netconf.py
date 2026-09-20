"""NETCONF collector (Phase 7).

Uses ncclient (open-source, MIT/Apache-licensed) when available. Offline-safe
fallback mirrors ssh.py: no ImportError at module import time if ncclient
isn't installed, only a failed CollectionResult at call time.

Config text strategy
--------------------
The downstream pipeline (parsers.py, topology_extractor.py, Batfish) all
expect vendor CLI text -- NOT raw XML.  We therefore retrieve the running
configuration in the *display* / *set* format that each vendor supports via
the ``execute-command`` RPC (Juniper Junos) or via a Netconf ``<rpc>`` that
requests ``text`` output encoding.  If the text-format RPC fails, we fall
back to stripping the XML tags so at least the value content flows through
the AI/RAG normalization stage rather than being silently discarded.
"""
from __future__ import annotations

import re
import time
import xml.etree.ElementTree as ET
from typing import Optional

from app.models.db import Device
from app.services.collectors.base import BaseCollector, CollectionResult, StructuredResult, timed, timed_structured
from app.services.openbao_service import DeviceCredentials, redact_secret_values

try:
    from ncclient import manager as ncclient_manager
    from ncclient.transport.ssh import SSHSession
    import paramiko
    
    # ncclient inherently ignores algorithms inherited from ssh_config; re-enable legacy algorithms explicitly
    if not getattr(paramiko.Transport, "_nulled_algorithms_patched", False):
        _orig_transport_init = paramiko.Transport.__init__
        def _patched_transport_init(self, *args, **kwargs):
            if "disabled_algorithms" not in kwargs:
                kwargs["disabled_algorithms"] = dict(pubkeys=[], kex=[])
            _orig_transport_init(self, *args, **kwargs)
        paramiko.Transport.__init__ = _patched_transport_init
        
        # Patch SSHSession to fallback to keyboard-interactive for IOS-XE / Junos
        from ncclient.transport import AuthenticationError
        _orig_auth = SSHSession._auth
        def _patched_auth(self, *args, **kwargs):
            try:
                _orig_auth(self, *args, **kwargs)
            except AuthenticationError as e:
                import logging
                logger = logging.getLogger("ncclient.transport.ssh")
                logger.error(f"Fallback caught AuthenticationError: {repr(e)}")
                
                # Extract username and password from args/kwargs for fallback
                username = kwargs.get("username") if "username" in kwargs else (args[0] if len(args) > 0 else None)
                password = kwargs.get("password") if "password" in kwargs else (args[1] if len(args) > 1 else None)
                logger.error(f"Fallback extracted user: {username}, pw len: {len(password) if password else 0}")
                
                if password and username:
                    import logging
                    logging.getLogger("ncclient.transport.ssh").info(
                        "falling back to auth_interactive for %s", username
                    )
                    def _interactive_handler(title, instructions, prompt_list):
                        return [password for _ in prompt_list]
                    self._transport.auth_interactive(username, _interactive_handler)
                else:
                    raise e
        SSHSession._auth = _patched_auth
        
        paramiko.Transport._nulled_algorithms_patched = True
    NCCLIENT_AVAILABLE = True
except ImportError:  # pragma: no cover
    NCCLIENT_AVAILABLE = False
    ncclient_manager = None

_NETCONF_VENDORS = {"juniper", "cisco_xe", "cisco"}

# ncclient device_params -> selects the vendor-specific handler that knows
# how to parse that platform's <hello> capabilities / RPC quirks. Leaving
# this as None (the previous behavior for every non-Juniper vendor) forces
# ncclient to fall back to its generic/default handler, which is more
# likely to mis-negotiate capabilities on IOS-XE and occasionally surface
# as an intermittent "collection worked last time, fails this time" NETCONF
# result -- one contributor to the reported flakiness.
_DEVICE_PARAMS = {
    "juniper": {"name": "junos"},
    "cisco_xe": {"name": "iosxe"},
    "cisco": {"name": "iosxe"},
}

# Transient/retryable ncclient-or-lower-level error substrings: devices
# commonly cap concurrent NETCONF sessions (Juniper/IOS-XE default to a
# small limit) and briefly refuse a new session while a previous one is
# still tearing down, or a first SSH key-exchange attempt is dropped under
# load. A single short-backoff retry resolves the vast majority of these
# without masking a genuine, persistent failure (auth/unreachable/etc. are
# not in this list and fail immediately).
_RETRYABLE_ERROR_SUBSTRINGS = (
    "session limit",
    "too many sessions",
    "resource temporarily unavailable",
    "connection reset",
    "eof",
    "unable to open shell",
)


def _xml_to_cli_text(xml_string: str) -> str:
    """Best-effort: strip XML tags, returning only whitespace-normalised content.

    This is a last-resort fallback so that NETCONF-collected configs remain
    partially useful even when the vendor-specific text-format RPC is not
    available.  It is NOT a proper XML-to-CLI converter; the AI/RAG pipeline
    will handle the unrecognised lines.
    """
    try:
        from lxml import etree
        # Remove XML namespaces so tags are simpler
        clean = re.sub(r'\s+xmlns(?::\w+)?="[^"]*"', "", xml_string)
        root = etree.fromstring(clean.encode('utf-8'))
        lines = []
        for elem in root.iter():
            tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
            text = (elem.text or "").strip()
            if text:
                lines.append(f"{tag} {text}")
        return "\n".join(lines)
    except Exception:
        # If XML is malformed strip tags with regex
        return re.sub(r"<[^>]+>", " ", xml_string)


def _get_juniper_cli_config(m) -> str:
    """Execute ``show configuration | display set`` via ncclient's RPC
    dispatch to obtain Junos set-format CLI text that the deterministic
    parser understands.

    Bug fixed here: this used to call
    ``m.dispatch(ncclient_manager.make_rpc_request(rpc_xml) if hasattr(...) else _raw_rpc(m, rpc_xml))``.
    `ncclient.manager` has no `make_rpc_request` attribute, so that
    `hasattr` check always evaluated False, and the `else` branch
    (`_raw_rpc`) itself already called `m._session.dispatch(rpc_xml)` and
    returned the *completed reply* -- which was then fed straight back into
    `m.dispatch(...)` a second time. Dispatching an already-built reply
    object always raised, so this path silently failed on every single
    call (caught by the bare `except` below) and every Juniper NETCONF
    collection fell back to the slower/lossier `get_config` + XML-tag-
    stripping path -- never the intended "display set" RPC. `Manager.
    dispatch()` is ncclient's own public entry point for a raw/custom RPC;
    call it directly, once.
    """
    rpc_xml = '<command format="text">show configuration | display set</command>'
    try:
        from ncclient.xml_ import to_ele
        reply = m.dispatch(to_ele(rpc_xml))
        raw = reply.xml if hasattr(reply, "xml") else str(reply)
        # Extract text content from the <output> wrapper Junos returns for
        # a text-format command RPC.
        match = re.search(r"<output[^>]*>(.*?)</output>", raw, re.DOTALL)
        if match:
            return match.group(1).strip()
        # Strip all tags as fallback
        return _xml_to_cli_text(raw)
    except Exception as e:
        import logging
        logging.getLogger("ncclient.collectors.netconf").warning(
            "Juniper 'display set' RPC failed, falling back to get-config: %r", e
        )
        return ""


class NetconfCollector(BaseCollector):
    transport = "netconf"

    @timed
    def collect_config(self, device: Device, credentials: DeviceCredentials) -> CollectionResult:
        if not NCCLIENT_AVAILABLE:
            return CollectionResult(
                success=False,
                vendor=device.vendor,
                hostname=device.hostname,
                error="ncclient is not installed; NETCONF collection unavailable in this environment",
            )

        vendor_key = (device.vendor or "").lower().replace(" ", "_")
        if vendor_key not in _NETCONF_VENDORS:
            return CollectionResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error=f"NETCONF collection not supported for vendor '{device.vendor}'",
            )

        management_address = getattr(device, "management_address", None) or device.hostname
        if not management_address:
            return CollectionResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error="Device has no management address/hostname to connect to",
            )

        secret = credentials.secret
        device_params = _DEVICE_PARAMS.get(vendor_key)
        connect_timeout = int(secret.get("timeout", 20))

        def _connect_and_collect():
            with ncclient_manager.connect(
                host=management_address,
                port=int(secret.get("port", 830)),
                username=secret.get("username"),
                password=secret.get("password"),
                hostkey_verify=False,
                # Never probe/wait on a local SSH agent or ~/.ssh/known_hosts
                # -- in a containerized backend these are usually absent,
                # but when present (or when the agent socket is
                # transiently unresponsive) paramiko's agent handshake can
                # add multi-second, inconsistent delays that look exactly
                # like "NETCONF collection sometimes just doesn't work".
                allow_agent=False,
                look_for_keys=False,
                device_params=device_params,
                timeout=connect_timeout,
            ) as m:
                # --- Juniper: prefer "display set" CLI text ---
                if vendor_key == "juniper":
                    cli_text = _get_juniper_cli_config(m)
                    if cli_text:
                        return cli_text
                    # Fallback: get-config and convert XML -> text
                    reply = m.get_config(source="running")
                    return _xml_to_cli_text(reply.data_xml)
                # Cisco / other: get-config returns XML; strip tags for parser
                reply = m.get_config(source="running")
                return _xml_to_cli_text(reply.data_xml)

        last_error: Optional[Exception] = None
        for attempt in range(2):  # one retry for transient session/limit errors
            try:
                raw_config = _connect_and_collect()
                last_error = None
                break
            except Exception as e:  # noqa: BLE001 -- ncclient raises many transport-specific errors
                last_error = e
                if attempt == 0 and any(s in str(e).lower() for s in _RETRYABLE_ERROR_SUBSTRINGS):
                    time.sleep(1.5)
                    continue
                break

        if last_error is not None:
            return CollectionResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error=redact_secret_values(f"{type(last_error).__name__}: {last_error}", secret),
            )

        return CollectionResult(
            success=True,
            vendor=device.vendor,
            hostname=device.hostname,
            raw_config=raw_config,
        )

    @timed_structured
    def get_interfaces(self, device: Device, credentials: DeviceCredentials) -> StructuredResult:
        if not NCCLIENT_AVAILABLE:
            return StructuredResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error="ncclient is not installed; NETCONF collection unavailable in this environment",
            )
        vendor_key = (device.vendor or "").lower().replace(" ", "_")
        if vendor_key not in _NETCONF_VENDORS:
            return StructuredResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error=f"NETCONF collection not supported for vendor '{device.vendor}'",
            )
        management_address = getattr(device, "management_address", None) or device.hostname
        if not management_address:
            return StructuredResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error="Device has no management address/hostname to connect to",
            )
        secret = credentials.secret
        device_params = _DEVICE_PARAMS.get(vendor_key)
        connect_timeout = int(secret.get("timeout", 20))

        def _connect_and_collect():
            with ncclient_manager.connect(
                host=management_address, port=int(secret.get("port", 830)),
                username=secret.get("username"), password=secret.get("password"),
                hostkey_verify=False, allow_agent=False, look_for_keys=False,
                device_params=device_params, timeout=connect_timeout,
            ) as m:
                rpc_filter = ('subtree', '<interfaces-state xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces"/>')
                reply = m.get(filter=rpc_filter)
                return reply.data_xml

        last_error: Optional[Exception] = None
        for attempt in range(2):
            try:
                raw_xml = _connect_and_collect()
                last_error = None
                break
            except Exception as e:  # noqa: BLE001
                last_error = e
                if attempt == 0 and any(s in str(e).lower() for s in _RETRYABLE_ERROR_SUBSTRINGS):
                    time.sleep(1.5)
                    continue
                break
        if last_error is not None:
            return StructuredResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error=redact_secret_values(f"{type(last_error).__name__}: {last_error}", secret),
            )

        interfaces = []
        try:
            # Remove namespaces so we can use simple XPath
            clean_xml = re.sub(r'\s+xmlns(?::\w+)?="[^"]*"', "", raw_xml)
            root = ET.fromstring(clean_xml.encode("utf-8"))
            for iface in root.findall(".//interfaces-state/interface"):
                name = (iface.findtext("name") or "").strip()
                if not name:
                    continue
                interfaces.append({
                    "name": name,
                    "admin_status": (iface.findtext("admin-status") or "unknown").strip(),
                    "oper_status": (iface.findtext("oper-status") or "unknown").strip(),
                    "mac_address": (iface.findtext("phys-address") or "").strip(),
                    "speed_bps": int(iface.findtext("speed") or 0) if (iface.findtext("speed") or "").strip().isdigit() else 0,
                })
        except Exception as e:  # noqa: BLE001
            return StructuredResult(
                success=False, vendor=device.vendor, hostname=device.hostname,
                error=f"Failed to parse ietf-interfaces XML: {e}",
            )

        return StructuredResult(
            success=True, vendor=device.vendor, hostname=device.hostname,
            data={"interfaces": interfaces, "interface_count": len(interfaces)},
        )