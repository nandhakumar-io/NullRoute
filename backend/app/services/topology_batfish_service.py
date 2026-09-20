"""Batfish-derived topology: interfaces, VLAN membership, VRFs, routes and
real layer-3 adjacency.

Uploading a configuration used to leave the Topology page empty:
`topology_service.refresh_device_topology()` (regex extractor) had no caller,
and the Batfish group scan returned interface/route frames that were never
persisted. This module turns a Batfish snapshot of one or more devices into
the same current-state tables the Topology page already reads
(NetworkInterface / VLAN / VRF / NetworkRoute / NetworkLink), so what is
shown is what Batfish actually modelled from the uploaded configs:

  interfaceProperties     -> interfaces (IP/mask, VRF, switchport mode,
                             access/native/allowed VLANs, SVIs, state)
  switchedVlanProperties  -> VLAN -> member interfaces per node
  routes                  -> routing table (local routes excluded)
  layer3Edges             -> adjacency between devices (link_type "batfish_l3")

Never fabricates: if Batfish is disabled/unavailable/errors, the caller gets
`engine="regex"` and the best-effort regex extractor is used instead; nothing
is guessed. VLAN *names* are not modelled by Batfish, so they are merged in
from the regex extractor when the config actually declares them.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import re
import shutil
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger("topology_batfish_service")

MAX_ROUTES_PER_DEVICE = 500
SOURCE_BATFISH = "batfish"
SOURCE_CONFIG = "config"
LINK_TYPE_BATFISH = "batfish_l3"

_IFACE_RE = re.compile(r"^(?P<node>.+?)\[(?P<iface>.+)\]$")
_SVI_RE = re.compile(r"^(?:vlan|irb\.?|vlanif)\s*(\d+)$", re.I)
_HOSTNAME_RE = re.compile(
    r"^\s*(?:hostname|set\s+system\s+host-name|set\s+hostname|host-name)\s+\"?([^\s\";]+)", re.I | re.M,
)


# ---------------------------------------------------------------------------
# Small, pure helpers (unit-tested with fake Batfish frames)
# ---------------------------------------------------------------------------

def _s(value: Any) -> Optional[str]:
    """Frame cell -> clean string (None for NaN/None/empty)."""
    if value is None:
        return None
    text = str(value).strip()
    if text in ("", "nan", "None", "NaN", "<NA>", "[]", "{}"):
        return None
    return text


def split_interface(ref: Any) -> Tuple[Optional[str], str]:
    """Batfish Interface -> (lower-cased node, interface name). Accepts the
    pybatfish Interface object or its "node[iface]" string form."""
    host = getattr(ref, "hostname", None)
    name = getattr(ref, "interface", None)
    if host and name:
        return str(host).lower(), str(name)
    m = _IFACE_RE.match(str(ref))
    if m:
        return m.group("node").lower(), m.group("iface")
    return None, str(ref)


def _iter_cells(value: Any) -> Iterable[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set, frozenset)):
        return list(value)
    text = _s(value)
    if text is None:
        return []
    if text.startswith("[") and text.endswith("]"):
        return [p.strip().strip("'\"") for p in text[1:-1].split(",") if p.strip()]
    return [text]


def _records(bf: Any, question: str, **kwargs: Any) -> List[Dict[str, Any]]:
    frame = getattr(bf.q, question)(**kwargs).answer().frame()
    return frame.to_dict(orient="records")


def _vlan_id(value: Any) -> Optional[str]:
    text = _s(value)
    if text is None:
        return None
    try:
        n = int(float(text))
    except ValueError:
        return None
    return str(n) if 0 < n < 4095 else None


def _split_address(value: Any) -> Tuple[Optional[str], Optional[str]]:
    text = _s(value)
    if not text:
        return None, None
    try:
        iface = ipaddress.ip_interface(text)
    except ValueError:
        return None, None
    if iface.version != 4:
        return str(iface.ip), None
    return str(iface.ip), str(iface.netmask)


def _svi_vlan(name: str) -> Optional[str]:
    m = _SVI_RE.match(name.strip())
    return _vlan_id(m.group(1)) if m else None


def config_hostname(raw_config: str) -> Optional[str]:
    m = _HOSTNAME_RE.search(raw_config or "")
    return m.group(1).lower() if m else None


@dataclass
class BatfishTopology:
    interfaces: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)   # node -> rows
    vlans: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)        # node -> rows
    vrfs: Dict[str, List[str]] = field(default_factory=dict)                    # node -> names
    routes: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)       # node -> rows
    edges: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def nodes(self) -> List[str]:
        return sorted(set(self.interfaces) | set(self.vlans) | set(self.routes))

    def summary(self) -> Dict[str, Any]:
        return {
            "nodes": self.nodes,
            "interface_count": sum(len(v) for v in self.interfaces.values()),
            "vlan_count": sum(len(v) for v in self.vlans.values()),
            "vrf_count": sum(len(v) for v in self.vrfs.values()),
            "route_count": sum(len(v) for v in self.routes.values()),
            "edge_count": len(self.edges),
            "warnings": list(self.warnings),
        }


def collect_topology(bf: Any) -> BatfishTopology:
    """Run the topology questions against an already-initialised snapshot.
    Each question is independent: one failing degrades that part only and is
    recorded in `warnings` (never silently treated as "no VLANs")."""
    topo = BatfishTopology()

    # -- interfaces -------------------------------------------------------
    try:
        for row in _records(bf, "interfaceProperties"):
            node, name = split_interface(row.get("Interface"))
            if not node:
                continue
            ip, mask = _split_address(row.get("Primary_Address"))
            mode = _s(row.get("Switchport_Mode"))
            access = _vlan_id(row.get("Access_VLAN"))
            native = _vlan_id(row.get("Native_VLAN"))
            encap = _vlan_id(row.get("Encapsulation_VLAN"))
            svi = _svi_vlan(name)
            vlan = access or svi or encap or (native if (mode or "").upper() == "TRUNK" else None)
            active = row.get("Active")
            state = None
            if active is not None and _s(active) is not None:
                state = "up" if str(active).lower() in ("true", "1") else "down"
            vrf = _s(row.get("VRF"))
            topo.interfaces.setdefault(node, []).append({
                "name": name,
                "description": _s(row.get("Description")),
                "ip_address": ip, "subnet_mask": mask,
                "vlan": vlan, "vrf": vrf,
                "admin_state": state,
                "switchport_mode": (mode.upper() if mode else None),
                "allowed_vlans": _s(row.get("Allowed_VLANs")) if (mode or "").upper() == "TRUNK" else None,
            })
            if vrf:
                topo.vrfs.setdefault(node, [])
                if vrf not in topo.vrfs[node]:
                    topo.vrfs[node].append(vrf)
    except Exception as e:  # noqa: BLE001
        logger.warning("Batfish interfaceProperties failed: %s", e)
        topo.warnings.append(f"interfaceProperties failed: {e}")

    # -- VLAN membership --------------------------------------------------
    try:
        for row in _records(bf, "switchedVlanProperties"):
            node = _s(row.get("Node"))
            vid = _vlan_id(row.get("VLAN_ID"))
            if not node or not vid:
                continue
            members = sorted({split_interface(c)[1] for c in _iter_cells(row.get("Interfaces"))})
            topo.vlans.setdefault(node.lower(), []).append({"vlan_id": vid, "interfaces": members})
    except Exception as e:  # noqa: BLE001
        logger.warning("Batfish switchedVlanProperties failed: %s", e)
        topo.warnings.append(f"switchedVlanProperties failed: {e}")

    # SVIs / routed sub-interfaces also define a VLAN presence on the node
    # even when Batfish reports no switched members (e.g. an L3-only SVI).
    for node, rows in topo.interfaces.items():
        have = {v["vlan_id"] for v in topo.vlans.get(node, [])}
        svi_members: Dict[str, List[str]] = {}
        for r in rows:
            svi = _svi_vlan(r["name"])
            if svi and svi not in have:
                svi_members.setdefault(svi, []).append(r["name"])
        for vid, names in svi_members.items():
            topo.vlans.setdefault(node, []).append({"vlan_id": vid, "interfaces": sorted(names)})

    # -- routes -----------------------------------------------------------
    try:
        for row in _records(bf, "routes"):
            node = _s(row.get("Node"))
            network = _s(row.get("Network"))
            protocol = (_s(row.get("Protocol")) or "").lower()
            if not node or not network or protocol == "local":
                continue
            bucket = topo.routes.setdefault(node.lower(), [])
            if len(bucket) >= MAX_ROUTES_PER_DEVICE:
                continue
            try:
                net = ipaddress.ip_network(network, strict=False)
                destination, mask = str(net.network_address), (str(net.netmask) if net.version == 4 else None)
            except ValueError:
                destination, mask = network, None
            bucket.append({
                "destination": destination, "mask": mask,
                "next_hop": _s(row.get("Next_Hop_IP")) if _s(row.get("Next_Hop_IP")) not in (None, "AUTO/NONE(-1l)") else _s(row.get("Next_Hop_Interface")),
                "vrf": _s(row.get("VRF")), "protocol": protocol or None,
            })
    except Exception as e:  # noqa: BLE001
        logger.warning("Batfish routes failed: %s", e)
        topo.warnings.append(f"routes failed: {e}")

    # -- layer-3 adjacency ------------------------------------------------
    try:
        seen = set()
        for row in _records(bf, "layer3Edges"):
            a_node, a_if = split_interface(row.get("Interface"))
            b_node, b_if = split_interface(row.get("Remote_Interface"))
            if not a_node or not b_node or a_node == b_node:
                continue
            key = tuple(sorted(((a_node, a_if), (b_node, b_if))))
            if key in seen:
                continue
            seen.add(key)
            topo.edges.append({
                "source_node": a_node, "source_interface": a_if,
                "target_node": b_node, "target_interface": b_if,
            })
    except Exception as e:  # noqa: BLE001
        logger.warning("Batfish layer3Edges failed: %s", e)
        topo.warnings.append(f"layer3Edges failed: {e}")

    return topo


# ---------------------------------------------------------------------------
# Snapshot orchestration (no DB access -- safe to run in a worker thread)
# ---------------------------------------------------------------------------

@dataclass
class CollectResult:
    engine: str                       # "batfish" | "unavailable"
    topology: Optional[BatfishTopology] = None
    detail: str = ""


def collect_from_configs(key: str, device_configs: Dict[str, str]) -> CollectResult:
    """Initialise one Batfish snapshot from `hostname -> raw config` and read
    the topology out of it. Never raises."""
    from app.services import batfish_service as bfs

    if not bfs.BATFISH_ENABLED:
        return CollectResult("unavailable", detail="BATFISH_ENABLED=false")
    if not device_configs:
        return CollectResult("unavailable", detail="no configurations to analyse")
    root = None
    try:
        bf = bfs._get_session()
        hc = bfs.health_check()
        if hc.get("status") == "unreachable":
            return CollectResult("unavailable", detail=f"Batfish unreachable: {hc.get('error')}")
        network = f"topology-{key}"
        bf.set_network(network)
        root = bfs.create_group_snapshot(f"topology-{key}", device_configs)
        bf.init_snapshot(root, name=f"snapshot-{key}", overwrite=True)
        return CollectResult("batfish", collect_topology(bf), "ok")
    except Exception as e:  # noqa: BLE001
        logger.warning("Batfish topology collection failed: %s", e)
        return CollectResult("unavailable", detail=str(e))
    finally:
        try:
            bfs.delete_group_snapshot(f"topology-{key}")
        except Exception:  # noqa: BLE001
            shutil.rmtree(root or "", ignore_errors=True)


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def _node_index(devices_with_raw: List[Tuple[Any, str]]) -> Dict[str, Any]:
    """lower-cased Batfish node name -> Device. Batfish names a node after
    the `hostname` in the config (lower-cased), which may differ from the
    inventory hostname, so both are indexed."""
    index: Dict[str, Any] = {}
    for device, raw in devices_with_raw:
        for name in (config_hostname(raw), (device.hostname or "").strip().lower(),
                     re.sub(r"[^a-z0-9_.-]", "_", (device.hostname or "").strip().lower())):
            if name:
                index.setdefault(name, device)
    return index


def persist_batfish_topology(
    db: Any, *, tenant_id: str, topo: BatfishTopology,
    devices_with_raw: List[Tuple[Any, str]], scan_ids: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Replace the current-state rows for every device Batfish returned data
    for. Devices Batfish returned nothing for keep their previous rows (the
    caller falls back to the regex extractor for those)."""
    from app.models.db import VLAN, VRF, NetworkInterface, NetworkLink, NetworkRoute
    from app.services.topology_extractor import extract_topology

    scan_ids = scan_ids or {}
    index = _node_index(devices_with_raw)
    raw_by_device = {d.id: raw for d, raw in devices_with_raw}
    persisted: Dict[str, Any] = {}
    unmapped = [n for n in topo.nodes if n not in index]

    for node in topo.nodes:
        device = index.get(node)
        if device is None:
            continue
        did = device.id
        sid = scan_ids.get(did)
        # VLAN names come from the config text (Batfish does not model them).
        names = {v.vlan_id: v.name for v in extract_topology(device.vendor, raw_by_device.get(did, "")).vlans}

        for model in (NetworkInterface, VLAN, VRF, NetworkRoute):
            db.query(model).filter(model.device_id == did).delete()

        for r in topo.interfaces.get(node, []):
            db.add(NetworkInterface(
                tenant_id=tenant_id, device_id=did, scan_id=sid, source=SOURCE_BATFISH,
                name=r["name"], description=r["description"], ip_address=r["ip_address"],
                subnet_mask=r["subnet_mask"], vlan=r["vlan"], vrf=r["vrf"], admin_state=r["admin_state"],
                switchport_mode=r["switchport_mode"], allowed_vlans=r["allowed_vlans"],
            ))
        for v in topo.vlans.get(node, []):
            db.add(VLAN(tenant_id=tenant_id, device_id=did, scan_id=sid, source=SOURCE_BATFISH,
                        vlan_id=v["vlan_id"], name=names.get(v["vlan_id"]), interfaces=v["interfaces"]))
        for name in topo.vrfs.get(node, []):
            db.add(VRF(tenant_id=tenant_id, device_id=did, scan_id=sid, name=name))
        for r in topo.routes.get(node, []):
            db.add(NetworkRoute(tenant_id=tenant_id, device_id=did, scan_id=sid,
                                destination=r["destination"], mask=r["mask"],
                                next_hop=r["next_hop"], vrf=r["vrf"]))
        persisted[did] = node

    # Adjacency: recompute Batfish links among the devices in this snapshot.
    covered = set(persisted)
    if covered:
        for row in db.query(NetworkLink).filter(
            NetworkLink.tenant_id == tenant_id, NetworkLink.link_type == LINK_TYPE_BATFISH,
        ).all():
            if row.source_device_id in covered and row.target_device_id in covered:
                db.delete(row)
    links = 0
    for e in topo.edges:
        a, b = index.get(e["source_node"]), index.get(e["target_node"])
        if a is None or b is None or a.id == b.id:
            continue
        db.add(NetworkLink(
            tenant_id=tenant_id, source_device_id=a.id, source_interface=e["source_interface"],
            target_device_id=b.id, target_interface=e["target_interface"], link_type=LINK_TYPE_BATFISH,
        ))
        links += 1
    db.commit()
    return {"devices_updated": len(persisted), "links": links, "unmapped_nodes": unmapped}


def persist_regex_topology(db: Any, *, tenant_id: str, device: Any, raw: str, scan_id: Optional[str]) -> None:
    from app.services.topology_service import refresh_device_topology

    refresh_device_topology(db, tenant_id=tenant_id, device_id=device.id, scan_id=scan_id,
                            vendor=device.vendor, raw_text=raw)


def apply_topology(
    db: Any, *, tenant_id: str, devices_with_raw: List[Tuple[Any, str]],
    topo: Optional[BatfishTopology], engine: str, detail: str = "",
    scan_ids: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Persist a collected Batfish topology, with a per-device regex fallback
    for anything Batfish returned nothing for. Synchronous (DB only)."""
    scan_ids = scan_ids or {}
    result: Dict[str, Any] = {"engine": engine, "detail": detail, "devices_updated": 0, "links": 0,
                              "unmapped_nodes": [], "fallback_devices": []}
    covered: set = set()
    if topo is not None and topo.nodes:
        info = persist_batfish_topology(db, tenant_id=tenant_id, topo=topo,
                                        devices_with_raw=devices_with_raw, scan_ids=scan_ids)
        result.update(info)
        result["summary"] = topo.summary()
        index = _node_index(devices_with_raw)
        covered = {index[n].id for n in topo.nodes if n in index}

    for device, raw in devices_with_raw:
        if device.id in covered:
            continue
        try:
            persist_regex_topology(db, tenant_id=tenant_id, device=device, raw=raw, scan_id=scan_ids.get(device.id))
            result["fallback_devices"].append(device.hostname or device.id)
        except Exception:  # noqa: BLE001
            logger.warning("Regex topology extraction failed for device %s", device.id, exc_info=True)
            try:
                db.rollback()
            except Exception:  # noqa: BLE001
                pass
    if covered and result["fallback_devices"]:
        result["engine"] = "batfish+regex"
    elif not covered:
        result["engine"] = "regex"
    return result


async def refresh_topology(
    db: Any, *, tenant_id: str, devices_with_raw: List[Tuple[Any, str]],
    scan_ids: Optional[Dict[str, str]] = None, key: Optional[str] = None,
) -> Dict[str, Any]:
    """Collect a fresh Batfish snapshot for `devices_with_raw` (off the event
    loop) and persist it, falling back to the regex extractor."""
    import anyio

    if not devices_with_raw:
        return {"engine": "none", "devices_updated": 0, "links": 0, "detail": "no devices with a config"}
    configs = {(d.hostname or d.id): raw for d, raw in devices_with_raw}
    res = await anyio.to_thread.run_sync(collect_from_configs, key or f"{tenant_id}-{os.getpid()}", configs)
    return apply_topology(db, tenant_id=tenant_id, devices_with_raw=devices_with_raw,
                          topo=res.topology, engine=res.engine, detail=res.detail, scan_ids=scan_ids)