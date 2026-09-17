"""Inventory/topology persistence (Phase 9).

Wraps services/topology_extractor.py: turns its best-effort extraction of
one raw_text into NetworkInterface/VLAN/VRF/NetworkRoute rows for a device,
replacing that device's previous snapshot (these tables hold CURRENT
observed state, not history -- see models/db.py).

Also provides `infer_links`, used by routers/topology.py to compute
NetworkLink-shaped adjacency at query time by matching interface IPs onto
the same /24-ish subnet -- never persisted as if it were an observed fact
(RULE 10), always recomputed from the current NetworkInterface rows.
"""
from __future__ import annotations

import ipaddress
from typing import Dict, List, Optional

from sqlalchemy.orm import Session

from app.services.topology_extractor import extract_topology


def refresh_device_topology(
    db: Session, *, tenant_id: str, device_id: str, scan_id: str, vendor: Optional[str], raw_text: str
) -> None:
    from app.models.db import VLAN, VRF, NetworkInterface, NetworkRoute

    extraction = extract_topology(vendor, raw_text)

    # Replace this device's prior snapshot -- current-state tables, not a log.
    db.query(NetworkInterface).filter(NetworkInterface.device_id == device_id).delete()
    db.query(VLAN).filter(VLAN.device_id == device_id).delete()
    db.query(VRF).filter(VRF.device_id == device_id).delete()
    db.query(NetworkRoute).filter(NetworkRoute.device_id == device_id).delete()

    for iface in extraction.interfaces:
        db.add(NetworkInterface(
            tenant_id=tenant_id, device_id=device_id, scan_id=scan_id,
            name=iface.name, description=iface.description, ip_address=iface.ip_address,
            subnet_mask=iface.subnet_mask, vlan=iface.vlan, vrf=iface.vrf, admin_state=iface.admin_state,
        ))
    for vlan in extraction.vlans:
        db.add(VLAN(tenant_id=tenant_id, device_id=device_id, scan_id=scan_id,
                     vlan_id=vlan.vlan_id, name=vlan.name))
    for vrf in extraction.vrfs:
        db.add(VRF(tenant_id=tenant_id, device_id=device_id, scan_id=scan_id,
                    name=vrf.name, route_distinguisher=vrf.route_distinguisher))
    for route in extraction.routes:
        db.add(NetworkRoute(tenant_id=tenant_id, device_id=device_id, scan_id=scan_id,
                             destination=route.destination, mask=route.mask,
                             next_hop=route.next_hop, vrf=route.vrf))
    db.commit()


def persist_observed_links(db: Session, *, tenant_id: str, device_id: str, neighbors: List[Dict]) -> int:
    """Store this device's directly-observed neighbors (from
    collectors.get_neighbors(), e.g. an LLDP-MIB walk) as NetworkLink rows
    with link_type="lldp_observed" -- unlike infer_links() below, this IS an
    observed fact (the remote device told us who it is), so it's fine to
    persist rather than recompute at query time.

    A remote neighbor is matched to a known Device by its LLDP system name
    against Device.hostname (case-insensitive); neighbors that don't match
    any device in this tenant (an unmanaged switch, an AP, a peer outside
    NetSecAuditor's inventory) are dropped rather than stored as a link to
    nowhere (RULE 10: never fabricate the far end).

    Replaces this device's previously-observed outbound links every call --
    current state, not a log, same convention as refresh_device_topology()."""
    from app.models.db import Device, NetworkLink

    tenant_devices = db.query(Device).filter(Device.tenant_id == tenant_id).all()
    by_hostname = {(d.hostname or "").strip().lower(): d for d in tenant_devices if d.hostname}

    db.query(NetworkLink).filter(
        NetworkLink.tenant_id == tenant_id,
        NetworkLink.source_device_id == device_id,
        NetworkLink.link_type == "lldp_observed",
    ).delete()

    stored = 0
    for n in neighbors:
        remote_name = (n.get("remote_system_name") or "").strip().lower()
        remote_device = by_hostname.get(remote_name)
        if not remote_device or remote_device.id == device_id:
            continue
        db.add(NetworkLink(
            tenant_id=tenant_id,
            source_device_id=device_id,
            source_interface=n.get("local_port"),
            target_device_id=remote_device.id,
            target_interface=n.get("remote_port_id") or n.get("remote_port_description"),
            link_type="lldp_observed",
        ))
        stored += 1
    db.commit()
    return stored


def get_topology_links(db: Session, tenant_id: str, interfaces: List["NetworkInterface"]) -> List[Dict]:
    """Combined link list for the /api/topology endpoint: real,
    SNMP/LLDP-observed adjacency first (link_type="lldp_observed", from
    persist_observed_links()), then subnet-inferred links for any device
    pair not already covered by an observed link. Observed links are
    ground truth and always take priority over a same-subnet guess between
    the same two devices."""
    from app.models.db import NetworkLink

    observed_rows = db.query(NetworkLink).filter(
        NetworkLink.tenant_id == tenant_id, NetworkLink.link_type == "lldp_observed",
    ).all()
    observed = [
        {
            "source_device_id": r.source_device_id, "source_interface": r.source_interface,
            "target_device_id": r.target_device_id, "target_interface": r.target_interface,
            "link_type": "lldp_observed",
        }
        for r in observed_rows
    ]
    covered_pairs = {tuple(sorted((l["source_device_id"], l["target_device_id"]))) for l in observed}

    inferred = [
        l for l in infer_links(interfaces)
        if tuple(sorted((l["source_device_id"], l["target_device_id"]))) not in covered_pairs
    ]
    return observed + inferred


def _network_of(ip: Optional[str], mask: Optional[str]) -> Optional[ipaddress.IPv4Network]:
    if not ip:
        return None
    try:
        if mask:
            return ipaddress.ip_network(f"{ip}/{mask}", strict=False)
        # No mask captured (e.g. Juniper CIDR-only lines already merged) --
        # fall back to a /24 guess ONLY for link inference (never stored as
        # fact, see module docstring); skip entirely if that's ambiguous.
        return ipaddress.ip_network(f"{ip}/24", strict=False)
    except ValueError:
        return None


def infer_links(interfaces: List["NetworkInterface"]) -> List[Dict]:
    """Group interfaces by the subnet their IP falls in; any subnet with
    interfaces from 2+ distinct devices is reported as an inferred link.
    Interfaces with no IP address contribute nothing (can't be inferred)."""
    by_subnet: Dict[str, List["NetworkInterface"]] = {}
    for iface in interfaces:
        net = _network_of(iface.ip_address, iface.subnet_mask)
        if net is None:
            continue
        by_subnet.setdefault(str(net), []).append(iface)

    links = []
    for subnet, ifaces in by_subnet.items():
        device_ids = {i.device_id for i in ifaces}
        if len(device_ids) < 2:
            continue
        # Pairwise links between distinct devices sharing this subnet.
        seen_pairs = set()
        for i, a in enumerate(ifaces):
            for b in ifaces[i + 1:]:
                if a.device_id == b.device_id:
                    continue
                pair = tuple(sorted((a.device_id, b.device_id)))
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)
                links.append({
                    "subnet": subnet,
                    "source_device_id": a.device_id,
                    "source_interface": a.name,
                    "target_device_id": b.device_id,
                    "target_interface": b.name,
                    "link_type": "inferred_subnet",
                })
    return links
