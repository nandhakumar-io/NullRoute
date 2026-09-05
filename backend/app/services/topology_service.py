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
