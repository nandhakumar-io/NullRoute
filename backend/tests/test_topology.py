from app.services.topology_extractor import extract_topology
from app.services.topology_service import infer_links


CISCO_TWO_LINKED_IFACES = """
!
hostname CORE-SW-01
!
interface GigabitEthernet1/0/1
 description Uplink-to-Distribution
 ip address 10.10.10.1 255.255.255.252
!
interface Vlan100
 ip address 10.10.20.1 255.255.255.0
!
vlan 100
 name USERS
!
ip vrf CUSTOMER-A
 rd 65000:1
!
ip route 0.0.0.0 0.0.0.0 10.10.10.2
!
"""


def test_cisco_extraction_finds_interfaces_vlans_vrfs_routes():
    result = extract_topology("Cisco", CISCO_TWO_LINKED_IFACES)
    names = {i.name for i in result.interfaces}
    assert names == {"GigabitEthernet1/0/1", "Vlan100"}

    gi = next(i for i in result.interfaces if i.name == "GigabitEthernet1/0/1")
    assert gi.ip_address == "10.10.10.1"
    assert gi.subnet_mask == "255.255.255.252"
    assert gi.description == "Uplink-to-Distribution"
    # structure_parser.py's contract (RULE 10) is stricter than the old
    # extractor's: admin_state is only ever set from an explicit
    # "shutdown"/"no shutdown" line, never assumed "up" by default when the
    # config simply doesn't say. This config has no shutdown line at all.
    assert gi.admin_state is None

    assert len(result.vlans) == 1
    assert result.vlans[0].vlan_id == "100"
    assert result.vlans[0].name == "USERS"

    assert len(result.vrfs) == 1
    assert result.vrfs[0].name == "CUSTOMER-A"
    assert result.vrfs[0].route_distinguisher == "65000:1"

    assert len(result.routes) == 1
    assert result.routes[0].destination == "0.0.0.0"
    assert result.routes[0].next_hop == "10.10.10.2"


def test_cisco_extraction_marks_shutdown_interface_down():
    text = "interface GigabitEthernet0/1\n shutdown\n!\n"
    result = extract_topology("Cisco", text)
    assert result.interfaces[0].admin_state == "down"


def test_unsupported_vendor_returns_empty_not_a_guess():
    result = extract_topology("Palo Alto Networks", "set deviceconfig system hostname fw01")
    assert result.interfaces == []
    assert result.vlans == []
    assert result.vrfs == []
    assert result.routes == []


def test_extraction_never_raises_on_malformed_text():
    # Best-effort per RULE 10 -- garbage input degrades to an empty result,
    # never an exception that would fail the whole pipeline.
    result = extract_topology("Cisco", "\x00\x01 not really a config \n interface \n")
    assert isinstance(result.interfaces, list)


class _FakeIface:
    def __init__(self, device_id, name, ip_address=None, subnet_mask=None):
        self.device_id = device_id
        self.name = name
        self.ip_address = ip_address
        self.subnet_mask = subnet_mask


def test_infer_links_connects_two_devices_sharing_a_subnet():
    interfaces = [
        _FakeIface("dev-a", "Gi1/0/1", "10.10.10.1", "255.255.255.252"),
        _FakeIface("dev-b", "Gi1/0/1", "10.10.10.2", "255.255.255.252"),
    ]
    links = infer_links(interfaces)
    assert len(links) == 1
    assert {links[0]["source_device_id"], links[0]["target_device_id"]} == {"dev-a", "dev-b"}


def test_infer_links_ignores_interfaces_on_the_same_device():
    interfaces = [
        _FakeIface("dev-a", "Gi1/0/1", "10.10.10.1", "255.255.255.0"),
        _FakeIface("dev-a", "Gi1/0/2", "10.10.10.2", "255.255.255.0"),
    ]
    assert infer_links(interfaces) == []


def test_infer_links_ignores_interfaces_without_ip():
    interfaces = [
        _FakeIface("dev-a", "Gi1/0/1", None, None),
        _FakeIface("dev-b", "Gi1/0/1", None, None),
    ]
    assert infer_links(interfaces) == []


def test_infer_links_no_link_when_subnets_differ():
    interfaces = [
        _FakeIface("dev-a", "Gi1/0/1", "10.10.10.1", "255.255.255.252"),
        _FakeIface("dev-b", "Gi1/0/1", "10.20.20.1", "255.255.255.252"),
    ]
    assert infer_links(interfaces) == []