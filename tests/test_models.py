import pytest

from landiscovery.models import (Coverage, DiscoveredService, Edge, Finding, Host, Node,
                                 ScanResult, Topology)


def test_host_key_prefers_mac():
    h = Host(ip="192.168.1.10", mac="aa:bb:cc:dd:ee:ff")
    assert h.key == "aa:bb:cc:dd:ee:ff"


def test_host_key_falls_back_to_ip():
    h = Host(ip="192.168.1.10", mac=None)
    assert h.key == "192.168.1.10"


def test_finding_rejects_unknown_severity():
    with pytest.raises(ValueError):
        Finding(host="192.168.1.10", severity="fatal", title="t", detail="d")


def test_scanresult_defaults_incomplete():
    r = ScanResult()
    assert r.complete is False
    assert r.discovered == [] and r.warnings == []
    assert r.topology is None and r.coverage is None
    r.discovered.append(DiscoveredService("1.2.3.4", "mdns", "n", "d"))
    assert ScanResult().discovered == []


def test_topology_inferred_default_true():
    t = Topology(nodes=[Node("a", "A", "gateway", "10.0.0.0/24")], edges=[Edge("a", "b")])
    assert t.inferred is True
    assert Topology([], []).nodes == []


def test_coverage_fields():
    c = Coverage(targets=["10.0.0.0/24"], profile="quick", ports="top100", privileged=False,
                 os_detect=False, service_detect=False, traceroute=False, mdns=False,
                 ssdp=False, snmp=False, security_checks=False)
    assert c.profile == "quick"
