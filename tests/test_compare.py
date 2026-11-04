from dataclasses import replace

from landiscovery.compare import compare_scans
from landiscovery.models import Coverage, Host, Port, ScanResult


def scan(hosts, *, targets=None, ports="22,80", complete=True, privileged=True,
         os_detect=True, service_detect=True):
    targets = targets or ["192.168.1.0/24"]
    coverage = Coverage(targets, "full", ports, privileged, os_detect,
                        service_detect, False, False, False, False, False)
    return ScanResult(targets=targets, hosts=hosts, coverage=coverage,
                      complete=complete, status="done")


def test_compare_new_and_gone():
    diff = compare_scans(scan([Host("192.168.1.2")]), scan([Host("192.168.1.3")]))
    assert diff.comparable
    assert [h.ip for h in diff.new_hosts] == ["192.168.1.3"]
    assert [h.ip for h in diff.gone_hosts] == ["192.168.1.2"]


def test_compare_host_without_mac_uses_ip():
    diff = compare_scans(scan([Host("192.168.1.2")]), scan([Host("192.168.1.2")]))
    assert diff.new_hosts == diff.gone_hosts == diff.changed == []


def test_compare_ignores_latency():
    diff = compare_scans(scan([Host("192.168.1.2", latency_ms=1)]),
                         scan([Host("192.168.1.2", latency_ms=100)]))
    assert diff.changed == []


def test_compare_detects_new_open_port():
    before = Host("192.168.1.2", ports=[Port(22)])
    after = Host("192.168.1.2", ports=[Port(22), Port(80)])
    assert compare_scans(scan([before]), scan([after])).changed[0].fields == ["ports"]


def test_compare_incomplete_scan_not_comparable():
    diff = compare_scans(scan([Host("192.168.1.2")]), scan([], complete=False))
    assert not diff.comparable and diff.reasons
    assert diff.new_hosts == diff.gone_hosts == []


def test_compare_different_targets_not_comparable():
    diff = compare_scans(scan([]), scan([], targets=["192.168.2.0/24"]))
    assert not diff.comparable and "target networks differ" in diff.reasons


def test_compare_ports_only_when_same_port_spec():
    before = scan([Host("192.168.1.2", ports=[Port(22)])])
    after = scan([Host("192.168.1.2", ports=[Port(22), Port(80)])], ports="22")
    assert compare_scans(before, after).changed == []


def test_compare_os_only_when_collected_in_both():
    before = scan([Host("192.168.1.2", os="Linux")])
    after = scan([Host("192.168.1.2", os="Windows")], os_detect=False)
    assert compare_scans(before, after).changed == []


def test_compare_mac_identity_survives_ip_change():
    before = Host("192.168.1.2", mac="AA:BB:CC:DD:EE:FF")
    after = Host("192.168.1.9", mac=before.mac)
    diff = compare_scans(scan([before]), scan([after]))
    assert diff.new_hosts == diff.gone_hosts == []
    assert diff.changed[0].fields == ["ip"]


def test_compare_privilege_modes_not_comparable():
    diff = compare_scans(scan([]), scan([], privileged=False))
    assert not diff.comparable
