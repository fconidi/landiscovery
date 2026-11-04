import threading

import pytest

from landiscovery.engine import (EngineError, ScanEngine, ScanOptions,
                                 parse_arp_scan)
from landiscovery.helper import HelperError
from landiscovery.profiles import BUILTIN, Profile
from landiscovery.runner import ScanCancelled

ARP = (
    "Interface: eth0, type: EN10MB, MAC: aa:bb:cc:00:00:01, IPv4: 192.168.1.5\n"
    "Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)\n"
    "192.168.1.1\tb8:27:eb:12:34:56\tRaspberry Pi Foundation\n"
    "192.168.1.20\t00:11:32:aa:bb:cc\t(Unknown)\n"
    "192.168.1.20\t00:11:32:aa:bb:cc\t(Unknown) (DUP: 2)\n"
    "\n"
    "3 packets received by filter, 0 packets dropped by kernel\n"
    "Ending arp-scan 1.10.0: 256 hosts scanned in 1.9 seconds (134.74 hosts/sec). 2 responded\n"
)


def nmap_xml(*hosts):
    """hosts: (ip, [ports], os) con porte come numeri."""
    out = ['<?xml version="1.0"?><nmaprun scanner="nmap">']
    for ip, ports, os_name in hosts:
        out.append(f'<host><status state="up"/><address addr="{ip}" addrtype="ipv4"/>')
        if ports:
            out.append("<ports>")
            for p in ports:
                out.append(f'<port protocol="tcp" portid="{p}"><state state="open"/>'
                           f'<service name="svc{p}"/></port>')
            out.append("</ports>")
        if os_name:
            out.append(f'<os><osmatch name="{os_name}" accuracy="100"/></os>')
        out.append("</host>")
    out.append("</nmaprun>")
    return "".join(out)


class FakeRunner:
    def __init__(self, arp=ARP, up=("192.168.1.1", "192.168.1.20"), fail=None,
                 on_call=None):
        self.arp, self.up, self.fail = arp, up, fail or {}
        self.calls = []
        self.cancelled = False
        self.resets = 0
        self.on_call = on_call

    def reset(self):
        self.resets += 1
        self.cancelled = False

    def cancel(self):
        self.cancelled = True

    def run(self, op, params, on_line=None):
        if self.cancelled:
            raise ScanCancelled()
        self.calls.append((op, params))
        if self.on_call:
            self.on_call(op, params)
        key = "discovery" if op == "port_scan" and params["ports"] == "" else op
        if key in self.fail:
            raise self.fail[key]
        if op == "arp_discover":
            return self.arp
        if key == "discovery":
            return nmap_xml(*[(ip, [], "") for ip in self.up])
        if op == "port_scan":
            return nmap_xml(*[(ip, [22, 80], "") for ip in params["targets"]])
        if op == "os_detect":
            return nmap_xml(*[(ip, [], "Linux 5.x") for ip in params["targets"]])
        raise AssertionError(op)

    def ops(self):
        return [c[0] for c in self.calls]


class FakeOui:
    def lookup(self, mac):
        return "Acme"


FULL = BUILTIN["full"]
QUICK = BUILTIN["quick"]


def engine(runner=None, privileged=True):
    return ScanEngine(runner=runner or FakeRunner(), oui=FakeOui(), privileged=privileged)


def test_parse_arp_scan():
    parsed = parse_arp_scan(ARP)
    assert parsed == {"B8:27:EB:12:34:56": ("192.168.1.1", "Raspberry Pi Foundation"),
                      "00:11:32:AA:BB:CC": ("192.168.1.20", "")}
    assert parse_arp_scan("") == {}


def test_scan_collects_hosts():
    res = engine().scan(["192.168.1.0/24"], FULL)
    assert res.status == "done" and res.complete and not res.warnings
    assert [h.ip for h in res.hosts] == ["192.168.1.1", "192.168.1.20"]
    h1, h2 = res.hosts
    assert h1.mac == "B8:27:EB:12:34:56" and h1.vendor == "Raspberry Pi Foundation"
    assert h2.vendor == "Acme"  # risolto con OUI
    assert [p.number for p in h1.ports] == [22, 80]
    assert h1.os == "Linux 5.x"
    assert res.id is None and res.profile == "full" and res.targets == ["192.168.1.0/24"]
    assert res.finished >= res.started and not res.reduced


def test_scan_zero_hosts_ok():
    r = FakeRunner(arp="", up=())
    res = engine(r).scan(["192.168.1.0/24"], FULL)
    assert res.hosts == [] and res.status == "done" and res.complete
    assert "os_detect" not in r.ops()


def test_targets_passed_as_strings():
    import ipaddress
    r = FakeRunner()
    engine(r).scan([ipaddress.ip_network("192.168.1.0/24"), "10.0.0.1"], QUICK)
    assert r.calls[0] == ("arp_discover", {"targets": ["192.168.1.0/24", "10.0.0.1"]})
    assert r.calls[1][1]["targets"] == ["192.168.1.0/24", "10.0.0.1"]
    scan_call = [c for c in r.calls if c[0] == "port_scan" and c[1]["ports"] != ""][0]
    assert scan_call[1] == {"targets": ["192.168.1.1", "192.168.1.20"],
                            "ports": "top100", "service": False}


def test_ping_profile_skips_port_scan():
    r = FakeRunner()
    res = engine(r).scan(["192.168.1.0/24"], BUILTIN["ping"])
    assert r.ops() == ["arp_discover", "port_scan"] and len(res.hosts) == 2
    assert res.complete


def test_reduced_mode_flag_and_empty_mac():
    r = FakeRunner()
    res = engine(r, privileged=False).scan(["192.168.1.0/24"], FULL)
    assert res.reduced and res.complete
    assert "arp_discover" not in r.ops() and "os_detect" not in r.ops()
    assert all(h.mac is None and h.vendor == "" and h.os == "" for h in res.hosts)
    assert res.hosts and res.hosts[0].ports
    assert any("OS detection" in w for w in res.warnings)
    assert res.coverage.privileged is False and res.coverage.os_detect is False


def test_cancel_marks_cancelled_and_incomplete():
    eng = engine()

    def on_call(op, params):
        if op == "arp_discover":
            eng.cancel()

    eng.runner.on_call = on_call
    res = eng.scan(["192.168.1.0/24"], FULL)
    assert res.status == "cancelled" and not res.complete
    assert eng.runner.cancelled
    assert [h.ip for h in res.hosts] == ["192.168.1.1", "192.168.1.20"]


def test_cancel_from_other_thread_during_run():
    eng = engine()
    started, release = threading.Event(), threading.Event()

    def on_call(op, params):
        if op == "port_scan" and params["ports"] != "":
            started.set()
            release.wait(2)

    eng.runner.on_call = on_call
    out = []
    t = threading.Thread(target=lambda: out.append(eng.scan(["192.168.1.0/24"], QUICK)))
    t.start()
    assert started.wait(2)
    eng.cancel()
    release.set()
    t.join(5)
    assert out[0].status == "cancelled" and not out[0].complete


def test_second_scan_after_cancel_works():
    r = FakeRunner()
    eng = engine(r)
    eng.cancel()
    res = eng.scan(["192.168.1.0/24"], QUICK)
    assert r.resets == 1 and res.status == "done" and res.complete


def test_missing_nmap_raises_clear_error():
    err = HelperError("cannot run nmap: No such file or directory")
    err.returncode = 127
    r = FakeRunner(fail={"discovery": err})
    with pytest.raises(EngineError, match="nmap"):
        engine(r, privileged=False).scan(["192.168.1.0/24"], QUICK)


def test_progress_callback_called():
    calls = []
    engine().scan(["192.168.1.0/24"], FULL, on_progress=lambda s, f: calls.append((s, f)))
    assert [c[0] for c in calls] == ["discovery", "discovery", "ports", "ports", "os", "os"]
    fr = [c[1] for c in calls]
    assert fr[0] == 0.0 and fr[-1] == 1.0 and fr == sorted(fr)


def test_progress_callback_exception_ignored():
    def boom(step, fraction):
        raise RuntimeError("x")

    res = engine().scan(["192.168.1.0/24"], QUICK, on_progress=boom)
    assert res.status == "done" and len(res.hosts) == 2


def test_failed_step_keeps_data_and_marks_incomplete():
    r = FakeRunner(fail={"os_detect": HelperError("boom")})
    res = engine(r).scan(["192.168.1.0/24"], FULL)
    assert res.status == "done" and not res.complete
    assert len(res.hosts) == 2 and res.hosts[0].ports
    assert any("os detection" in w and "boom" in w for w in res.warnings)


def test_bad_xml_is_a_warning():
    class Bad(FakeRunner):
        def run(self, op, params, on_line=None):
            if op == "port_scan" and params["ports"] != "":
                return "<nmaprun><host>"
            return super().run(op, params, on_line)

    res = engine(Bad()).scan(["192.168.1.0/24"], QUICK)
    assert res.status == "done" and not res.complete and len(res.hosts) == 2


def test_everything_failed_is_failed():
    e = HelperError("boom")
    r = FakeRunner(fail={"arp_discover": e, "discovery": e})
    res = engine(r).scan(["192.168.1.0/24"], QUICK)
    assert res.status == "failed" and not res.complete and res.hosts == []


def test_coverage_reflects_profile_and_privileges():
    res = engine().scan(["192.168.1.0/24"], FULL, ScanOptions())
    c = res.coverage
    assert (c.profile, c.ports, c.targets) == ("full", "1-65535", ["192.168.1.0/24"])
    assert c.privileged and c.os_detect and c.service_detect
    # passi non ancora collegati: mai dichiarati
    assert not (c.mdns or c.ssdp or c.snmp or c.traceroute or c.security_checks)
    res = engine(privileged=False).scan(["192.168.1.0/24"], QUICK)
    assert not res.coverage.privileged and not res.coverage.os_detect
    assert res.coverage.ports == "top100" and not res.coverage.service_detect


def test_coverage_ping_profile_has_no_ports():
    c = engine().scan(["192.168.1.0/24"], BUILTIN["ping"]).coverage
    assert c.ports == "" and not c.service_detect and not c.os_detect


def test_coverage_after_cancel_during_os_step():
    eng = engine()

    def on_call(op, params):
        if op == "os_detect":
            eng.cancel()

    eng.runner.on_call = on_call
    res = eng.scan(["192.168.1.0/24"], FULL)
    c = res.coverage
    assert res.status == "cancelled"
    assert c.ports == "1-65535" and c.service_detect and not c.os_detect


def test_coverage_after_failed_os_step():
    r = FakeRunner(fail={"os_detect": HelperError("boom")})
    c = engine(r).scan(["192.168.1.0/24"], FULL).coverage
    assert c.ports == "1-65535" and not c.os_detect


def test_coverage_after_failed_port_step():
    r = FakeRunner(fail={"port_scan": HelperError("boom")})
    r.fail = {}

    class F(FakeRunner):
        def run(self, op, params, on_line=None):
            if op == "port_scan" and params["ports"] != "":
                raise HelperError("boom")
            return super().run(op, params, on_line)

    c = engine(F()).scan(["192.168.1.0/24"], FULL).coverage
    assert c.ports == "" and not c.service_detect


def test_coverage_reduced_mode_with_os_profile():
    c = engine(privileged=False).scan(["192.168.1.0/24"], FULL).coverage
    assert not c.os_detect and not c.privileged and c.ports == "1-65535"


def test_two_macs_one_ip_keeps_first_and_warns():
    arp = ("192.168.1.1\taa:aa:aa:00:00:01\tOne\n"
           "192.168.1.1\tbb:bb:bb:00:00:02\tTwo\n")
    res = engine(FakeRunner(arp=arp, up=("192.168.1.1",))).scan(
        ["192.168.1.0/24"], BUILTIN["ping"])
    assert res.hosts[0].mac == "AA:AA:AA:00:00:01" and res.hosts[0].vendor == "One"
    assert any("192.168.1.1" in w and "BB:BB:BB:00:00:02" in w for w in res.warnings)


def test_overlapping_scan_raises():
    eng = engine()
    started, release = threading.Event(), threading.Event()

    def on_call(op, params):
        started.set()
        release.wait(2)

    eng.runner.on_call = on_call
    t = threading.Thread(target=lambda: eng.scan(["192.168.1.0/24"], QUICK))
    t.start()
    assert started.wait(2)
    with pytest.raises(EngineError, match="scan already running"):
        eng.scan(["192.168.1.0/24"], QUICK)
    release.set()
    t.join(5)
    assert eng.scan(["192.168.1.0/24"], BUILTIN["ping"]).status == "done"


def test_progress_exception_is_logged(caplog):
    import logging

    def boom(step, fraction):
        raise RuntimeError("cb-fail")

    with caplog.at_level(logging.DEBUG, logger="landiscovery.engine"):
        engine().scan(["192.168.1.0/24"], BUILTIN["ping"], on_progress=boom)
    assert "cb-fail" in caplog.text


def test_complete_true_only_on_full_success():
    assert engine().scan(["192.168.1.0/24"], QUICK).complete
    r = FakeRunner(fail={"arp_discover": HelperError("no arp")})
    res = engine(r).scan(["192.168.1.0/24"], QUICK)
    assert res.status == "done" and not res.complete


def test_empty_targets_use_local_network():
    r = FakeRunner()
    res = engine(r).scan([], BUILTIN["ping"])
    assert r.calls == [("arp_discover", {"targets": []})]
    assert len(res.hosts) == 2


def test_ipv6_target_skips_arp():
    r = FakeRunner(up=("fe80::1",))
    res = engine(r).scan(["fe80::/112"], BUILTIN["ping"])
    assert "arp_discover" not in r.ops() and [h.ip for h in res.hosts] == ["fe80::1"]
