import logging
import threading
from pathlib import Path

import pytest

from landiscovery.discovery import DiscoveredService, ToolMissing
from landiscovery.engine import (EngineError, ScanEngine, ScanOptions,
                                 parse_arp_scan, read_default_gateway)
from landiscovery.helper import NSE_ALLOWED, HelperError
from landiscovery.models import Host
from landiscovery.profiles import BUILTIN, Profile
from landiscovery.runner import ScanCancelled

FIXTURES = Path(__file__).parent / "fixtures"
NSE_XML = (FIXTURES / "nmap_nse.xml").read_text()
TRACE_XML = (FIXTURES / "nmap_traceroute.xml").read_text()

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
                 on_call=None, nse=NSE_XML, trace=TRACE_XML):
        self.arp, self.up, self.fail = arp, up, fail or {}
        self.nse, self.trace = nse, trace
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
        if op == "nse_safe":
            return self.nse
        if op == "traceroute":
            return self.trace
        raise AssertionError(op)

    def ops(self):
        return [c[0] for c in self.calls]


class FakeOui:
    def lookup(self, mac):
        return "Acme"


def test_missing_installed_helper_uses_reduced_mode(monkeypatch):
    monkeypatch.setattr("landiscovery.engine.os.geteuid", lambda: 1000)
    monkeypatch.setattr("landiscovery.engine.shutil.which", lambda _: "/usr/bin/pkexec")
    monkeypatch.setattr("landiscovery.engine.os.access", lambda *_: False)
    assert ScanEngine(runner=FakeRunner()).privileged is False


FULL = BUILTIN["full"]
QUICK = BUILTIN["quick"]


class FakeTools:
    def __init__(self, mdns=(), ssdp=(), snmp=None, gateway="192.168.1.1",
                 raises=None, on_call=None):
        self._mdns, self._ssdp, self._snmp = list(mdns), list(ssdp), snmp or {}
        self._gateway = gateway
        self.raises = raises or {}
        self.on_call = on_call
        self.calls = []

    def _hit(self, name, *args):
        self.calls.append((name, *args))
        if self.on_call:
            self.on_call(name)
        if name in self.raises:
            raise self.raises[name]

    def mdns(self):
        self._hit("mdns")
        return list(self._mdns)

    def ssdp(self):
        self._hit("ssdp")
        return list(self._ssdp)

    def snmp(self, ip, community):
        self._hit("snmp", ip, community)
        return self._snmp.get(ip)

    def gateway(self):
        self.calls.append(("gateway",))
        return self._gateway

    def names(self):
        return [c[0] for c in self.calls]


def engine(runner=None, privileged=True, tools=None):
    return ScanEngine(runner=runner or FakeRunner(), oui=FakeOui(),
                      privileged=privileged, tools=tools or FakeTools())


def svc(ip, kind="mdns", name="dev", detail=""):
    return DiscoveredService(ip=ip, kind=kind, name=name, detail=detail)


ALL = Profile("all", "top100", traceroute=True, mdns=True, ssdp=True, snmp=True,
              security_checks=True)


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
                            "ports": "top100", "service": False, "resolve": True}


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
    assert [c[0] for c in calls] == ["discovery", "discovery", "ports", "ports", "os", "os",
                                     "mdns", "mdns", "ssdp", "ssdp"]
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
    # FULL chiede mdns e ssdp: dichiarati; il resto non è richiesto
    assert c.mdns and c.ssdp
    assert not (c.snmp or c.traceroute or c.security_checks)
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


# --- Task 9b: scoperta, NSE e topologia ------------------------------------------

def node_ids(topo):
    return {n.id for n in topo.nodes}


def test_discovery_results_in_scanresult():
    tools = FakeTools(mdns=[svc("192.168.1.20", "mdns", "printer")],
                      ssdp=[svc("192.168.1.99", "ssdp", "tv")])
    res = engine(tools=tools).scan(["192.168.1.0/24"], FULL)
    assert [(d.kind, d.name) for d in res.discovered] == [("mdns", "printer"), ("ssdp", "tv")]
    assert res.coverage.mdns and res.coverage.ssdp and res.complete


def test_services_attached_to_matching_hosts_only():
    tools = FakeTools(mdns=[svc("192.168.1.20", "mdns", "printer"),
                            svc("192.168.1.20", "mdns", "printer")],
                      ssdp=[svc("192.168.1.99", "ssdp", "tv")])
    res = engine(tools=tools).scan(["192.168.1.0/24"], FULL)
    by_ip = {h.ip: h for h in res.hosts}
    assert by_ip["192.168.1.20"].services == ["mdns:printer"]
    assert by_ip["192.168.1.1"].services == []
    assert len(res.discovered) == 3  # l'host sconosciuto resta solo in discovered


def test_services_capped_per_host():
    many = [svc("192.168.1.20", "mdns", f"s{i}") for i in range(50)]
    res = engine(tools=FakeTools(mdns=many)).scan(["192.168.1.0/24"], FULL)
    h = [h for h in res.hosts if h.ip == "192.168.1.20"][0]
    assert len(h.services) == 20 and h.services[0] == "mdns:s0"
    assert len(res.discovered) == 50


def test_missing_avahi_warns_and_marks_incomplete():
    tools = FakeTools(raises={"mdns": ToolMissing("avahi-browse")})
    res = engine(tools=tools).scan(["192.168.1.0/24"], FULL)
    assert any("avahi-browse not installed" in w for w in res.warnings)
    assert res.status == "done" and not res.complete
    assert not res.coverage.mdns and res.coverage.ssdp
    assert [h.ip for h in res.hosts] == ["192.168.1.1", "192.168.1.20"]


def test_step_failure_does_not_stop_later_steps():
    tools = FakeTools(raises={"mdns": OSError("boom")}, ssdp=[svc("192.168.1.20", "ssdp", "tv")],
                      snmp={"192.168.1.20": svc("192.168.1.20", "snmp", "sw")})
    prof = Profile("p", "top100", mdns=True, ssdp=True, snmp=True)
    res = engine(tools=tools).scan(["192.168.1.0/24"], prof, ScanOptions(snmp_community="public"))
    assert any(w.startswith("mdns") for w in res.warnings) and not res.complete
    assert not res.coverage.mdns and res.coverage.ssdp and res.coverage.snmp
    assert {d.kind for d in res.discovered} == {"ssdp", "snmp"}


def test_failed_runner_step_does_not_stop_later_steps():
    r = FakeRunner(fail={"traceroute": HelperError("nope")})
    tools = FakeTools(mdns=[svc("192.168.1.20")])
    res = engine(r, tools=tools).scan(["192.168.1.0/24"], ALL, ScanOptions(snmp_community="x"))
    assert any("traceroute" in w and "nope" in w for w in res.warnings)
    assert not res.coverage.traceroute and res.coverage.security_checks
    assert res.coverage.mdns and res.coverage.ssdp and res.coverage.snmp
    assert res.topology is not None and not res.complete


def test_nse_findings_attached_to_hosts():
    r = FakeRunner()
    res = engine(r).scan(["192.168.1.0/24"], BUILTIN["security"])
    by_ip = {h.ip: h for h in res.hosts}
    assert by_ip["192.168.1.20"].findings
    assert all(f.host == "192.168.1.20" for f in by_ip["192.168.1.20"].findings)
    assert by_ip["192.168.1.1"].findings == []
    assert res.coverage.security_checks and res.complete
    call = [c for c in r.calls if c[0] == "nse_safe"]
    assert len(call) == 1
    assert call[0][1]["scripts"] == list(NSE_ALLOWED)
    assert call[0][1]["ports"] == "top100"
    assert call[0][1]["targets"] == ["192.168.1.1", "192.168.1.20"]


def test_findings_for_unknown_host_ignored():
    res = engine(FakeRunner(arp="", up=("192.168.1.1",))).scan(
        ["192.168.1.0/24"], BUILTIN["security"])
    assert [h.ip for h in res.hosts] == ["192.168.1.1"]
    assert res.hosts[0].findings == [] and res.coverage.security_checks


def test_nse_ports_fallback_to_top100_and_explicit_kept():
    r = FakeRunner()
    engine(r).scan(["192.168.1.0/24"], Profile("s", "", security_checks=True))
    assert [c for c in r.calls if c[0] == "nse_safe"][0][1]["ports"] == "top100"
    r = FakeRunner()
    engine(r).scan(["192.168.1.0/24"], Profile("s", "22,80", security_checks=True))
    assert [c for c in r.calls if c[0] == "nse_safe"][0][1]["ports"] == "22,80"


def test_nse_works_in_reduced_mode():
    r = FakeRunner()
    res = engine(r, privileged=False).scan(["192.168.1.0/24"], BUILTIN["security"])
    assert "nse_safe" in r.ops() and res.coverage.security_checks


def test_nse_failure_marks_incomplete_without_coverage():
    r = FakeRunner(fail={"nse_safe": HelperError("bad")})
    res = engine(r).scan(["192.168.1.0/24"], BUILTIN["security"])
    assert not res.coverage.security_checks and not res.complete
    assert any("security checks" in w for w in res.warnings)


def test_nse_bad_xml_is_a_warning():
    res = engine(FakeRunner(nse="<nmaprun><host>")).scan(
        ["192.168.1.0/24"], BUILTIN["security"])
    assert not res.coverage.security_checks and not res.complete and res.status == "done"


def test_topology_inferred_from_traceroute():
    r = FakeRunner()
    prof = Profile("t", "top100", traceroute=True)
    res = engine(r).scan(["192.168.1.0/24"], prof)
    assert "traceroute" in r.ops() and res.coverage.traceroute and res.complete
    topo = res.topology
    assert topo.inferred
    ids = node_ids(topo)
    assert {"192.168.1.1", "10.0.0.1", "10.0.1.1"} <= ids
    kinds = {n.id: n.kind for n in topo.nodes}
    assert kinds["192.168.1.1"] == "gateway" and kinds["10.0.0.1"] == "router"
    call = [c for c in r.calls if c[0] == "traceroute"][0]
    assert call[1] == {"targets": ["192.168.1.1", "192.168.1.20"]}


def test_star_topology_when_no_traceroute():
    r = FakeRunner()
    res = engine(r).scan(["192.168.1.0/24"], QUICK)
    assert "traceroute" not in r.ops() and not res.coverage.traceroute
    topo = res.topology
    assert topo is not None and topo.inferred
    assert {n.id for n in topo.nodes if n.kind == "gateway"} == {"192.168.1.1"}
    assert len(topo.edges) == 1 and "00:11:32:AA:BB:CC" in node_ids(topo)


def test_gateway_unknown_gives_virtual_gateway():
    res = engine(tools=FakeTools(gateway=None)).scan(["192.168.1.0/24"], QUICK)
    gws = [n for n in res.topology.nodes if n.kind == "gateway"]
    assert [n.id for n in gws] == ["gateway"]
    assert len(res.topology.edges) == 2


def test_gateway_error_is_tolerated():
    class Bad(FakeTools):
        def gateway(self):
            raise OSError("x")

    res = engine(tools=Bad()).scan(["192.168.1.0/24"], QUICK)
    assert res.topology is not None and res.status == "done"


def test_reduced_mode_skips_traceroute_with_warning():
    r = FakeRunner()
    res = engine(r, privileged=False).scan(
        ["192.168.1.0/24"], Profile("t", "top100", traceroute=True))
    assert "traceroute" not in r.ops() and not res.coverage.traceroute
    assert any("traceroute" in w and "reduced" in w for w in res.warnings)
    assert res.topology is not None  # stella


def test_zero_hosts_gateway_only_topology_and_no_host_steps():
    r = FakeRunner(arp="", up=())
    tools = FakeTools(mdns=[svc("192.168.1.9")])
    res = engine(r, tools=tools).scan(["192.168.1.0/24"], ALL, ScanOptions(snmp_community="x"))
    assert res.hosts == [] and res.status == "done"
    assert not ({"nse_safe", "traceroute"} & set(r.ops()))
    assert "snmp" not in tools.names()
    assert [n.kind for n in res.topology.nodes] == ["gateway"] and res.topology.edges == []
    assert not (res.coverage.traceroute or res.coverage.security_checks or res.coverage.snmp)
    assert res.coverage.mdns and res.coverage.ssdp


def test_chunked_targets_for_traceroute_and_nse():
    from landiscovery.helper import MAX_TARGETS
    ips = tuple(f"10.1.{i // 250}.{i % 250 + 1}" for i in range(MAX_TARGETS + 5))
    r = FakeRunner(arp="", up=ips, nse="<nmaprun/>", trace="<nmaprun/>")
    res = engine(r).scan(["10.1.0.0/16"], Profile("t", "top100", traceroute=True,
                                                    security_checks=True))
    for op in ("traceroute", "nse_safe"):
        sizes = [len(c[1]["targets"]) for c in r.calls if c[0] == op]
        assert sorted(sizes) == [5, MAX_TARGETS]
    assert res.coverage.traceroute and res.coverage.security_checks


def test_snmp_queries_hosts_with_community():
    tools = FakeTools(snmp={"192.168.1.20": svc("192.168.1.20", "snmp", "switch", "descr")})
    prof = Profile("p", "top100", snmp=True)
    res = engine(tools=tools).scan(["192.168.1.0/24"], prof, ScanOptions(snmp_community="lan"))
    assert [c[1:] for c in tools.calls if c[0] == "snmp"] == [
        ("192.168.1.1", "lan"), ("192.168.1.20", "lan")]
    assert res.coverage.snmp and res.complete  # nessuna risposta non è un errore
    assert [d.name for d in res.discovered] == ["switch"]
    h = [h for h in res.hosts if h.ip == "192.168.1.20"][0]
    assert h.services == ["snmp:switch"]


def test_snmp_skipped_without_community_with_warning():
    tools = FakeTools()
    prof = Profile("p", "top100", snmp=True)
    for opts in (None, ScanOptions(), ScanOptions(snmp_community="")):
        res = engine(tools=tools).scan(["192.168.1.0/24"], prof, opts)
        assert "snmp" not in tools.names()
        assert "snmp community not provided" in res.warnings
        assert not res.complete and not res.coverage.snmp and res.status == "done"


def test_snmp_not_requested_ignores_community():
    tools = FakeTools()
    res = engine(tools=tools).scan(["192.168.1.0/24"], QUICK, ScanOptions(snmp_community="x"))
    assert "snmp" not in tools.names() and not res.coverage.snmp and res.complete


def test_snmp_invalid_community_aborts_without_echo():
    secret = "s3cr3t community!"
    tools = FakeTools(raises={"snmp": ValueError(f"bad {secret}")})
    prof = Profile("p", "top100", snmp=True)
    res = engine(tools=tools).scan(["192.168.1.0/24"], prof, ScanOptions(snmp_community=secret))
    assert [c[0] for c in tools.calls].count("snmp") == 1  # il passo si ferma
    assert any(w.startswith("snmp") for w in res.warnings)
    assert secret not in " ".join(res.warnings) and "s3cr3t" not in " ".join(res.warnings)
    assert not res.coverage.snmp and not res.complete


def test_snmp_capped_at_256_hosts():
    ips = tuple(f"10.2.{i // 250}.{i % 250 + 1}" for i in range(300))
    tools = FakeTools()
    r = FakeRunner(arp="", up=ips)
    res = engine(r, tools=tools).scan(["10.2.0.0/16"], Profile("p", "", snmp=True),
                                      ScanOptions(snmp_community="c"))
    assert tools.names().count("snmp") == 256
    assert any("256" in w for w in res.warnings) and not res.coverage.snmp


def test_community_never_in_runner_args_or_logs(caplog):
    secret = "zz-secret-comm"
    tools = FakeTools(raises={"ssdp": OSError("net down")})
    r = FakeRunner(fail={"nse_safe": HelperError("bad")})
    with caplog.at_level(logging.DEBUG):
        res = engine(r, tools=tools).scan(["192.168.1.0/24"], ALL,
                                          ScanOptions(snmp_community=secret),
                                          on_progress=lambda s, f: None)
    assert secret not in repr(r.calls)
    assert secret not in caplog.text
    assert secret not in repr(res.warnings)
    assert secret not in repr(res.discovered)


def test_cancel_during_discovery_stops_all_steps():
    eng_box = []

    def on_call(name):
        if name == "mdns":
            eng_box[0].cancel()

    tools = FakeTools(on_call=on_call, mdns=[svc("192.168.1.20")])
    eng = engine(tools=tools)
    eng_box.append(eng)
    res = eng.scan(["192.168.1.0/24"], ALL, ScanOptions(snmp_community="c"))
    assert res.status == "cancelled" and not res.complete
    assert "ssdp" not in tools.names() and "snmp" not in tools.names()
    assert not res.coverage.mdns and not res.coverage.ssdp and not res.coverage.snmp
    assert res.coverage.security_checks and res.coverage.traceroute  # già conclusi
    assert [h.ip for h in res.hosts] == ["192.168.1.1", "192.168.1.20"]


def test_cancel_before_ssdp_skips_blocking_call():
    tools = FakeTools()
    eng = engine(tools=tools)
    eng.runner.on_call = lambda op, params: eng.cancel() if op == "nse_safe" else None
    prof = Profile("p", "top100", security_checks=True, mdns=True, ssdp=True)
    res = eng.scan(["192.168.1.0/24"], prof)
    assert res.status == "cancelled"
    assert "mdns" not in tools.names()
    assert "ssdp" not in tools.names()


def test_cancel_during_traceroute_keeps_hosts_and_star():
    eng = engine()
    eng.runner.on_call = lambda op, params: eng.cancel() if op == "traceroute" else None
    res = eng.scan(["192.168.1.0/24"], Profile("t", "top100", traceroute=True,
                                                security_checks=True))
    assert res.status == "cancelled" and not res.coverage.traceroute
    assert not res.coverage.security_checks
    assert len(res.hosts) == 2 and res.topology is not None


def test_progress_includes_new_steps_in_order():
    calls = []
    engine().scan(["192.168.1.0/24"], ALL, ScanOptions(snmp_community="c"),
                  on_progress=lambda s, f: calls.append((s, f)))
    names = []
    for n, _ in calls:
        if n not in names:
            names.append(n)
    assert names == ["discovery", "ports", "traceroute", "security", "mdns", "ssdp", "snmp"]
    fr = [c[1] for c in calls]
    assert fr == sorted(fr) and fr[-1] == 1.0


def test_default_tools_are_used_when_none_given():
    eng = ScanEngine(runner=FakeRunner(), oui=FakeOui(), privileged=True)
    assert all(hasattr(eng.tools, n) for n in ("mdns", "ssdp", "snmp", "gateway"))


def test_read_default_gateway(tmp_path):
    route = tmp_path / "route"
    route.write_text(
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
        "eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
        "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n")
    assert read_default_gateway(str(route)) == "192.168.1.1"
    assert read_default_gateway(str(tmp_path / "missing")) is None
    bad = tmp_path / "bad"
    bad.write_text("garbage\n\x00\xff")
    assert read_default_gateway(str(bad)) is None


def test_parse_arp_entries_keeps_every_ip_of_a_shared_mac():
    from landiscovery.engine import parse_arp_entries
    text = ("10.0.0.2\taa:bb:cc:00:00:01\tVendor\n10.0.0.3\taa:bb:cc:00:00:01\tVendor\n"
            "10.0.0.3\taa:bb:cc:00:00:01\tVendor (DUP: 2)\n")
    assert parse_arp_entries(text) == [("10.0.0.2", "AA:BB:CC:00:00:01", "Vendor"),
                                       ("10.0.0.3", "AA:BB:CC:00:00:01", "Vendor")]
