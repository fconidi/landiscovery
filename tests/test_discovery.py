import logging
import os
import socket
import stat
import subprocess
from pathlib import Path

import pytest

from landiscovery import discovery
from landiscovery.discovery import (
    ToolMissing,
    discover_mdns,
    discover_ssdp,
    parse_avahi,
    parse_ssdp_response,
    query_snmp,
    run_tool,
)

FIXTURE = Path(__file__).parent / "fixtures" / "avahi_browse.txt"
COMMUNITY = "s3cr3tCommunity.x"


def test_parse_avahi_output():
    res = parse_avahi(FIXTURE.read_text())
    by_ip = {s.ip: s for s in res}
    assert set(by_ip) == {
        "192.168.1.20", "fe80::2a0:c9ff:fe12:3456", "2001:db8::20", "192.168.1.31",
    }
    s = by_ip["192.168.1.20"]
    assert s.kind == "mdns"
    assert s.name == "Stampante Ufficio"
    assert s.detail == "_ipp._tcp stampante.local:631"
    assert len(res) == 4  # duplicato rimosso
    assert by_ip["192.168.1.31"].detail == "_googlecast._tcp Chromecast-1234.local:8009"


def test_parse_avahi_sanitizes():
    line = "=;eth0;IPv4;" + "A" * 300 + "\\007x;_t._tcp;local;h.local;10.0.0.1;80;\n"
    res = parse_avahi(line)
    assert len(res[0].name) == 120
    assert "\x07" not in res[0].name
    assert len(res[0].detail) <= 200


def test_mdns_uses_expected_command():
    seen = []

    def runner(argv, timeout, env=None):
        seen.append(argv)
        return FIXTURE.read_text()

    res = discover_mdns(runner=runner)
    assert seen == [["avahi-browse", "-a", "-t", "-r", "-p"]]
    assert len(res) == 4


def test_mdns_missing_tool_raises_ToolMissing():
    def runner(argv, timeout, env=None):
        raise ToolMissing(argv[0])

    with pytest.raises(ToolMissing):
        discover_mdns(runner=runner)


def test_run_tool_missing_binary():
    with pytest.raises(ToolMissing):
        run_tool(["landiscovery-no-such-binary-xyz"], 1.0)


def test_run_tool_timeout_returns_empty():
    assert run_tool(["sleep", "5"], 0.2) == ""


def test_run_tool_output():
    assert run_tool(["echo", "ciao"], 2.0).strip() == "ciao"


SSDP_RESP = (
    b"HTTP/1.1 200 OK\r\n"
    b"CACHE-CONTROL: max-age=1800\r\n"
    b"Location: http://192.168.1.1:5000/desc.xml\r\n"
    b"server: Linux/5.4 UPnP/1.0 MiniUPnPd/2.1\r\n"
    b"ST: upnp:rootdevice\r\n"
    b"USN: uuid:abc::upnp:rootdevice\r\n\r\n"
)


class FakeSock:
    def __init__(self, packets):
        self.packets = list(packets)
        self.sent = []
        self.closed = False

    def settimeout(self, t):
        pass

    def sendto(self, data, addr):
        self.sent.append((data, addr))

    def recvfrom(self, n):
        if self.packets:
            return self.packets.pop(0)
        raise socket.timeout()

    def close(self):
        self.closed = True


def test_ssdp_parses_response():
    sock = FakeSock([(SSDP_RESP, ("192.168.1.1", 1900))])
    res = discover_ssdp(timeout=0.3, sock=sock)
    assert len(res) == 1
    s = res[0]
    assert s.ip == "192.168.1.1"
    assert s.kind == "ssdp"
    assert s.name == "Linux/5.4 UPnP/1.0 MiniUPnPd/2.1"
    assert s.detail == "upnp:rootdevice http://192.168.1.1:5000/desc.xml"
    data, addr = sock.sent[0]
    assert addr == ("239.255.255.250", 1900)
    assert b"M-SEARCH * HTTP/1.1" in data
    assert b"ST: ssdp:all" in data
    assert b"MX: 2" in data
    assert b'MAN: "ssdp:discover"' in data


def test_ssdp_name_falls_back_to_usn():
    resp = b"HTTP/1.1 200 OK\r\nST: x\r\nUSN: uuid:1\r\n\r\n"
    s = parse_ssdp_response(resp, ("10.0.0.5", 1900))
    assert s.name == "uuid:1"


def test_ssdp_ignores_malformed_packets():
    pk = [
        (b"\xff\xfe\x00garbage", ("192.168.1.9", 1900)),
        (b"", ("192.168.1.9", 1900)),
        (b"NOTIFY * HTTP/1.1\r\nHost: x\r\n\r\n", ("192.168.1.9", 1900)),
        (b"HTTP/1.1 200 OK\r\nST: x\r\n\r\n", ("192.168.1.9", 1900)),  # senza SERVER/USN
        (SSDP_RESP, ("not-an-ip", 1900)),
        (SSDP_RESP, ("192.168.1.1", 1900)),
    ]
    sock = FakeSock(pk)
    res = discover_ssdp(timeout=0.3, sock=sock)
    assert [s.ip for s in res] == ["192.168.1.1"]


def test_ssdp_closes_internal_socket(monkeypatch):
    made = []

    def fake_factory(*a, **k):
        s = FakeSock([])
        made.append(s)
        return s

    monkeypatch.setattr(discovery, "_make_ssdp_socket", fake_factory)
    discover_ssdp(timeout=0.2)
    assert made and made[0].closed


# --- SNMP ---

def make_runner(output="router1\nLinux router 5.4\nsecond line", record=None, raises=None):
    def runner(argv, timeout, env=None):
        if record is not None:
            record["argv"] = list(argv)
            record["env"] = dict(env or {})
            d = env["SNMPCONFPATH"]
            record["dir"] = d
            record["dir_mode"] = stat.S_IMODE(os.stat(d).st_mode)
            conf = os.path.join(d, "snmp.conf")
            record["file_mode"] = stat.S_IMODE(os.stat(conf).st_mode)
            record["conf"] = Path(conf).read_text()
        if raises:
            raise raises
        return output

    return runner


def test_snmp_basic():
    rec = {}
    s = query_snmp("192.168.1.1", COMMUNITY, runner=make_runner(record=rec))
    assert s.kind == "snmp" and s.ip == "192.168.1.1"
    assert s.name == "router1"
    assert s.detail == "Linux router 5.4"
    assert rec["argv"] == [
        "snmpget", "-r1", "-t2", "-Oqv", "192.168.1.1",
        "1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.1.0",
    ]
    assert "defVersion 2c" in rec["conf"]
    assert f"defCommunity {COMMUNITY}" in rec["conf"]
    assert rec["env"]["SNMP_PERSISTENT_DIR"] == rec["dir"]


def test_snmp_detail_capped():
    out = "n\n" + "d" * 500
    s = query_snmp("10.0.0.1", COMMUNITY, runner=make_runner(out))
    assert len(s.detail) == 200


def test_snmp_community_not_in_argv():
    rec = {}
    query_snmp("192.168.1.1", COMMUNITY, runner=make_runner(record=rec))
    assert not any(COMMUNITY in a for a in rec["argv"])


def test_snmp_community_not_in_logs(caplog):
    caplog.set_level(logging.DEBUG)
    query_snmp("192.168.1.1", COMMUNITY, runner=make_runner())
    query_snmp("192.168.1.1", COMMUNITY, runner=make_runner(""))
    with pytest.raises(RuntimeError):
        query_snmp("192.168.1.1", COMMUNITY, runner=make_runner(raises=RuntimeError("boom")))
    text = caplog.text + "".join(str(r.args) + r.getMessage() for r in caplog.records)
    assert COMMUNITY not in text


def test_snmp_dir_permissions_during_run():
    rec = {}
    query_snmp("192.168.1.1", COMMUNITY, runner=make_runner(record=rec))
    assert rec["dir_mode"] == 0o700
    assert rec["file_mode"] == 0o600


def test_snmp_dir_removed_after_call():
    rec = {}
    query_snmp("192.168.1.1", COMMUNITY, runner=make_runner(record=rec))
    assert not os.path.exists(rec["dir"])


def test_snmp_dir_removed_when_runner_raises():
    rec = {}
    with pytest.raises(RuntimeError) as ei:
        query_snmp("192.168.1.1", COMMUNITY,
                   runner=make_runner(record=rec, raises=RuntimeError("boom")))
    assert not os.path.exists(rec["dir"])
    assert COMMUNITY not in str(ei.value)


def test_snmp_tool_missing_propagates_and_cleans():
    rec = {}
    with pytest.raises(ToolMissing):
        query_snmp("192.168.1.1", COMMUNITY,
                   runner=make_runner(record=rec, raises=ToolMissing("snmpget")))
    assert not os.path.exists(rec["dir"])


@pytest.mark.parametrize("out", ["", "\n", "Timeout: No Response from 192.168.1.1", "No Response from x"])
def test_snmp_timeout_returns_none(out):
    assert query_snmp("192.168.1.1", COMMUNITY, runner=make_runner(out)) is None


@pytest.mark.parametrize("bad", ["", "a b", "a;b", "x" * 65, "pub\nlic", "caffè", "a/b"])
def test_snmp_invalid_community_rejected(bad):
    called = []
    with pytest.raises(ValueError) as ei:
        query_snmp("192.168.1.1", bad, runner=lambda *a, **k: called.append(1) or "")
    assert not called
    assert bad not in str(ei.value) or bad == ""


@pytest.mark.parametrize("ip", ["", "999.1.1.1", "-h", "host.local", "1.2.3.4; ls"])
def test_snmp_invalid_ip_rejected(ip):
    with pytest.raises(ValueError):
        query_snmp(ip, "public", runner=make_runner())


# --- fix round 1 ---

@pytest.mark.parametrize("ip", ["fe80::1%eth0", "fe80::1%-h x", "fe80::1%1"])
def test_snmp_rejects_scoped_ipv6(ip):
    called = []
    with pytest.raises(ValueError):
        query_snmp(ip, "public", runner=lambda *a, **k: called.append(1) or "")
    assert not called


def test_parsers_never_return_percent():
    for s in parse_avahi(FIXTURE.read_text()):
        assert "%" not in s.ip
    resp = b"HTTP/1.1 200 OK\r\nSERVER: x\r\n\r\n"
    s = parse_ssdp_response(resp, ("fe80::1%eth0", 1900, 0, 2))
    assert s.ip == "fe80::1"


@pytest.mark.parametrize("msg", [
    "No Such Object available on this agent at this OID",
    "No Such Instance currently exists at this OID",
    "no such name",
])
def test_snmp_no_such_sysname_returns_none(msg):
    assert query_snmp("10.0.0.1", COMMUNITY, runner=make_runner(f"{msg}\ndescr")) is None
    assert query_snmp("10.0.0.1", COMMUNITY, runner=make_runner(f"{msg}\n{msg}")) is None


@pytest.mark.parametrize("msg", [
    "No Such Object available on this agent at this OID",
    "No Such Instance currently exists at this OID",
    "No Such Name",
])
def test_snmp_no_such_sysdescr_gives_empty_detail(msg):
    s = query_snmp("10.0.0.1", COMMUNITY, runner=make_runner(f"host1\n{msg}"))
    assert s.name == "host1" and s.detail == ""


def test_control_and_bidi_stripped():
    bad = "a\u202eb\u2066c\u2069d\u2028e\u2029f\u200bg\u200fh\ufeffi"
    line = f"=;eth0;IPv4;{bad};_t._tcp;local;h.local;10.0.0.1;80;\n"
    assert parse_avahi(line)[0].name == "abcdefghi"
    resp = f"HTTP/1.1 200 OK\r\nSERVER: {bad}\r\n\r\n".encode()
    assert parse_ssdp_response(resp, ("10.0.0.2", 1900)).name == "abcdefghi"


def test_avahi_escape_rules():
    line = "=;e;IPv4;A\\999B\\065;_t._tcp;local;h.local;10.0.0.1;80;\n"
    assert parse_avahi(line)[0].name == "A\\999BA"
    # cifre non ASCII non sono escape
    line = "=;e;IPv4;A\\\u0661\u0662\u0663;_t._tcp;local;h.local;10.0.0.1;80;\n"
    assert "\\" in parse_avahi(line)[0].name


@pytest.mark.parametrize("port", ["80x", "", "-1", "8 0", "\u0668\u0660"])
def test_avahi_bad_port_skipped(port):
    line = f"=;e;IPv4;N;_t._tcp;local;h.local;10.0.0.1;{port};\n"
    assert parse_avahi(line) == []


@pytest.mark.parametrize("status", [
    b"HTTP/1.1 2000 OK", b"HTTP/2 200 OK", b"HTTP/1.1 404 x", b"XHTTP/1.1 200 OK",
    b"HTTP/1.1 500 200",
])
def test_ssdp_status_line_strict(status):
    data = status + b"\r\nSERVER: x\r\n\r\n"
    assert parse_ssdp_response(data, ("10.0.0.1", 1900)) is None


def test_ssdp_stops_at_empty_line():
    data = b"HTTP/1.1 200 OK\r\nST: a\r\n\r\nSERVER: injected\r\n"
    assert parse_ssdp_response(data, ("10.0.0.1", 1900)) is None


def test_ssdp_caps_results():
    pk = []
    for i in range(600):
        resp = f"HTTP/1.1 200 OK\r\nSERVER: s{i}\r\n\r\n".encode()
        pk.append((resp, ("10.0.%d.%d" % (i // 250, i % 250 + 1), 1900)))
    res = discover_ssdp(timeout=2.0, sock=FakeSock(pk))
    assert len(res) == 500


def test_ssdp_send_error_propagates_and_closes():
    class Bad(FakeSock):
        def sendto(self, data, addr):
            raise OSError("rete non raggiungibile")

    sock = Bad([])
    with pytest.raises(OSError):
        discover_ssdp(timeout=0.2, sock=sock)


def test_ssdp_send_error_closes_internal(monkeypatch):
    class Bad(FakeSock):
        def sendto(self, data, addr):
            raise OSError("x")

    made = []
    monkeypatch.setattr(discovery, "_make_ssdp_socket", lambda: made.append(Bad([])) or made[0])
    with pytest.raises(OSError):
        discover_ssdp(timeout=0.2)
    assert made[0].closed


def test_run_tool_permission_error_maps_to_toolmissing(monkeypatch):
    def boom(*a, **k):
        raise PermissionError("secret path /x/y")

    monkeypatch.setattr(subprocess, "run", boom)
    with pytest.raises(ToolMissing) as ei:
        run_tool(["foo", "arg"], 1.0)
    assert str(ei.value) == "foo"


def test_run_tool_caps_output():
    out = run_tool(["python3", "-c", "print('a' * (3 * 1024 * 1024))"], 10.0)
    assert len(out) == 1024 * 1024
