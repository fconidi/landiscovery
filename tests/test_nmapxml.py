from pathlib import Path

import pytest

from landiscovery.nmapxml import ScanParseError, parse_nmap_xml

FIX = Path(__file__).parent / "fixtures"


def load(name):
    return (FIX / name).read_text(encoding="utf-8")


def test_parse_basic_hosts():
    hosts = parse_nmap_xml(load("nmap_basic.xml"))
    assert [h.ip for h in hosts] == ["192.168.1.1", "192.168.1.20", "192.168.1.100", "fe80::1"]
    r = hosts[0]
    assert r.mac == "B8:27:EB:12:34:56"
    assert r.vendor == "Raspberry Pi Foundation"
    assert r.hostname == "router.lan"
    assert r.latency_ms == pytest.approx(1.25)
    assert r.os == "Linux 5.4 - 5.15"
    assert r.key == "B8:27:EB:12:34:56"
    assert [(p.number, p.proto, p.state, p.service) for p in r.ports] == [
        (22, "tcp", "open", "ssh"),
        (53, "tcp", "open", "domain"),
        (80, "tcp", "open", "http"),
        (443, "tcp", "closed", "https"),
    ]
    assert r.ports[0].version == "OpenSSH 9.2p1 Debian 2+deb12u3"
    assert r.ports[1].version == "dnsmasq 2.89"
    assert r.ports[2].version == "lighttpd"
    h2 = hosts[1]
    assert h2.vendor == "" and h2.hostname == "" and h2.os == ""
    assert h2.latency_ms == pytest.approx(15.8)
    assert (h2.ports[1].proto, h2.ports[1].state) == ("udp", "open|filtered")
    h3 = hosts[2]
    assert h3.mac is None and h3.key == "192.168.1.100"
    assert h3.hostname == "desktop.lan" and h3.latency_ms is None
    assert h3.os == "Linux 6.1"
    assert hosts[3].mac is None


def test_parse_skips_down_hosts():
    ips = [h.ip for h in parse_nmap_xml(load("nmap_basic.xml"))]
    assert "192.168.1.50" not in ips


def test_parse_empty_returns_no_hosts():
    assert parse_nmap_xml(load("nmap_empty.xml")) == []


def test_parse_truncated_raises():
    with pytest.raises(ScanParseError):
        parse_nmap_xml(load("nmap_truncated.xml"))


@pytest.mark.parametrize("text", ["", "   \n", "<html/>"])
def test_parse_blank_or_foreign_raises(text):
    with pytest.raises(ScanParseError):
        parse_nmap_xml(text)
