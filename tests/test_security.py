from pathlib import Path

import pytest

from landiscovery import security
from landiscovery.nmapxml import ScanParseError
from landiscovery.security import TITLES, parse_nse_findings

FIX = Path(__file__).parent / "fixtures"


def load(name):
    return (FIX / name).read_text(encoding="utf-8")


def one(script_id, output, port=80, service="http", elems="", host="10.0.0.1"):
    return (
        '<nmaprun><host><address addr="%s" addrtype="ipv4"/><ports>'
        '<port protocol="tcp" portid="%s"><state state="open"/><service name="%s"/>'
        '<script id="%s" output="%s">%s</script></port></ports></host></nmaprun>'
        % (host, port, service, script_id, output, elems)
    )


def hostscript(script_id, output, elems=""):
    return (
        '<nmaprun><host><address addr="10.0.0.1" addrtype="ipv4"/><ports/><hostscript>'
        '<script id="%s" output="%s">%s</script></hostscript></host></nmaprun>'
        % (script_id, output, elems)
    )


def titles(findings, severity=None):
    return [f.title for f in findings if severity is None or f.severity == severity]


@pytest.fixture(scope="module")
def fx():
    return parse_nse_findings(load("nmap_nse.xml"))


def by_host(fx, ip):
    return [f for f in fx if f.host == ip]


def test_open_telnet_is_warning(fx):
    f = [x for x in fx if x.title == TITLES["telnet_open"]]
    assert len(f) == 1 and f[0].severity == "warning" and f[0].host == "192.168.1.10"
    assert "23/tcp" in f[0].detail


def test_open_telnet_by_port_only():
    xml = ('<nmaprun><host><address addr="10.0.0.1" addrtype="ipv4"/><ports>'
           '<port protocol="tcp" portid="23"><state state="open"/></port></ports></host></nmaprun>')
    assert titles(parse_nse_findings(xml)) == [TITLES["telnet_open"]]


def test_closed_telnet_not_reported():
    xml = ('<nmaprun><host><address addr="10.0.0.1" addrtype="ipv4"/><ports>'
           '<port protocol="tcp" portid="23"><state state="closed"/><service name="telnet"/></port>'
           '</ports></host></nmaprun>')
    assert parse_nse_findings(xml) == []


def test_smb1_is_critical(fx):
    f = [x for x in fx if x.severity == "critical"]
    assert [x.title for x in f] == [TITLES["smb1_enabled"]]
    assert f[0].host == "192.168.1.20"


def test_smb2_only_not_critical():
    xml = one("smb-protocols", "dialects: 2.02 2.10 3.00", 445, "microsoft-ds")
    assert parse_nse_findings(xml) == []


def test_no_scripts_no_findings():
    xml = ('<nmaprun><host><address addr="10.0.0.1" addrtype="ipv4"/><ports>'
           '<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>'
           '</ports></host></nmaprun>')
    assert parse_nse_findings(xml) == []
    assert parse_nse_findings("<nmaprun/>") == []


def test_unknown_script_ignored(fx):
    assert not any("something interesting" in f.detail for f in fx)
    assert parse_nse_findings(one("made-up-script", "boom")) == []


def test_ftp_anon(fx):
    f = [x for x in fx if x.title == TITLES["ftp_anon"]]
    assert len(f) == 1 and f[0].severity == "warning"


def test_ftp_anon_not_allowed():
    assert parse_nse_findings(one("ftp-anon", "Login failed", 21, "ftp")) == []


def test_smb_signing_disabled_and_guest(fx):
    t = titles(by_host(fx, "192.168.1.20"), "warning")
    assert TITLES["smb_signing"] in t
    assert TITLES["smb_guest"] in t


@pytest.mark.parametrize("value,expect", [
    ("disabled", True), ("supported", True), ("not required", True),
    ("required", False), ("enabled and required", False)])
def test_smb_signing_values(value, expect):
    xml = one("smb-security-mode", "message_signing: " + value, 445, "microsoft-ds")
    assert (TITLES["smb_signing"] in titles(parse_nse_findings(xml))) is expect


def test_smb2_signing_not_required():
    xml = one("smb2-security-mode", "3:1:1: Message signing enabled but not required", 445)
    assert TITLES["smb_signing"] in titles(parse_nse_findings(xml))
    xml = one("smb2-security-mode", "3:1:1: Message signing enabled and required", 445)
    assert parse_nse_findings(xml) == []


def test_http_methods_risky(fx):
    f = [x for x in fx if x.title == TITLES["http_risky_methods"]]
    assert len(f) == 1 and f[0].severity == "warning"
    assert "TRACE" in f[0].detail and "PUT" in f[0].detail


def test_http_methods_safe():
    assert parse_nse_findings(one("http-methods", "Supported Methods: GET HEAD POST OPTIONS")) == []


def test_ssh_weak_algorithms(fx):
    f = [x for x in fx if x.title == TITLES["ssh_weak_algos"]]
    assert len(f) == 1 and f[0].severity == "warning"
    for a in ("diffie-hellman-group1-sha1", "arcfour", "3des-cbc", "hmac-md5", "ssh-dss"):
        assert a in f[0].detail


def test_ssh_strong_algorithms():
    assert parse_nse_findings(one("ssh2-enum-algos", "kex: curve25519-sha256 aes128-ctr", 22, "ssh")) == []


def test_expired_vs_valid_cert(fx):
    exp = [x for x in fx if x.title == TITLES["cert_expired"]]
    assert [x.host for x in exp] == ["192.168.1.10"]
    assert exp[0].severity == "warning"
    assert TITLES["cert_info"] in titles(by_host(fx, "192.168.1.30"), "info")


def test_cert_date_unparsable_no_finding():
    out = "Subject: commonName=x&#10;Not valid after:  not-a-date"
    assert TITLES["cert_expired"] not in titles(parse_nse_findings(one("ssl-cert", out, 443, "https")))


def test_cert_expired_uses_now():
    import datetime as dt
    out = "Subject: commonName=x&#10;Not valid after:  2030-01-01T00:00:00"
    xml = one("ssl-cert", out, 443, "https")
    assert TITLES["cert_expired"] not in titles(parse_nse_findings(xml))
    later = dt.datetime(2031, 1, 1, tzinfo=dt.timezone.utc)
    assert TITLES["cert_expired"] in titles(parse_nse_findings(xml, now=later))


def test_cert_expired_from_elems():
    elems = '<table key="validity"><elem key="notAfter">2001-02-03T04:05:06</elem></table>'
    xml = one("ssl-cert", "Subject: commonName=x", 443, "https", elems)
    assert TITLES["cert_expired"] in titles(parse_nse_findings(xml))


def test_rdp_native(fx):
    f = [x for x in fx if x.title == TITLES["rdp_no_nla"]]
    assert len(f) == 1 and f[0].severity == "warning"


def test_rdp_nla_only_ok():
    out = "Security layer&#10;  CredSSP (NLA): SUCCESS&#10;  Native RDP: FAILURE"
    assert parse_nse_findings(one("rdp-enum-encryption", out, 3389)) == []


def test_rdp_without_credssp():
    out = "Security layer&#10;  CredSSP (NLA): FAILURE&#10;  SSL: SUCCESS"
    assert TITLES["rdp_no_nla"] in titles(parse_nse_findings(one("rdp-enum-encryption", out, 3389)))


def test_telnet_encryption(fx):
    assert TITLES["telnet_no_encryption"] in titles(fx, "warning")


def test_info_findings(fx):
    inf = titles(fx, "info")
    for k in ("http_title", "http_server", "ssh_hostkeys", "snmp_info", "upnp_info",
              "nbstat", "banner", "cert_info"):
        assert TITLES[k] in inf, k
    hk = [x for x in fx if x.title == TITLES["ssh_hostkeys"]]
    assert len(hk) == 1
    assert "RSA 3072" in hk[0].detail and "ED25519 256" in hk[0].detail
    t = [x for x in fx if x.title == TITLES["http_title"]][0]
    assert t.detail.endswith("Welcome to the router")


def test_hostscript(fx):
    f = [x for x in fx if x.title == TITLES["nbstat"]]
    assert len(f) == 1 and f[0].host == "192.168.1.20"
    assert "DESKTOP-1" in f[0].detail


def test_host_prefers_ipv4(fx):
    assert "fe80::2" not in {f.host for f in fx}
    xml = ('<nmaprun><host><address addr="fe80::9" addrtype="ipv6"/><ports>'
           '<port protocol="tcp" portid="23"><state state="open"/></port></ports></host></nmaprun>')
    assert parse_nse_findings(xml)[0].host == "fe80::9"


def test_ordering(fx):
    rank = {"critical": 0, "warning": 1, "info": 2}
    ranks = [rank[f.severity] for f in fx]
    assert ranks == sorted(ranks)
    warn_hosts = [f.host for f in fx if f.severity == "warning"]
    assert warn_hosts == sorted(warn_hosts, key=lambda h: tuple(map(int, h.split("."))))


def test_dedup():
    one_host = ('<host><address addr="10.0.0.1" addrtype="ipv4"/><ports>'
                '<port protocol="tcp" portid="23"><state state="open"/></port></ports></host>')
    assert len(parse_nse_findings("<nmaprun>" + one_host * 3 + "</nmaprun>")) == 1


@pytest.mark.parametrize("text", ["", "   ", '<nmaprun><host>', load("nmap_truncated.xml")])
def test_bad_xml_raises(text):
    with pytest.raises(ScanParseError):
        parse_nse_findings(text)


def test_not_nmap_raises():
    with pytest.raises(ScanParseError):
        parse_nse_findings("<html/>")


def test_control_characters_stripped():
    evil = "a&#x202E;b&#x200B;c&#x2028;d&#x7F;e&#x85;f&#x2066;g"
    f = parse_nse_findings(one("http-title", evil))
    assert len(f) == 1
    for ch in "‮​ \x07\x1b":
        assert ch not in f[0].detail
        assert ch not in f[0].title
    assert "abcdefg" in f[0].detail


def test_huge_output_capped():
    big = "A" * 2_000_000
    f = parse_nse_findings(one("http-title", big))
    assert len(f[0].detail) <= 300 and len(f[0].title) <= 120
    f = parse_nse_findings(one("ssh2-enum-algos", "arcfour " * 300000, 22, "ssh"))
    assert len(f[0].detail) <= 300


def test_template_not_formatted():
    f = parse_nse_findings(one("http-title", "%s %(x)s {0} {x}"))
    assert f[0].detail.endswith("%s %(x)s {0} {x}")


def test_hostile_attributes():
    xml = ('<nmaprun><host><address addr="10.0.0.1" addrtype="ipv4"/><ports>'
           '<port protocol="tcp" portid="abc"><script id="http-title"/></port>'
           '<port><script output="x"/><script id="banner"/></port>'
           '<port portid="99999999999999999999"><state/><script id="banner" output="hi"/></port>'
           '</ports><hostscript><script/></hostscript></host>'
           '<host><ports><port portid="23"><state state="open"/></port></ports></host></nmaprun>')
    f = parse_nse_findings(xml)
    assert [(x.host, x.severity, x.title) for x in f] == [
        ("10.0.0.1", "info", TITLES["banner"])]
    assert f[0].detail == "hi"


def test_rules_table_complete():
    from landiscovery.helper import NSE_ALLOWED
    covered = {r.script for r in security.RULES if r.script}
    assert covered == set(NSE_ALLOWED)
    assert all(r.key in TITLES for r in security.RULES)
    assert all(len(t) <= 120 for t in TITLES.values())


def test_clean_strips_c0_controls():
    assert security._clean("a\x07b\x1bc\x00d\te") == "abcd e"


# ---- review round 1

@pytest.mark.parametrize("out", [
    "SMBv1 not supported", "SMBv1 disabled", "dialects:&#10;  2.02&#10;  SMBv1 is disabled",
    "SMBv1: not enabled"])
def test_smb1_negative_phrases(out):
    assert parse_nse_findings(hostscript("smb-protocols", out)) == []
    assert parse_nse_findings(one("smb-protocols", out, 445)) == []


@pytest.mark.parametrize("out", [
    "dialects:&#10;  NT LM 0.12 (SMBv1) [dangerous, but default]&#10;  2.02",
    "dialects:&#10;  NT LM 0.12&#10;  2.02",
    "dialects:&#10;  2.02&#10;  (SMBv1)"])
def test_smb1_dialect_lines(out):
    f = parse_nse_findings(hostscript("smb-protocols", out))
    assert titles(f) == [TITLES["smb1_enabled"]] and f[0].severity == "critical"


def test_smb_hostscript_fixture(fx):
    assert TITLES["smb1_enabled"] in titles(by_host(fx, "192.168.1.20"), "critical")
    assert TITLES["smb_signing"] in titles(by_host(fx, "192.168.1.20"), "warning")


def test_smb_security_mode_hostscript():
    out = "account_used: guest&#10;message_signing: disabled"
    assert set(titles(parse_nse_findings(hostscript("smb-security-mode", out)))) == {
        TITLES["smb_signing"], TITLES["smb_guest"]}


def test_smb_guest_negative():
    xml = hostscript("smb-security-mode", "account_used: &lt;blank&gt;&#10;message_signing: required")
    assert parse_nse_findings(xml) == []
    xml = one("smb-security-mode", "", 445, "microsoft-ds",
              '<elem key="account_used">user1</elem><elem key="message_signing">required</elem>')
    assert parse_nse_findings(xml) == []


def test_telnet_encryption_negative():
    xml = one("telnet-encryption", "Telnet server supports encryption", 80, "http")
    assert parse_nse_findings(xml) == []


def test_nbstat_hostscript_only(fx):
    assert [f.host for f in fx if f.title == TITLES["nbstat"]] == ["192.168.1.20"]


def test_rdp_credssp_and_ssl_warns():
    out = "Security layer&#10;  CredSSP (NLA): SUCCESS&#10;  SSL: SUCCESS&#10;  Native RDP: FAILURE"
    assert titles(parse_nse_findings(one("rdp-enum-encryption", out, 3389))) == [TITLES["rdp_no_nla"]]


def test_rdp_credssp_and_rdstls_warns():
    out = "CredSSP (NLA): SUCCESS&#10;RDSTLS: SUCCESS"
    assert titles(parse_nse_findings(one("rdp-enum-encryption", out, 3389))) == [TITLES["rdp_no_nla"]]


def test_rdp_credssp_only_ok():
    out = ("Security layer&#10;  CredSSP (NLA): SUCCESS&#10;  CredSSP with Early User Auth: SUCCESS"
           "&#10;  Native RDP: FAILURE&#10;  RDSTLS: FAILURE&#10;  SSL: FAILURE")
    assert parse_nse_findings(one("rdp-enum-encryption", out, 3389)) == []


def test_rdp_native_only_warns():
    out = "Security layer&#10;  Native RDP: SUCCESS"
    assert titles(parse_nse_findings(one("rdp-enum-encryption", out, 3389))) == [TITLES["rdp_no_nla"]]


def test_rdp_early_user_auth_does_not_mask_nla_failure():
    out = ("CredSSP with Early User Auth: SUCCESS&#10;CredSSP (NLA): FAILURE&#10;SSL: FAILURE")
    assert titles(parse_nse_findings(one("rdp-enum-encryption", out, 3389))) == [TITLES["rdp_no_nla"]]


def test_cert_unparsable_elem_falls_back_to_text():
    out = "Subject: commonName=x&#10;Not valid after:  2001-02-03T04:05:06"
    elems = '<elem key="notAfter">garbage</elem>'
    assert TITLES["cert_expired"] in titles(parse_nse_findings(one("ssl-cert", out, 443, "https", elems)))


def test_large_elem_is_fast():
    import time
    elems = '<elem key="x">' + "A" * 3_000_000 + "</elem>"
    t0 = time.monotonic()
    parse_nse_findings(one("ssl-cert", "Subject: commonName=x", 443, "https", elems))
    assert time.monotonic() - t0 < 1.0


@pytest.mark.parametrize("algo", ["blowfish-cbc", "cast128-cbc", "diffie-hellman-group-exchange-sha1"])
def test_more_weak_ssh_algos(algo):
    f = parse_nse_findings(one("ssh2-enum-algos", "enc: aes128-ctr " + algo, 22, "ssh"))
    assert titles(f) == [TITLES["ssh_weak_algos"]] and algo in f[0].detail


def test_entity_declarations_rejected():
    bomb = ('<?xml version="1.0"?><!DOCTYPE nmaprun [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;">]>'
            '<nmaprun>&b;</nmaprun>')
    with pytest.raises(ScanParseError):
        parse_nse_findings(bomb)
    from landiscovery.nmapxml import parse_nmap_xml
    with pytest.raises(ScanParseError):
        parse_nmap_xml(bomb)
    with pytest.raises(ScanParseError):
        parse_nse_findings('<!DOCTYPE nmaprun [ ]><nmaprun/>')


def test_plain_doctype_accepted():
    assert parse_nse_findings("<!DOCTYPE nmaprun>\n<nmaprun/>") == []
