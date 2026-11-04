import ipaddress

import pytest

from landiscovery.targets import ScopeCheck, TargetError, check_scope, parse_targets


def test_parse_cidr_and_single_ip():
    nets = parse_targets("192.168.1.0/24, 10.0.0.5 fe80::1")
    assert nets[0] == ipaddress.ip_network("192.168.1.0/24")
    assert nets[1] == ipaddress.ip_network("10.0.0.5/32")
    assert nets[2] == ipaddress.ip_network("fe80::1/128")


def test_parse_ignores_empty_tokens():
    assert len(parse_targets("10.0.0.1,, 10.0.0.2 ,")) == 2


@pytest.mark.parametrize("text", ["1.2.3.4; rm", "1.2.3.4;rm", "$(id)", "1.2.3.4|x", "1.2.3.4 ;rm", "1.2.3.4`id`"])
def test_parse_rejects_shell_chars(text):
    with pytest.raises(TargetError):
        parse_targets(text)


@pytest.mark.parametrize("text", ["-sS", "--script=x", "-1.2.3.4"])
def test_parse_rejects_option_like(text):
    with pytest.raises(TargetError):
        parse_targets(text)


@pytest.mark.parametrize("text", ["", "  ", ",,"])
def test_parse_rejects_empty(text):
    with pytest.raises(TargetError):
        parse_targets(text)


def test_private_range_ok():
    r = check_scope(parse_targets("192.168.1.0/24,10.1.0.0/16,fd00::1,169.254.1.1,127.0.0.1"))
    assert isinstance(r, ScopeCheck)
    assert r.allowed and not r.needs_confirmation and r.reasons == []


def test_public_range_needs_confirmation():
    r = check_scope(parse_targets("8.8.8.8"))
    assert r.allowed and r.needs_confirmation and r.reasons


def test_ipv4_wider_than_slash16_needs_confirmation():
    r = check_scope(parse_targets("10.0.0.0/8"))
    assert r.allowed and r.needs_confirmation and r.reasons


def test_ipv6_slash64_not_allowed():
    r = check_scope(parse_targets("fd00::/64"))
    assert not r.allowed and r.reasons


def test_ipv6_slash112_allowed():
    assert check_scope(parse_targets("fd00::/112")).allowed


@pytest.mark.parametrize("text", [
    "fe80::1%eth0", "fe80::1%$(id)", "fe80::1%-sS", "fe80::1%a;b",
    "10.0.0.0/255.0.0.0", "1.2.3.4/33",
])
def test_parse_rejects_zone_ids_netmasks_bad_prefix(text):
    with pytest.raises(TargetError):
        parse_targets(text)


def test_ipv4_prefix_boundaries():
    for t in ("10.0.0.0/16", "10.0.0.0/17"):
        assert not check_scope(parse_targets(t)).needs_confirmation
    assert check_scope(parse_targets("10.0.0.0/15")).needs_confirmation


def test_default_route_needs_confirmation():
    r = check_scope(parse_targets("0.0.0.0/0"))
    assert r.allowed and r.needs_confirmation


def test_mixed_private_and_public_needs_confirmation():
    r = check_scope(parse_targets("192.168.1.0/24,8.8.8.8"))
    assert r.allowed and r.needs_confirmation and r.reasons
