import pytest

from landiscovery.models import Finding, Host


def test_host_key_prefers_mac():
    h = Host(ip="192.168.1.10", mac="aa:bb:cc:dd:ee:ff")
    assert h.key == "aa:bb:cc:dd:ee:ff"


def test_host_key_falls_back_to_ip():
    h = Host(ip="192.168.1.10", mac=None)
    assert h.key == "192.168.1.10"


def test_finding_rejects_unknown_severity():
    with pytest.raises(ValueError):
        Finding(host="192.168.1.10", severity="fatal", title="t", detail="d")
