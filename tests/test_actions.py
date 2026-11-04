import pytest

from landiscovery.actions import build_action, wake_on_lan
from landiscovery.models import Host, Port


def test_ssh_command_list():
    assert build_action("ssh", Host("192.168.1.2")) == [
        "x-terminal-emulator", "-e", "ssh", "192.168.1.2"]


def test_browser_url_uses_open_http_port():
    host = Host("192.168.1.2", ports=[Port(80)])
    assert build_action("browser", host) == ["xdg-open", "http://192.168.1.2"]


def test_wol_packet_format(monkeypatch):
    sent = []
    class Socket:
        def __enter__(self): return self
        def __exit__(self, *_): return None
        def setsockopt(self, *_): pass
        def sendto(self, packet, target): sent.append((packet, target))
    monkeypatch.setattr("landiscovery.actions.socket.socket", lambda *_: Socket())
    wake_on_lan("AA:BB:CC:DD:EE:FF")
    assert sent == [(b"\xff" * 6 + bytes.fromhex("AABBCCDDEEFF") * 16,
                     ("255.255.255.255", 9))]


def test_wol_rejects_invalid_mac():
    with pytest.raises(ValueError):
        wake_on_lan("AA:BB:CC:DD:EE:FF;reboot")


def test_hostname_with_spaces_not_injected():
    host = Host("192.168.1.2", hostname="bad name;reboot")
    assert "bad name;reboot" not in " ".join(build_action("ssh", host))
    with pytest.raises(ValueError):
        build_action("ssh", Host("192.168.1.2;reboot"))
