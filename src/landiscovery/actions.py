"""Validated host actions launched without a shell."""
from __future__ import annotations

import ipaddress
import re
import socket

from .models import Host

_MAC = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def build_action(kind: str, host: Host) -> list[str]:
    ip = str(ipaddress.ip_address(host.ip))
    if kind == "ssh":
        return ["x-terminal-emulator", "-e", "ssh", ip]
    if kind == "rdp":
        return ["xfreerdp", f"/v:{ip}"]
    if kind == "browser":
        https = any(p.number == 443 and p.state == "open" for p in host.ports)
        http = any(p.number == 80 and p.state == "open" for p in host.ports)
        if not (https or http):
            raise ValueError("no HTTP or HTTPS port is open")
        bracketed = f"[{ip}]" if ":" in ip else ip
        return ["xdg-open", f"{'https' if https else 'http'}://{bracketed}"]
    if kind == "ping":
        return ["x-terminal-emulator", "-e", "ping", "-c", "4", ip]
    if kind == "traceroute":
        return ["x-terminal-emulator", "-e", "traceroute", ip]
    raise ValueError(f"unknown action: {kind}")


def wake_on_lan(mac: str) -> None:
    if not isinstance(mac, str) or not _MAC.fullmatch(mac):
        raise ValueError("invalid MAC address")
    octets = bytes.fromhex(mac.replace(":", ""))
    packet = b"\xff" * 6 + octets * 16
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(packet, ("255.255.255.255", 9))


def copy_value(value: str) -> str:
    """Return plain text for the UI clipboard, without markup or escaping."""
    return str(value)
