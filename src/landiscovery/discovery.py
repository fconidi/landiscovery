"""Scoperta di servizi di rete: mDNS (Avahi), UPnP/SSDP e SNMP.

Le stringhe ricevute dalla rete non sono attendibili: vengono ripulite dai
caratteri di controllo e ridotte a lunghezze massime.

La community SNMP non compare mai negli argomenti del processo, nei log o
nei messaggi di errore: viene scritta in una configurazione temporanea privata
(cartella 0700, file 0600) rimossa al termine, anche in caso di errore.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
from typing import Callable

from .models import DiscoveredService

MAX_NAME = 120
MAX_DETAIL = 200

SSDP_ADDR = ("239.255.255.250", 1900)
SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
COMMUNITY_RE = re.compile(r"[A-Za-z0-9_.@-]{1,64}")

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_ESCAPE_RE = re.compile(r"\\(\d{3})")

OID_SYSNAME = "1.3.6.1.2.1.1.5.0"
OID_SYSDESCR = "1.3.6.1.2.1.1.1.0"


class ToolMissing(Exception):
    """Lo strumento esterno richiesto non è installato."""


Runner = Callable[[list, float, "dict | None"], str]


def run_tool(argv: list[str], timeout: float, env: dict | None = None) -> str:
    """Esegue un comando senza shell e restituisce lo standard output."""
    full_env = {"PATH": SAFE_PATH, "LANG": "C", "LC_ALL": "C"}
    if env:
        full_env.update(env)
    try:
        proc = subprocess.run(
            argv, shell=False, capture_output=True, text=True,
            errors="replace", timeout=timeout, env=full_env, stdin=subprocess.DEVNULL,
        )
    except FileNotFoundError as exc:
        raise ToolMissing(argv[0]) from exc
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout or ""
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        return out
    return proc.stdout or ""


def _clean(text: str, limit: int) -> str:
    return _CONTROL_RE.sub("", text).strip()[:limit]


def _normalize_ip(value: str) -> str | None:
    value = value.split("%", 1)[0].strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _unescape_avahi(text: str) -> str:
    raw = bytearray()
    pos = 0
    for m in _ESCAPE_RE.finditer(text):
        raw += text[pos:m.start()].encode("utf-8")
        raw.append(int(m.group(1)) & 0xFF)
        pos = m.end()
    raw += text[pos:].encode("utf-8")
    return raw.decode("utf-8", "replace")


def parse_avahi(text: str) -> list[DiscoveredService]:
    """Interpreta l'output di ``avahi-browse -a -t -r -p`` (righe ``=``)."""
    out: list[DiscoveredService] = []
    seen = set()
    for line in text.splitlines():
        if not line.startswith("="):
            continue
        f = line.split(";", 9)
        if len(f) < 9:
            continue
        _, _iface, _proto, name, stype, _domain, host, addr, port = f[:9]
        ip = _normalize_ip(addr)
        if ip is None:
            continue
        name = _clean(_unescape_avahi(name), MAX_NAME)
        detail = _clean(f"{_unescape_avahi(stype)} {_unescape_avahi(host)}:{port}", MAX_DETAIL)
        key = (ip, name, detail)
        if key in seen:
            continue
        seen.add(key)
        out.append(DiscoveredService(ip=ip, kind="mdns", name=name, detail=detail))
    return out


def discover_mdns(runner: Runner | None = None, timeout: float = 5.0) -> list[DiscoveredService]:
    runner = runner or run_tool
    text = runner(["avahi-browse", "-a", "-t", "-r", "-p"], timeout, None)
    return parse_avahi(text)


def parse_ssdp_response(data: bytes, addr) -> DiscoveredService | None:
    """Interpreta una risposta SSDP; None se malformata."""
    try:
        ip = _normalize_ip(str(addr[0]))
        text = data.decode("utf-8", "replace")
    except (TypeError, IndexError, AttributeError):
        return None
    if ip is None:
        return None
    lines = text.split("\n")
    if not lines or not lines[0].strip().upper().startswith("HTTP/1.") or " 200" not in lines[0]:
        return None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers.setdefault(k.strip().lower(), v.strip())
    name = _clean(headers.get("server") or headers.get("usn") or "", MAX_NAME)
    if not name:
        return None
    detail = _clean(f"{headers.get('st', '')} {headers.get('location', '')}", MAX_DETAIL)
    return DiscoveredService(ip=ip, kind="ssdp", name=name, detail=detail)


def _make_ssdp_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    return sock


def discover_ssdp(timeout: float = 3.0, sock=None) -> list[DiscoveredService]:
    own = sock is None
    if own:
        sock = _make_ssdp_socket()
    request = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 2\r\n"
        "ST: ssdp:all\r\n\r\n"
    ).encode("ascii")
    found: list[DiscoveredService] = []
    seen = set()
    try:
        sock.sendto(request, SSDP_ADDR)
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                data, addr = sock.recvfrom(65535)
            except (socket.timeout, OSError):
                break
            svc = parse_ssdp_response(data, addr)
            if svc is None:
                continue
            key = (svc.ip, svc.name, svc.detail)
            if key not in seen:
                seen.add(key)
                found.append(svc)
    except OSError:
        pass
    finally:
        if own:
            sock.close()
    return found


def query_snmp(ip: str, community: str, runner: Runner | None = None) -> DiscoveredService | None:
    """Legge sysName e sysDescr via ``snmpget`` (SNMP v2c)."""
    try:
        ip_norm = str(ipaddress.ip_address(ip))
    except (ValueError, TypeError):
        raise ValueError("indirizzo IP non valido") from None
    if not isinstance(community, str) or not COMMUNITY_RE.fullmatch(community):
        raise ValueError("community SNMP non valida")
    runner = runner or run_tool
    confdir = tempfile.mkdtemp(prefix="landiscovery-snmp-")
    try:
        os.chmod(confdir, 0o700)
        fd = os.open(os.path.join(confdir, "snmp.conf"),
                     os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(f"defVersion 2c\ndefCommunity {community}\n")
        env = {"SNMPCONFPATH": confdir, "SNMP_PERSISTENT_DIR": confdir}
        argv = ["snmpget", "-r1", "-t2", "-Oqv", ip_norm, OID_SYSNAME, OID_SYSDESCR]
        output = runner(argv, 8.0, env)
    finally:
        shutil.rmtree(confdir, ignore_errors=True)
    lines = [ln.strip() for ln in (output or "").splitlines()]
    lines = [ln for ln in lines if ln]
    if not lines:
        return None
    if any(ln.startswith(("Timeout", "No Response", "snmpget:")) or "No Response" in ln
           for ln in lines):
        return None
    name = _clean(lines[0], MAX_NAME)
    detail = _clean(lines[1], MAX_DETAIL) if len(lines) > 1 else ""
    return DiscoveredService(ip=ip_norm, kind="snmp", name=name, detail=detail)
