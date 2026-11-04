"""Lettura dell'output XML di nmap (-oX)."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from .models import Host, Port


class ScanParseError(Exception):
    """XML di nmap vuoto, troncato o non valido."""


def reject_entities(text: str) -> None:
    """Rifiuta dichiarazioni di entità o sottoinsiemi DTD (nmap non ne produce)."""
    head = text[:4096] if len(text) > 4096 else text
    low = text.lower()
    if "<!entity" in low:
        raise ScanParseError("XML con dichiarazioni di entità non ammesso")
    i = head.lower().find("<!doctype")
    if i >= 0:
        end = head.find(">", i)
        if end < 0 or "[" in head[i:end]:
            raise ScanParseError("XML con sottoinsieme DTD non ammesso")


def _port(el: ET.Element) -> Port | None:
    try:
        number = int(el.get("portid", ""))
    except ValueError:
        return None
    state = el.find("state")
    svc = el.find("service")
    version = ""
    name = ""
    if svc is not None:
        name = svc.get("name", "")
        version = " ".join(
            v for v in (svc.get("product"), svc.get("version")) if v
        )
    return Port(
        number=number,
        proto=el.get("protocol", "tcp"),
        state=state.get("state", "open") if state is not None else "open",
        service=name,
        version=version,
    )


def _host(el: ET.Element) -> Host | None:
    status = el.find("status")
    if status is None or status.get("state") != "up":
        return None
    ip = mac = None
    vendor = ""
    for addr in el.findall("address"):
        kind = addr.get("addrtype")
        if kind in ("ipv4", "ipv6") and ip is None:
            ip = addr.get("addr")
        elif kind == "mac":
            mac = (addr.get("addr") or "").upper() or None
            vendor = addr.get("vendor", "")
    if not ip:
        return None
    hostname = ""
    hn = el.find("hostnames/hostname")
    if hn is not None:
        hostname = hn.get("name", "")
    latency = None
    times = el.find("times")
    if times is not None and times.get("srtt"):
        try:
            latency = int(times.get("srtt")) / 1000.0
        except ValueError:
            pass
    os_name = ""
    match = el.find("os/osmatch")
    if match is not None:
        os_name = match.get("name", "")
    ports = [p for p in map(_port, el.findall("ports/port")) if p]
    return Host(ip=ip, mac=mac, vendor=vendor, hostname=hostname,
                latency_ms=latency, os=os_name, ports=ports)


def parse_nmap_xml(text: str) -> list[Host]:
    if not text or not text.strip():
        raise ScanParseError("output nmap vuoto")
    reject_entities(text)
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ScanParseError(f"XML nmap non valido o troncato: {exc}") from exc
    if root.tag != "nmaprun":
        raise ScanParseError("XML non prodotto da nmap")
    return [h for h in map(_host, root.findall("host")) if h]
