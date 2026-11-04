"""Controlli di sicurezza passivi: output degli script NSE -> Finding."""
from __future__ import annotations

import datetime as dt
import ipaddress
import re
import unicodedata
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Callable

from .models import Finding
from .nmapxml import ScanParseError, reject_entities

MAX_TITLE = 120
MAX_DETAIL = 300
# Prima di qualsiasi espressione regolare l'output viene troncato a questa lunghezza.
MAX_RAW = 20000
MAX_ELEMS = 200

# Titoli (costanti inglesi): la chiave è l'identificativo della regola,
# il valore è il testo che la GUI traduce.
TITLES: dict[str, str] = {
    "telnet_open": "Telnet service is open",
    "telnet_no_encryption": "Telnet server does not support encryption",
    "ftp_anon": "Anonymous FTP login allowed",
    "smb1_enabled": "SMBv1 is enabled",
    "smb_signing": "SMB message signing is not required",
    "smb_guest": "SMB accepts guest sessions",
    "http_risky_methods": "Risky HTTP methods enabled",
    "ssh_weak_algos": "Weak SSH algorithms offered",
    "cert_expired": "TLS certificate expired",
    "rdp_no_nla": "RDP does not require Network Level Authentication",
    "banner": "Service banner",
    "http_title": "HTTP page title",
    "http_server": "HTTP server header",
    "cert_info": "TLS certificate",
    "ssh_hostkeys": "SSH host keys",
    "snmp_info": "SNMP information",
    "upnp_info": "UPnP information",
    "nbstat": "NetBIOS information",
}


@dataclass(frozen=True)
class Ctx:
    """Dati di uno script (già sanificati e limitati) visti da una regola."""
    text: str                 # output su più righe
    elems: dict[str, str]     # elementi <elem key=...> appiattiti
    port: int | None
    service: str
    now: dt.datetime


@dataclass(frozen=True)
class Rule:
    key: str                              # chiave di TITLES
    script: str | None                    # None = regola sulla porta, senza script
    severity: str
    match: Callable[[Ctx], str | None]    # None = nessun riscontro, altrimenti la prova
    detail: str = ""                      # frase fissa, prima della prova

    @property
    def title(self) -> str:
        return TITLES[self.key]


# ---------------------------------------------------------------- sanificazione

def _clean(value, keep_newlines: bool = False) -> str:
    out = []
    for ch in str(value):
        if ch in "\n\r\t":
            out.append("\n" if keep_newlines and ch != "\t" else " ")
            continue
        cat = unicodedata.category(ch)
        if cat[0] == "C" or cat in ("Zl", "Zp"):
            continue
        out.append(ch)
    text = "".join(out)
    if keep_newlines:
        return "\n".join(" ".join(line.split()) for line in text.split("\n"))
    return " ".join(text.split())


def _cap(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


# ------------------------------------------------------------------- predicati

def _telnet_open(c: Ctx) -> str | None:
    if c.service.lower() == "telnet" or c.port == 23:
        return ""
    return None


def _contains(*needles: str) -> Callable[[Ctx], str | None]:
    low = tuple(n.lower() for n in needles)

    def match(c: Ctx) -> str | None:
        t = c.text.lower()
        return "" if any(n in t for n in low) else None
    return match


def _smb1(c: Ctx) -> str | None:
    for line in c.text.split("\n"):
        line = line.strip()
        if re.match(r"NT LM 0\.12(?:[ \t]+\(SMBv1\))?(?:[ \t]|$)", line):
            return ""
        if re.match(r"(?:\d+(?:\.\d+)*[ \t]+)?\(SMBv1\)(?:[ \t]|$)", line):
            return ""
    return None


def _smb_signing(c: Ctx) -> str | None:
    value = c.elems.get("message_signing")
    if value is None:
        m = re.search(r"message_signing:[ \t]*([^\n]{0,60})", c.text)
        value = m.group(1) if m else None
    if value is not None:
        v = value.strip().lower()
        if v.startswith("disabled") or v.startswith("supported") or "not required" in v:
            return "message_signing: " + _cap(v, 40)
        return None
    # smb2-security-mode: "Message signing enabled but not required"
    low = c.text.lower()
    if "signing" in low and "not required" in low:
        return "message signing enabled but not required"
    return None


def _smb_guest(c: Ctx) -> str | None:
    value = c.elems.get("account_used")
    if value is None:
        m = re.search(r"account_used:[ \t]*([^\n]{0,40})", c.text)
        value = m.group(1) if m else ""
    return "account_used: guest" if value.strip().lower() == "guest" else None


_RISKY = ("TRACE", "PUT", "DELETE")


def _http_risky(c: Ctx) -> str | None:
    m = re.search(r"Potentially risky methods:[ \t]*([^\n]{0,200})", c.text)
    if not m:
        return None
    words = [w for w in re.findall(r"[A-Z][A-Z-]{1,14}", m.group(1))]
    if not words:
        return None
    risky = [w for w in words if w in _RISKY] or words
    return " ".join(dict.fromkeys(risky))


_WEAK_SSH = re.compile(
    r"(?<![\w-])(diffie-hellman-group1-sha1|arcfour[\w-]*|3des-cbc|blowfish-cbc|cast128-cbc|diffie-hellman-group-exchange-sha1|hmac-md5[\w-]*|ssh-dss)(?![\w-])",
    re.IGNORECASE)


def _ssh_weak(c: Ctx) -> str | None:
    found = dict.fromkeys(m.group(1).lower() for m in _WEAK_SSH.finditer(c.text))
    return ", ".join(sorted(found)) if found else None


def _parse_date(value: str) -> dt.datetime | None:
    value = value.strip()
    if not value or len(value) > 40:
        return None
    try:
        d = dt.datetime.fromisoformat(value.replace(" ", "T", 1))
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=dt.timezone.utc)
    return d


def _cert_expired(c: Ctx) -> str | None:
    raw = c.elems.get("notAfter")
    d = _parse_date(raw) if raw is not None else None
    if d is None:
        m = re.search(r"Not valid after:[ \t]*([^\n]{0,40})", c.text)
        raw = m.group(1) if m else ""
        d = _parse_date(raw)
    if d is None or d >= c.now:
        return None
    return "not valid after " + _cap(raw.strip(), 40)


_RDP_LAYER = re.compile(
    r"(?m)^[ \t]*(Native RDP|RDP Security Layer|SSL|RDSTLS)[ \t]*:?[ \t]*SUCCESS", re.IGNORECASE)
_RDP_NLA = re.compile(r"(?m)^[ \t]*CredSSP[ \t]*\(NLA\)[ \t]*:[ \t]*([A-Za-z]+)")


def _rdp(c: Ctx) -> str | None:
    t = c.text
    layer = _RDP_LAYER.search(t)
    if layer:
        return layer.group(1) + " accepted without NLA"
    nla = _RDP_NLA.search(t)
    if nla and nla.group(1).upper() != "SUCCESS":
        return "CredSSP (NLA) not supported"
    return None


def _whole_text(c: Ctx) -> str | None:
    return c.text.replace("\n", " | ").strip(" |") or None


def _cert_summary(c: Ctx) -> str | None:
    parts = []
    for label in ("Subject", "Issuer"):
        m = re.search(r"(?m)^" + label + r":[ \t]*([^\n]{0,200})", c.text)
        if m:
            parts.append(label + ": " + m.group(1).strip())
    return " | ".join(parts) or _whole_text(c)


def _hostkeys(c: Ctx) -> str | None:
    keys = [f"{m.group(2)} {m.group(1)}" for m in
            re.finditer(r"(?m)^[ \t]*(\d{2,5})[ \t]+\S+[ \t]+\(([A-Za-z0-9-]{1,20})\)", c.text)]
    if keys:
        return ", ".join(dict.fromkeys(keys))
    return _whole_text(c)


# ---------------------------------------------------------------------- regole

RULES: tuple[Rule, ...] = (
    # critical
    Rule("smb1_enabled", "smb-protocols", "critical", _smb1,
         "The SMBv1 protocol is offered; it is obsolete and exploitable."),
    # warning
    Rule("telnet_open", None, "warning", _telnet_open,
         "Telnet sends data, including passwords, in clear text."),
    Rule("telnet_no_encryption", "telnet-encryption", "warning",
         _contains("does not support encryption"),
         "Telnet traffic can be read by anyone on the network."),
    Rule("ftp_anon", "ftp-anon", "warning", _contains("Anonymous FTP login allowed"),
         "Anyone can log in to the FTP server without credentials."),
    Rule("smb_signing", "smb-security-mode", "warning", _smb_signing,
         "SMB sessions can be tampered with or relayed."),
    Rule("smb_signing", "smb2-security-mode", "warning", _smb_signing,
         "SMB sessions can be tampered with or relayed."),
    Rule("smb_guest", "smb-security-mode", "warning", _smb_guest,
         "The SMB server maps unknown users to a guest account."),
    Rule("http_risky_methods", "http-methods", "warning", _http_risky,
         "The web server allows methods that can expose or modify content:"),
    Rule("ssh_weak_algos", "ssh2-enum-algos", "warning", _ssh_weak,
         "The SSH server offers outdated algorithms:"),
    Rule("cert_expired", "ssl-cert", "warning", _cert_expired,
         "The certificate is no longer valid:"),
    Rule("rdp_no_nla", "rdp-enum-encryption", "warning", _rdp,
         "Remote Desktop accepts connections without Network Level Authentication:"),
    # info
    Rule("banner", "banner", "info", _whole_text),
    Rule("http_title", "http-title", "info", _whole_text),
    Rule("http_server", "http-server-header", "info", _whole_text),
    Rule("cert_info", "ssl-cert", "info", _cert_summary),
    Rule("ssh_hostkeys", "ssh-hostkey", "info", _hostkeys),
    Rule("snmp_info", "snmp-info", "info", _whole_text),
    Rule("upnp_info", "upnp-info", "info", _whole_text),
    Rule("nbstat", "nbstat", "info", _whole_text),
)

_SCRIPT_RULES: dict[str, tuple[Rule, ...]] = {}
for _r in RULES:
    if _r.script:
        _SCRIPT_RULES[_r.script] = _SCRIPT_RULES.get(_r.script, ()) + (_r,)
_PORT_RULES = tuple(r for r in RULES if r.script is None)

_RANK = {"critical": 0, "warning": 1, "info": 2}


# ---------------------------------------------------------------------- lettura

def _flat_elems(script: ET.Element) -> dict[str, str]:
    out: dict[str, str] = {}
    for el in script.iter("elem"):
        if len(out) >= MAX_ELEMS:
            break
        key = el.get("key")
        if key and key not in out:
            out[key] = _cap(_clean((el.text or "")[:400]), 200)
    return out


def _address(host: ET.Element) -> str | None:
    v4 = v6 = None
    for a in host.findall("address"):
        kind, addr = a.get("addrtype"), (a.get("addr") or "").strip()
        if not addr:
            continue
        if kind == "ipv4" and v4 is None:
            v4 = addr
        elif kind == "ipv6" and v6 is None:
            v6 = addr
    return v4 or v6


def _host_key(host: str) -> tuple:
    try:
        ip = ipaddress.ip_address(host.split("%", 1)[0])
        return (ip.version, int(ip), host)
    except ValueError:
        return (9, 0, host)


def _make(rule: Rule, evidence: str, label: str) -> Finding:
    detail = rule.detail
    if evidence:
        evidence = _clean(evidence)
        detail = detail + (" " if detail else "") + evidence
    if label:
        detail = label + ": " + detail if detail else label
    return Finding("", rule.severity, _cap(rule.title, MAX_TITLE), _cap(detail, MAX_DETAIL))


def parse_nse_findings(xml_text: str, *, now: dt.datetime | None = None) -> list[Finding]:
    if not xml_text or not xml_text.strip():
        raise ScanParseError("output nmap vuoto")
    reject_entities(xml_text)
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ScanParseError(f"XML nmap non valido o troncato: {exc}") from exc
    if root.tag != "nmaprun":
        raise ScanParseError("XML non prodotto da nmap")
    if now is None:
        now = dt.datetime.now(dt.timezone.utc)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=dt.timezone.utc)

    found: list[tuple[tuple, Finding]] = []
    seen: set[tuple] = set()
    seq = 0

    def emit(host: str, port: int | None, finding: Finding) -> None:
        nonlocal seq
        finding.host = host
        ident = (host, finding.severity, finding.title, finding.detail)
        if ident in seen:
            return
        seen.add(ident)
        seq += 1
        key = (_RANK[finding.severity], _host_key(host),
               -1 if port is None else port, seq)
        found.append((key, finding))

    def run(host: str, rule: Rule, ctx: Ctx, label: str) -> None:
        try:
            evidence = rule.match(ctx)
        except Exception:  # un'anomalia nei dati non deve fermare l'analisi
            return
        if evidence is not None:
            emit(host, ctx.port, _make(rule, evidence, label))

    def scripts_of(parent: ET.Element, host: str, port: int | None,
                   service: str, label: str) -> None:
        for sc in parent.findall("script"):
            rules = _SCRIPT_RULES.get(sc.get("id") or "")
            if not rules:
                continue
            text = _clean(_cap_raw(sc.get("output") or ""), keep_newlines=True)
            ctx = Ctx(text, _flat_elems(sc), port, service, now)
            for rule in rules:
                run(host, rule, ctx, label)

    for h in root.findall("host"):
        host = _address(h)
        if not host:
            continue
        for p in h.findall("ports/port"):
            state = p.find("state")
            if state is not None and not (state.get("state") or "open").startswith("open"):
                continue
            try:
                port = int(p.get("portid", ""))
            except ValueError:
                port = None
            if port is not None and not 0 < port < 65536:
                port = None
            proto = _clean(p.get("protocol") or "tcp")[:10]
            label = "" if port is None else f"{port}/{proto}"
            svc = p.find("service")
            service = _clean(svc.get("name") or "")[:40] if svc is not None else ""
            ctx = Ctx("", {}, port, service, now)
            for rule in _PORT_RULES:
                run(host, rule, ctx, label)
            scripts_of(p, host, port, service, label)
        hs = h.find("hostscript")
        if hs is not None:
            scripts_of(hs, host, None, "", "")

    found.sort(key=lambda kv: kv[0])
    return [f for _, f in found]


def _cap_raw(text: str) -> str:
    return text[:MAX_RAW]
