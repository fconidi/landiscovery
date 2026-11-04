"""Motore di scansione: scoperta host, porte/servizi e rilevamento OS.

``ScanEngine.scan`` è sincrono e gira nel thread del chiamante (un'interfaccia
grafica lo esegue in un thread di lavoro). ``cancel`` può essere chiamato da
un altro thread: ferma il passo in corso e la scansione restituisce un
risultato con stato ``cancelled`` e i dati raccolti fino a quel momento.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import shutil
import socket
import struct
import threading
import time
from dataclasses import dataclass

from . import discovery
from .discovery import DiscoveredService, ToolMissing
from .helper import MAX_TARGETS, NSE_ALLOWED, HelperError
from .models import Coverage, Host, ScanResult
from .nmapxml import ScanParseError, parse_nmap_xml
from .oui import OuiDatabase
from .profiles import Profile
from .runner import HelperRunner, ScanCancelled
from .security import parse_nse_findings
from .topology import build_topology, parse_traceroute

MAX_SERVICES_PER_HOST = 20
MAX_SNMP_HOSTS = 256

log = logging.getLogger(__name__)


class EngineError(Exception):
    """La scansione non può nemmeno partire (per esempio nmap manca)."""


@dataclass
class ScanOptions:
    snmp_community: str | None = None


def parse_arp_scan(text: str) -> dict[str, tuple[str, str]]:
    """Legge l'output di arp-scan: righe ``IP<TAB>MAC<TAB>produttore``.

    Restituisce ``{MAC maiuscolo: (ip, produttore)}``. Intestazione, riepilogo
    e righe non riconoscibili sono ignorati; l'annotazione ``(DUP: n)`` dei
    duplicati viene rimossa e il produttore ``(Unknown...)`` diventa vuoto.
    """
    result: dict[str, tuple[str, str]] = {}
    for line in (text or "").splitlines():
        parts = line.rstrip("\r\n").split("\t")
        if len(parts) < 2:
            continue
        ip, mac = parts[0].strip(), parts[1].strip().upper()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        if len(mac.split(":")) != 6:
            continue
        vendor = parts[2].strip() if len(parts) > 2 else ""
        if vendor.startswith("(Unknown"):
            vendor = ""
        if "(DUP:" in vendor:
            vendor = vendor.split("(DUP:")[0].strip()
        result.setdefault(mac, (ip, vendor))
    return result


def _ip_key(ip: str):
    try:
        addr = ipaddress.ip_address(ip)
        return (addr.version, int(addr))
    except ValueError:
        return (9, 0)


def _missing_tool(exc: HelperError) -> bool:
    return getattr(exc, "returncode", None) == 127 or str(exc).startswith("cannot run")


def _norm_ip(ip: str) -> str:
    """Indirizzo normalizzato, senza zona; il testo originale se non valido."""
    try:
        return str(ipaddress.ip_address(str(ip).split("%", 1)[0]))
    except ValueError:
        return str(ip)


def read_default_gateway(path: str = "/proc/net/route") -> str | None:
    """Gateway IPv4 predefinito dalla tabella di routing; None se illeggibile."""
    try:
        with open(path, encoding="ascii", errors="replace") as fh:
            lines = fh.read().splitlines()[1:]
    except OSError:
        return None
    best = None
    for line in lines:
        cols = line.split()
        try:
            if len(cols) < 7 or int(cols[1], 16) != 0:
                continue
            flags, metric = int(cols[3], 16), int(cols[6])
            gw = int(cols[2], 16)
        except ValueError:
            continue
        if not flags & 2 or gw == 0:  # RTF_GATEWAY
            continue
        if best is None or metric < best[0]:
            best = (metric, gw)
    if best is None:
        return None
    return socket.inet_ntoa(struct.pack("<L", best[1]))


class DefaultTools:
    """Strumenti di scoperta reali (avahi, SSDP, snmpget, tabella di routing)."""

    def mdns(self) -> list[DiscoveredService]:
        return discovery.discover_mdns()

    def ssdp(self) -> list[DiscoveredService]:
        return discovery.discover_ssdp()

    def snmp(self, ip: str, community: str) -> DiscoveredService | None:
        return discovery.query_snmp(ip, community)

    def gateway(self) -> str | None:
        return read_default_gateway()


class _Cancelled(Exception):
    pass


class ScanEngine:
    def __init__(self, runner=None, oui=None, privileged: bool | None = None,
                 tools=None):
        if privileged is None:
            privileged = os.geteuid() == 0 or shutil.which("pkexec") is not None
        self.privileged = bool(privileged)
        if runner is None:
            runner = HelperRunner(direct=not self.privileged)
        self.runner = runner
        self._oui = oui
        self.tools = tools if tools is not None else DefaultTools()
        self._cancel = threading.Event()
        self._lock = threading.Lock()

    @property
    def oui(self) -> OuiDatabase:
        if self._oui is None:
            self._oui = OuiDatabase()
        return self._oui

    def cancel(self) -> None:
        """Annulla la scansione in corso; si può chiamare da un altro thread."""
        self._cancel.set()
        self.runner.cancel()

    # --- scansione -------------------------------------------------------------

    def scan(self, targets: list, profile: Profile, options: ScanOptions | None = None,
             on_progress=None) -> ScanResult:
        """Esegue la scansione e restituisce il risultato.

        Un passo fallito non interrompe la scansione: lo stato resta ``done``
        con ``complete=False`` e un avviso in ``warnings``. Lo stato è
        ``failed`` solo se nessun passo è riuscito. ``coverage`` descrive ciò
        che è stato davvero eseguito con successo.
        """
        if not self._lock.acquire(blocking=False):
            raise EngineError("scan already running")
        try:
            self._cancel.clear()
            self.runner.reset()
            return self._scan(targets, profile, options or ScanOptions(), on_progress)
        finally:
            self._lock.release()

    def _scan(self, targets, profile, options, on_progress) -> ScanResult:
        target_strs = [str(t) for t in targets]
        priv = self.privileged
        do_ports = profile.ports != ""
        do_os = profile.os_detect and priv
        result = ScanResult(
            started=time.time(), targets=target_strs, profile=profile.name,
            status="running", reduced=not priv)
        result.coverage = Coverage(
            targets=target_strs, profile=profile.name, ports="",
            privileged=priv, os_detect=False, service_detect=False,
            traceroute=False, mdns=False, ssdp=False, snmp=False,
            security_checks=False)
        if profile.os_detect and not priv:
            result.warnings.append(
                "OS detection needs privileges and was skipped (reduced mode)")

        do_trace = profile.traceroute and priv
        if profile.traceroute and not priv:
            result.warnings.append(
                "traceroute needs privileges and was skipped (reduced mode)")
        community = options.snmp_community or None
        do_snmp = profile.snmp and community is not None
        if profile.snmp and not do_snmp:
            result.warnings.append("snmp community not provided")
            incomplete = True
        else:
            incomplete = False
        steps = (["discovery"] + (["ports"] if do_ports else [])
                 + (["os"] if do_os else []) + (["traceroute"] if do_trace else [])
                 + (["security"] if profile.security_checks else [])
                 + (["mdns"] if profile.mdns else []) + (["ssdp"] if profile.ssdp else [])
                 + (["snmp"] if do_snmp else []))
        state = _State(result, steps, on_progress)
        if incomplete:
            state.failures += 1
        hosts: dict[str, Host] = {}
        hops: dict[str, list[str]] = {}
        try:
            self._discovery(state, hosts, target_strs, priv)
            ips = sorted(hosts, key=_ip_key)
            if do_ports:
                self._ports(state, hosts, ips, profile)
            if do_os:
                self._os(state, hosts, ips)
            if do_trace:
                self._traceroute(state, ips, hops)
            if profile.security_checks:
                self._security(state, hosts, ips, profile)
            if profile.mdns:
                self._discover(state, hosts, "mdns", self.tools.mdns)
            if profile.ssdp:
                self._discover(state, hosts, "ssdp", self.tools.ssdp)
            if do_snmp:
                self._snmp(state, hosts, ips, community)
            result.status = "done"
        except _Cancelled:
            result.status = "cancelled"
        except ScanCancelled:
            result.status = "cancelled"
        if self._cancel.is_set():
            result.status = "cancelled"

        result.hosts = self._finish_hosts(hosts, priv)
        result.topology = self._topology(result.hosts, hops)
        if result.status == "done" and state.failures and not state.successes:
            result.status = "failed"
        result.complete = result.status == "done" and state.failures == 0
        result.finished = time.time()
        return result

    def _finish_hosts(self, hosts: dict[str, Host], priv: bool) -> list[Host]:
        out = []
        for ip in sorted(hosts, key=_ip_key):
            host = hosts[ip]
            if not priv:
                host.mac, host.vendor, host.os = None, "", ""
            elif host.mac and not host.vendor:
                host.vendor = self.oui.lookup(host.mac)
            out.append(host)
        return out

    def _call(self, state, step: str, op: str, params: dict) -> str | None:
        """Esegue un'operazione; su errore registra un avviso e restituisce None."""
        if self._cancel.is_set():
            raise _Cancelled()
        try:
            return self.runner.run(op, params)
        except ScanCancelled:
            raise
        except HelperError as exc:
            state.fail(f"{step}: {exc}")
            state.last_error = exc
            return None

    @staticmethod
    def _merge(hosts: dict[str, Host], new: Host, fields: tuple[str, ...]) -> None:
        cur = hosts.get(new.ip)
        if cur is None:
            hosts[new.ip] = new
            return
        for name in fields:
            value = getattr(new, name)
            if value not in (None, "", []):
                setattr(cur, name, value)

    def _discovery(self, state, hosts, targets, priv) -> None:
        state.start("discovery")
        v4 = not targets or all(":" not in t for t in targets)
        if priv and v4:
            text = self._call(state, "arp discovery", "arp_discover", {"targets": targets})
            if text is not None:
                try:
                    for mac, (ip, vendor) in parse_arp_scan(text).items():
                        known = hosts.get(ip)
                        if known is not None and known.mac and known.mac != mac:
                            state.result.warnings.append(
                                f"arp discovery: {ip} answered from more than one "
                                f"MAC ({known.mac}, {mac}); keeping the first")
                            continue
                        self._merge(hosts, Host(ip=ip, mac=mac, vendor=vendor),
                                    ("mac", "vendor"))
                    state.ok()
                except Exception as exc:  # pragma: no cover - parser è tollerante
                    state.fail(f"arp discovery: {exc}")
        if targets:
            text = self._call(state, "host discovery", "port_scan",
                              {"targets": targets, "ports": "", "service": False})
            if text is None:
                err = state.last_error
                if err is not None and _missing_tool(err) and not hosts and not state.successes:
                    raise EngineError(self._missing_message(err))
            else:
                self._absorb(state, "host discovery", text, hosts,
                             ("hostname", "latency_ms", "mac", "vendor"))
        state.end()

    @staticmethod
    def _missing_message(err: HelperError) -> str:
        text = str(err)
        if "nmap" in text:
            return f"nmap is not available: {text}"
        return f"scan cannot start: {text}"

    def _absorb(self, state, step, text, hosts, fields) -> None:
        try:
            parsed = parse_nmap_xml(text)
        except ScanParseError as exc:
            state.fail(f"{step}: {exc}")
            return
        for h in parsed:
            self._merge(hosts, h, fields)
        state.ok()

    def _chunks(self, ips: list[str]):
        for version in (4, 6):
            group = [ip for ip in ips if _ip_key(ip)[0] == version]
            for i in range(0, len(group), MAX_TARGETS):
                yield group[i:i + MAX_TARGETS]

    def _ports(self, state, hosts, ips, profile) -> None:
        state.start("ports")
        before = state.failures
        for chunk in self._chunks(ips):
            text = self._call(state, "port scan", "port_scan",
                              {"targets": chunk, "ports": profile.ports,
                               "service": profile.service_detect})
            if text is not None:
                self._absorb(state, "port scan", text, hosts,
                             ("ports", "hostname", "latency_ms", "mac", "vendor"))
        if state.failures == before and not self._cancel.is_set():
            cov = state.result.coverage
            cov.ports, cov.service_detect = profile.ports, profile.service_detect
        state.end()

    def _os(self, state, hosts, ips) -> None:
        state.start("os")
        before = state.failures
        for chunk in self._chunks(ips):
            text = self._call(state, "os detection", "os_detect", {"targets": chunk})
            if text is not None:
                self._absorb(state, "os detection", text, hosts, ("os",))
        if state.failures == before and not self._cancel.is_set():
            state.result.coverage.os_detect = True
        state.end()


    # --- passi opzionali ---------------------------------------------------------

    def _topology(self, hosts: list[Host], hops: dict[str, list[str]]):
        """Topologia dedotta; senza traceroute è la stella attorno al gateway.

        Senza host restituisce una topologia con il solo gateway.
        """
        try:
            gateway = self.tools.gateway()
        except Exception:
            log.debug("default gateway lookup failed", exc_info=True)
            gateway = None
        return build_topology(hosts, hops, gateway)

    def _traceroute(self, state, ips, hops) -> None:
        if not ips:
            return
        state.start("traceroute")
        before = state.failures
        for chunk in self._chunks(ips):
            text = self._call(state, "traceroute", "traceroute", {"targets": chunk})
            if text is None:
                continue
            try:
                hops.update(parse_traceroute(text))
            except Exception as exc:
                state.fail(f"traceroute: {exc}")
        if state.failures == before and not self._cancel.is_set():
            state.result.coverage.traceroute = True
        state.end()

    def _security(self, state, hosts, ips, profile) -> None:
        if not ips:
            return
        state.start("security")
        before = state.failures
        ports = profile.ports or "top100"
        by_ip = {_norm_ip(ip): h for ip, h in hosts.items()}
        for chunk in self._chunks(ips):
            text = self._call(state, "security checks", "nse_safe",
                              {"targets": chunk, "ports": ports,
                               "scripts": list(NSE_ALLOWED)})
            if text is None:
                continue
            try:
                findings = parse_nse_findings(text)
            except Exception as exc:
                state.fail(f"security checks: {exc}")
                continue
            for finding in findings:
                host = by_ip.get(_norm_ip(finding.host))
                if host is not None:
                    host.findings.append(finding)
        if state.failures == before and not self._cancel.is_set():
            state.result.coverage.security_checks = True
        state.end()

    def _run_tool(self, state, step: str, func, *args):
        """Esegue una funzione di scoperta; (ok, valore). Gli errori diventano avvisi."""
        if self._cancel.is_set():
            raise _Cancelled()
        try:
            value = func(*args)
        except ToolMissing as exc:
            state.fail(f"{exc or step} not installed")
            return False, None
        except Exception as exc:
            state.fail(f"{step}: {exc}" if str(exc) else f"{step}: {type(exc).__name__}")
            return False, None
        if self._cancel.is_set():
            raise _Cancelled()
        return True, value

    @staticmethod
    def _attach(state, hosts, found) -> None:
        by_ip = {_norm_ip(ip): h for ip, h in hosts.items()}
        state.result.discovered.extend(found)
        for item in found:
            host = by_ip.get(_norm_ip(item.ip))
            if host is None:
                continue
            label = f"{item.kind}:{item.name}"
            if label not in host.services and len(host.services) < MAX_SERVICES_PER_HOST:
                host.services.append(label)

    def _discover(self, state, hosts, kind: str, func) -> None:
        state.start(kind)
        ok, found = self._run_tool(state, kind, func)
        if ok:
            self._attach(state, hosts, found or [])
            setattr(state.result.coverage, kind, True)
        state.end()

    def _snmp(self, state, hosts, ips, community) -> None:
        if not ips:
            return
        state.start("snmp")
        targets = ips[:MAX_SNMP_HOSTS]
        complete = True
        if len(ips) > len(targets):
            state.fail(f"snmp: only the first {MAX_SNMP_HOSTS} hosts were queried")
            complete = False
        for ip in targets:
            if self._cancel.is_set():
                raise _Cancelled()
            try:
                found = self.tools.snmp(ip, community)
            except ValueError:
                # Messaggio fisso: la community non compare mai in avvisi o log.
                state.fail("snmp: invalid community or address, step aborted")
                complete = False
                break
            except Exception as exc:
                state.fail(f"snmp: {type(exc).__name__}, step aborted")
                complete = False
                break
            if self._cancel.is_set():
                raise _Cancelled()
            if found is not None:
                self._attach(state, hosts, [found])
        if complete:
            state.result.coverage.snmp = True
        state.end()


class _State:
    """Contatori e avanzamento di una scansione."""

    def __init__(self, result: ScanResult, steps: list[str], on_progress):
        self.result = result
        self.steps = steps
        self.on_progress = on_progress
        self.index = -1
        self.failures = 0
        self.successes = 0
        self.last_error: HelperError | None = None

    def _emit(self, name: str, fraction: float) -> None:
        if self.on_progress is None:
            return
        try:
            self.on_progress(name, max(0.0, min(1.0, fraction)))
        except Exception:
            log.debug("on_progress callback failed", exc_info=True)

    def start(self, name: str) -> None:
        self.index = self.steps.index(name)
        self._emit(name, self.index / len(self.steps))

    def end(self) -> None:
        self._emit(self.steps[self.index], (self.index + 1) / len(self.steps))

    def ok(self) -> None:
        self.successes += 1

    def fail(self, message: str) -> None:
        self.failures += 1
        self.result.warnings.append(message)
