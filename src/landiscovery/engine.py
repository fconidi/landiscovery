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
import threading
import time
from dataclasses import dataclass

from .helper import MAX_TARGETS, HelperError
from .models import Coverage, Host, ScanResult
from .nmapxml import ScanParseError, parse_nmap_xml
from .oui import OuiDatabase
from .profiles import Profile
from .runner import HelperRunner, ScanCancelled

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


class _Cancelled(Exception):
    pass


class ScanEngine:
    def __init__(self, runner=None, oui=None, privileged: bool | None = None):
        if privileged is None:
            privileged = os.geteuid() == 0 or shutil.which("pkexec") is not None
        self.privileged = bool(privileged)
        if runner is None:
            runner = HelperRunner(direct=not self.privileged)
        self.runner = runner
        self._oui = oui
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
            return self._scan(targets, profile, on_progress)
        finally:
            self._lock.release()

    def _scan(self, targets, profile, on_progress) -> ScanResult:
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

        steps = ["discovery"] + (["ports"] if do_ports else []) + (["os"] if do_os else [])
        state = _State(result, steps, on_progress)
        hosts: dict[str, Host] = {}
        try:
            self._discovery(state, hosts, target_strs, priv)
            ips = sorted(hosts, key=_ip_key)
            if do_ports:
                self._ports(state, hosts, ips, profile)
            if do_os:
                self._os(state, hosts, ips)
            result.status = "done"
        except _Cancelled:
            result.status = "cancelled"
        except ScanCancelled:
            result.status = "cancelled"
        if self._cancel.is_set():
            result.status = "cancelled"

        result.hosts = self._finish_hosts(hosts, priv)
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
