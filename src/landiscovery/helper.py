"""Helper privilegiato: esegue solo un elenco fisso di operazioni di scansione.

Legge da stdin un oggetto JSON ``{"op": ..., "params": {...}}``, costruisce
il comando a partire da parametri validati e lo esegue senza shell. Gli
argomenti nmap arbitrari non sono mai accettati.
"""

from __future__ import annotations

import json
import os
import select
import signal
import subprocess
import sys
import time

from .profiles import validate_ports
from .targets import TargetError, check_scope, parse_targets

MAX_INPUT = 64 * 1024
MAX_TARGETS = 256
KILL_GRACE = 2.0
EXIT_INVALID = 2
EXIT_NOT_FOUND = 127
EXIT_TERMINATED = 143

BIN: dict[str, str] = {
    "nmap": "/usr/bin/nmap",
    "arp-scan": "/usr/sbin/arp-scan",
}

_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}

# Script NSE ammessi: solo nomi esatti, non intrusivi, delle categorie
# "safe"/"default". Mai categorie, mai argomenti agli script.
NSE_ALLOWED: tuple[str, ...] = (
    "banner",
    "http-title",
    "http-server-header",
    "http-methods",
    "ssl-cert",
    "ssh-hostkey",
    "ssh2-enum-algos",
    "smb-protocols",
    "smb-security-mode",
    "smb2-security-mode",
    "ftp-anon",
    "telnet-encryption",
    "rdp-enum-encryption",
    "snmp-info",
    "upnp-info",
    "nbstat",
)

_PARAMS: dict[str, frozenset[str]] = {
    "arp_discover": frozenset({"targets"}),
    "port_scan": frozenset({"targets", "ports", "service"}),
    "os_detect": frozenset({"targets"}),
    "nse_safe": frozenset({"targets", "ports", "scripts"}),
    "traceroute": frozenset({"targets"}),
}

_NMAP_BASE = ["-n", "-oX", "-"]

# Ogni opzione che build_command può emettere prima del separatore "--".
FIXED_OPTIONS = frozenset({
    "--localnet", "-n", "-oX", "-", "-6", "-sS", "-sT", "-sn", "-sV", "-p",
    "--top-ports", "-O", "--osscan-limit", "--traceroute", "--script",
})


class HelperError(ValueError):
    """Richiesta non valida per l'helper."""


def _check_keys(op: str, params) -> None:
    if not isinstance(params, dict):
        raise HelperError("params must be an object")
    expected = _PARAMS[op]
    keys = set(params)
    if keys - expected:
        raise HelperError(f"unknown parameters: {sorted(map(str, keys - expected))}")
    if expected - keys:
        raise HelperError(f"missing parameters: {sorted(expected - keys)}")


def _targets(value, allow_empty: bool = False) -> list:
    if not isinstance(value, list) or not all(isinstance(t, str) for t in value):
        raise HelperError("targets must be a list of strings")
    if not value:
        if allow_empty:
            return []
        raise HelperError("no target given")
    nets = []
    for item in value:
        if not item.strip():
            raise HelperError("empty target")
        try:
            nets.extend(parse_targets(item))
        except TargetError as exc:
            raise HelperError(str(exc)) from exc
    if len(nets) > MAX_TARGETS:
        raise HelperError("too many targets")
    if not check_scope(nets).allowed:
        raise HelperError("target network too wide")
    if len({n.version for n in nets}) > 1:
        raise HelperError("IPv4 and IPv6 targets cannot be mixed")
    return nets


def _ports(value) -> str:
    try:
        validate_ports(value)
    except ValueError as exc:
        raise HelperError(f"invalid ports: {value!r}") from exc
    return value


def _port_args(ports: str) -> list[str]:
    if ports == "top100":
        return ["--top-ports", "100"]
    return ["-p", ports]


def _scan_type(euid: int) -> str:
    return "-sS" if euid == 0 else "-sT"


def build_command(op: str, params: dict, euid: int | None = None) -> list[str]:
    """Costruisce la riga di comando per un'operazione ammessa."""
    if not isinstance(op, str) or op not in _PARAMS:
        raise HelperError(f"unknown operation: {op!r}")
    _check_keys(op, params)
    if euid is None:
        euid = os.geteuid()

    if op == "arp_discover":
        nets = _targets(params["targets"], allow_empty=True)
        if any(n.version != 4 for n in nets):
            raise HelperError("ARP discovery supports IPv4 only")
        if not nets:
            return ["arp-scan", "--localnet"]
        return ["arp-scan", "--", *map(str, nets)]

    nets = _targets(params["targets"])
    opts: list[str] = ["-6"] if nets[0].version == 6 else []

    if op == "port_scan":
        ports = _ports(params["ports"])
        service = params["service"]
        if not isinstance(service, bool):
            raise HelperError("service must be a boolean")
        if ports == "":
            opts.append("-sn")
        else:
            opts += [_scan_type(euid), *_port_args(ports)]
            if service:
                opts.append("-sV")
    elif op == "os_detect":
        opts += ["-O", "--osscan-limit"]
    elif op == "traceroute":
        opts += ["--traceroute", "-sn"]
    elif op == "nse_safe":
        ports = _ports(params["ports"])
        if ports == "":
            raise HelperError("NSE scripts need a port specification")
        scripts = params["scripts"]
        if not isinstance(scripts, list) or not scripts:
            raise HelperError("scripts must be a non-empty list")
        chosen: list[str] = []
        for name in scripts:
            if not isinstance(name, str) or name not in NSE_ALLOWED:
                raise HelperError(f"script not allowed: {name!r}")
            if name not in chosen:
                chosen.append(name)
        opts += [_scan_type(euid), *_port_args(ports), "--script", ",".join(chosen)]

    return ["nmap", *_NMAP_BASE, *opts, "--", *map(str, nets)]


def _parse_request(raw) -> tuple[str, dict]:
    if len(raw) > MAX_INPUT:
        raise HelperError("request too large")
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise HelperError("request is not valid UTF-8") from exc
    try:
        req = json.loads(raw)
    except ValueError as exc:
        raise HelperError("request is not valid JSON") from exc
    if not isinstance(req, dict) or set(req) != {"op", "params"}:
        raise HelperError('request must be {"op": ..., "params": {...}}')
    return req["op"], req["params"]


class _Runner:
    def __init__(self):
        self.proc: subprocess.Popen | None = None
        self.stop = False
        self.deadline = 0.0
        self.killed = False

    def _killpg(self, sig: int) -> None:
        if self.proc is None:
            return
        try:
            os.killpg(self.proc.pid, sig)
        except (ProcessLookupError, PermissionError):
            pass

    def request_stop(self, *_args) -> None:
        if not self.stop:
            self.stop = True
            self.deadline = time.monotonic() + KILL_GRACE
            self._killpg(signal.SIGTERM)

    def _escalate(self) -> None:
        if self.stop and not self.killed and time.monotonic() >= self.deadline:
            self.killed = True
            self._killpg(signal.SIGKILL)

    def _leader_exited(self) -> bool:
        # Controlla senza raccogliere il processo: finché è uno zombie il
        # gruppo resta riservato e killpg non può colpire processi estranei.
        try:
            info = os.waitid(os.P_PID, self.proc.pid,
                             os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except ChildProcessError:
            return True
        return info is not None

    def run(self, argv: list[str], out) -> int:
        self.proc = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=None,
            shell=False, close_fds=True, start_new_session=True, env=_ENV)
        if self.stop:
            self._killpg(signal.SIGTERM)
        fd = self.proc.stdout.fileno()
        try:
            while True:
                self._escalate()
                if fd is not None:
                    ready, _, _ = select.select([fd], [], [], 0.1)
                    if not ready:
                        continue
                    data = os.read(fd, 65536)
                    if not data:
                        fd = None
                        continue
                    if not self.stop:
                        try:
                            out.write(data)
                            out.flush()
                        except (BrokenPipeError, OSError):
                            self.request_stop()
                elif self._leader_exited():
                    break
                else:
                    time.sleep(0.05)
            if self.stop:
                self._killpg(signal.SIGKILL)
        except BaseException:
            self._killpg(signal.SIGKILL)
            raise
        finally:
            rc = self.proc.wait()
            self.proc.stdout.close()
        if self.stop:
            return EXIT_TERMINATED
        return rc if rc >= 0 else 128 - rc


def _error(stderr, msg: str) -> None:
    line = " ".join(str(msg).split())
    stderr.write(f"landiscovery-helper: {line}\n")
    stderr.flush()


def main(argv=None, stdin=None, stdout=None, stderr=None, which=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    stdin = sys.stdin.buffer if stdin is None else stdin
    stdout = sys.stdout.buffer if stdout is None else stdout
    stderr = sys.stderr if stderr is None else stderr
    which = BIN if which is None else which

    try:
        if argv:
            raise HelperError("no command line arguments are accepted")
        op, params = _parse_request(stdin.read(MAX_INPUT + 1))
        cmd = build_command(op, params)
    except HelperError as exc:
        _error(stderr, str(exc))
        return EXIT_INVALID

    runner = _Runner()
    previous = {sig: signal.signal(sig, runner.request_stop)
                for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        return runner.run([which[cmd[0]], *cmd[1:]], stdout)
    except OSError as exc:
        _error(stderr, f"cannot run {cmd[0]}: {exc.strerror or exc}")
        return EXIT_NOT_FOUND
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


if __name__ == "__main__":
    sys.exit(main())
