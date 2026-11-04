"""Helper privilegiato: esegue solo un elenco fisso di operazioni di scansione.

La prima riga di stdin è un oggetto JSON ``{"op": ..., "params": {...}}``;
il comando è costruito a partire da parametri validati ed eseguito senza
shell. Gli argomenti nmap arbitrari non sono mai accettati.

Dopo la richiesta stdin resta aperto e fa da canale di annullamento: una
riga ``cancel`` oppure la fine del file fanno terminare il gruppo di processi
del figlio (SIGTERM, poi SIGKILL dopo 2 s) e l'uscita con codice 143. Lo
stesso accade se stdout non è più scrivibile.
"""

from __future__ import annotations

import json
import os
import select
import signal
import subprocess
import sys
import threading
import time

from .profiles import validate_ports
from .targets import TargetError, check_scope, parse_targets

MAX_INPUT = 64 * 1024
MAX_TARGETS = 256
MIN_PREFIX_V4 = 8
MAX_SHOWN = 80
MAX_CONTROL_LINE = 256
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


def _short(value) -> str:
    """Rappresentazione di un valore dell'utente, al massimo MAX_SHOWN caratteri."""
    text = repr(value)
    if len(text) > MAX_SHOWN:
        text = text[:MAX_SHOWN - 3] + "..."
    return text


def _check_keys(op: str, params) -> None:
    if not isinstance(params, dict):
        raise HelperError("params must be an object")
    expected = _PARAMS[op]
    keys = set(params)
    if keys - expected:
        raise HelperError(f"unknown parameters: {_short(sorted(map(str, keys - expected)))}")
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
            raise HelperError(f"invalid target: {_short(item)}") from exc
    if len(nets) > MAX_TARGETS:
        raise HelperError("too many targets")
    if any(n.version == 4 and n.prefixlen < MIN_PREFIX_V4 for n in nets):
        raise HelperError(f"IPv4 target network wider than /{MIN_PREFIX_V4}")
    if not check_scope(nets).allowed:
        raise HelperError("target network too wide")
    if len({n.version for n in nets}) > 1:
        raise HelperError("IPv4 and IPv6 targets cannot be mixed")
    return nets


def _ports(value) -> str:
    try:
        validate_ports(value)
    except ValueError as exc:
        raise HelperError(f"invalid ports: {_short(value)}") from exc
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
        raise HelperError(f"unknown operation: {_short(op)}")
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
                raise HelperError(f"script not allowed: {_short(name)}")
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
    except RecursionError as exc:
        raise HelperError("request is nested too deeply") from exc
    if not isinstance(req, dict) or set(req) != {"op", "params"}:
        raise HelperError('request must be {"op": ..., "params": {...}}')
    return req["op"], req["params"]


_PR_SET_PDEATHSIG = 1
_prctl = None


def _load_prctl():
    """Risolve prctl(2) prima del fork: nel figlio non si caricano librerie."""
    global _prctl
    if _prctl is None and sys.platform.startswith("linux"):
        import ctypes
        try:
            _prctl = ctypes.CDLL(None, use_errno=True).prctl
        except (OSError, AttributeError):
            _prctl = False
    return _prctl or None


def child_setup():
    """Restituisce la funzione da eseguire nel figlio prima di exec.

    Il figlio riceve SIGKILL se il processo che lo ha avviato muore, così
    un helper ucciso non lascia nmap in esecuzione come root.
    """
    prctl = _load_prctl()
    parent = os.getpid()
    if prctl is not None:
        import ctypes
        args = [ctypes.c_ulong(v) for v in (signal.SIGKILL, 0, 0, 0)]

    def setup():
        if prctl is not None:
            prctl(_PR_SET_PDEATHSIG, *args)
            if os.getppid() != parent:
                os.kill(os.getpid(), signal.SIGKILL)

    return setup


class _Runner:
    """Esegue un comando nel proprio gruppo di processi e lo ferma su richiesta.

    ``request_stop`` può essere chiamato da un gestore di segnali o da un altro
    thread. Il gruppo viene colpito solo finché il leader non è stato raccolto,
    quindi il suo identificativo non può appartenere a processi estranei.
    """

    def __init__(self, stderr=None):
        self.proc: subprocess.Popen | None = None
        self.stop = False
        self.deadline = 0.0
        self.killed = False
        self.reaped = False
        self.stderr = stderr
        self._lock = threading.RLock()

    def _killpg(self, sig: int) -> None:
        with self._lock:
            if self.proc is None or self.reaped:
                return
            try:
                os.killpg(self.proc.pid, sig)
            except (ProcessLookupError, PermissionError):
                pass

    def request_stop(self, *_args) -> None:
        if not self.stop:
            # Prima la scadenza, poi il flag: un altro thread che vede il flag
            # trova già la scadenza corretta.
            self.deadline = time.monotonic() + KILL_GRACE
            self.stop = True
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

    def _reap(self) -> int:
        main_thread = threading.current_thread() is threading.main_thread()
        blocked = {signal.SIGTERM, signal.SIGINT}
        if main_thread:
            old = signal.pthread_sigmask(signal.SIG_BLOCK, blocked)
        try:
            with self._lock:
                # Il leader è ancora da raccogliere: il gruppo è sicuramente
                # nostro e qualunque processo rimasto viene ucciso.
                self._killpg(signal.SIGKILL)
                rc = self.proc.wait()
                self.reaped = True
        finally:
            if main_thread:
                signal.pthread_sigmask(signal.SIG_SETMASK, old)
        return rc

    def run(self, argv: list[str], out, on_started=None) -> int:
        if self.stop:
            return EXIT_TERMINATED
        self.proc = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=self.stderr,
            shell=False, close_fds=True, start_new_session=True, env=_ENV, cwd="/",
            preexec_fn=child_setup())
        fd = self.proc.stdout.fileno()
        leader_gone = False
        drain_until = 0.0
        try:
            if on_started is not None:
                on_started()
            if self.stop:
                self._killpg(signal.SIGTERM)
            while True:
                self._escalate()
                if not leader_gone and self._leader_exited():
                    leader_gone = True
                    drain_until = time.monotonic() + KILL_GRACE
                    # Eventuali discendenti rimasti nel gruppo non servono più.
                    self._killpg(signal.SIGKILL)
                if fd is None:
                    if leader_gone:
                        break
                    time.sleep(0.05)
                    continue
                if leader_gone and time.monotonic() >= drain_until:
                    break
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
        finally:
            rc = self._reap()
            self.proc.stdout.close()
        if self.stop:
            return EXIT_TERMINATED
        return rc if rc >= 0 else 128 - rc


class _LineReader:
    """Legge righe direttamente dal descrittore, senza buffer con lock.

    Un thread fermo in lettura su un oggetto file bufferizzato bloccherebbe
    la chiusura dell'interprete; ``os.read`` non ha questo problema.
    """

    def __init__(self, fd: int):
        self.fd = fd
        self.buf = b""
        self.eof = False

    def readline(self, limit: int) -> bytes:
        while b"\n" not in self.buf and len(self.buf) < limit and not self.eof:
            data = os.read(self.fd, 4096)
            if not data:
                self.eof = True
            self.buf += data
        end = self.buf.find(b"\n")
        end = len(self.buf) if end < 0 else end + 1
        end = min(end, limit)
        line, self.buf = self.buf[:end], self.buf[end:]
        return line


def _watch_stdin(reader: _LineReader, runner: _Runner) -> None:
    """Legge il canale di annullamento: ``cancel`` o EOF fermano l'esecuzione."""
    try:
        while True:
            line = reader.readline(MAX_CONTROL_LINE)
            if not line or line.strip() == b"cancel":
                break
    except OSError:
        pass
    runner.request_stop()


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
    reader = _LineReader(stdin.fileno())

    try:
        if argv:
            raise HelperError("no command line arguments are accepted")
        op, params = _parse_request(reader.readline(MAX_INPUT + 1))
        cmd = build_command(op, params)
    except HelperError as exc:
        _error(stderr, str(exc))
        return EXIT_INVALID

    runner = _Runner()
    previous = {sig: signal.signal(sig, runner.request_stop)
                for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
    watcher = threading.Thread(target=_watch_stdin, args=(reader, runner), daemon=True)
    try:
        # Il controllo di stdin parte dopo l'avvio del figlio: il fork avviene
        # con un solo thread attivo.
        return runner.run([which[cmd[0]], *cmd[1:]], stdout, on_started=watcher.start)
    except OSError as exc:
        _error(stderr, f"cannot run {cmd[0]}: {exc.strerror or exc}")
        return EXIT_NOT_FOUND
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


if __name__ == "__main__":
    sys.exit(main())
