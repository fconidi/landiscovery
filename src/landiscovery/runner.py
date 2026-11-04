"""Esecuzione cancellabile delle scansioni.

Con privilegi la richiesta passa a ``pkexec`` e all'helper: il processo
dell'applicazione non può inviare segnali a un processo di root, quindi
l'annullamento viaggia sulla pipe di stdin (riga ``cancel`` e poi EOF). Se il
processo dell'applicazione muore, la pipe si chiude e l'helper si ferma da
solo.

In modalità ridotta il comando è costruito con la stessa validazione
dell'helper ed eseguito direttamente, senza privilegi.
"""

from __future__ import annotations

import json
import os
import select
import signal
import subprocess
import tempfile
import threading

from . import helper
from .helper import HelperError

DEFAULT_COMMAND = ["pkexec", "/usr/lib/landiscovery/landiscovery-helper"]

CANCEL_WAIT = 5.0
KILL_WAIT = 2.0
MAX_STDERR = 64 * 1024
MAX_MESSAGE = 300

_IDLE, _RUNNING, _FINISHED = "idle", "running", "finished"


class ScanCancelled(Exception):
    """La scansione è stata annullata."""


def _failure(rc: int, stderr: bytes, what: str) -> HelperError:
    text = stderr.decode("utf-8", errors="replace")
    lines = [" ".join(line.split()) for line in text.splitlines()]
    lines = [line for line in lines if line]
    msg = lines[-1] if lines else f"{what} exited with status {rc}"
    if len(msg) > MAX_MESSAGE:
        msg = msg[:MAX_MESSAGE - 3] + "..."
    err = HelperError(msg)
    err.returncode = rc
    return err


class _CallbackError(Exception):
    """Errore sollevato da ``on_line``: va riconsegnato al chiamante intatto."""

    def __init__(self, original: BaseException):
        super().__init__(original)
        self.original = original


class _Lines:
    """Raccoglie stdout e passa al chiamante ogni riga completa."""

    def __init__(self, on_line):
        self.on_line = on_line
        self.data = bytearray()
        self.partial = b""

    def _emit(self, raw: bytes) -> None:
        try:
            self.on_line(raw.decode("utf-8", errors="replace"))
        except Exception as exc:
            # Incapsulato perché non venga scambiato per un errore di scrittura.
            raise _CallbackError(exc) from None

    def write(self, chunk: bytes) -> None:
        self.data += chunk
        if self.on_line is None:
            return
        self.partial += chunk
        *lines, self.partial = self.partial.split(b"\n")
        for line in lines:
            self._emit(line)

    def flush(self) -> None:
        pass

    def finish(self) -> str:
        if self.on_line is not None and self.partial:
            partial, self.partial = self.partial, b""
            self._emit(partial)
        return self.data.decode("utf-8", errors="replace")


def _encode(op: str, params: dict) -> bytes:
    try:
        request = (json.dumps({"op": op, "params": params}) + "\n").encode()
    except (TypeError, ValueError) as exc:
        raise HelperError("request cannot be encoded") from exc
    if len(request) > helper.MAX_INPUT:
        raise HelperError("request too large")
    return request


def _signal(proc: subprocess.Popen, sig: int) -> None:
    try:
        proc.send_signal(sig)
    except OSError:
        pass  # processo di un altro utente o già terminato


def _terminate(proc: subprocess.Popen) -> bool:
    """Attende l'uscita, poi SIGTERM e SIGKILL; True se il processo è raccolto."""
    for sig, timeout in ((None, CANCEL_WAIT), (signal.SIGTERM, KILL_WAIT),
                         (signal.SIGKILL, CANCEL_WAIT)):
        if sig is not None:
            _signal(proc, sig)
        try:
            proc.wait(timeout=timeout)
            return True
        except subprocess.TimeoutExpired:
            continue
    return False


class HelperRunner:
    """Esegue le operazioni dell'helper e ne permette l'annullamento.

    Lo stesso oggetto serve per più passi di una scansione, uno alla volta:
    un secondo ``run`` concorrente solleva ``RuntimeError``.

    ``cancel()`` si può chiamare da qualunque thread e in qualunque momento e
    resta valido: l'esecuzione in corso viene fermata lungo tutta la catena di
    processi e ogni ``run`` successivo solleva subito ``ScanCancelled``, senza
    avviare nulla, finché non si chiama ``reset()``. ``cancel()`` può
    attendere fino a circa 12 s che i processi terminino: va chiamato da un
    thread di lavoro, non dal ciclo principale dell'interfaccia.

    ``on_line`` viene eseguito nel thread che chiama ``run``: un'interfaccia
    grafica deve passare le righe al proprio ciclo principale (per esempio
    con ``GLib.idle_add``). Un'eccezione sollevata da ``on_line`` ferma
    l'esecuzione e arriva invariata al chiamante.
    """

    def __init__(self, command: list[str] | None = None, *, direct: bool = False,
                 which: dict[str, str] | None = None):
        self.command = list(DEFAULT_COMMAND if command is None else command)
        self.direct = direct
        self.which = helper.BIN if which is None else which
        self._lock = threading.Lock()
        self._state = _IDLE
        self._cancelled = False
        self._writing = False
        self._proc: subprocess.Popen | None = None
        self._direct: helper._Runner | None = None
        self._done = threading.Event()

    # --- stato ---------------------------------------------------------------

    def _start(self) -> None:
        """Passa allo stato di esecuzione; va chiamato con il lock acquisito."""
        if self._state == _RUNNING:
            raise RuntimeError("a run is already in progress")
        if self._cancelled:
            raise ScanCancelled()
        self._state = _RUNNING
        self._done.clear()

    def _finish(self) -> None:
        with self._lock:
            self._state = _FINISHED
            self._proc = None
            self._direct = None
        self._done.set()

    def reset(self) -> None:
        """Annulla l'effetto di ``cancel()`` per le esecuzioni successive."""
        with self._lock:
            if self._state == _RUNNING:
                raise RuntimeError("cannot reset while a run is in progress")
            self._cancelled = False

    # --- esecuzione ------------------------------------------------------------

    def run(self, op: str, params: dict, on_line=None) -> str:
        """Esegue ``op`` e restituisce lo stdout prodotto (XML o testo)."""
        try:
            if self.direct:
                return self._run_direct(op, params, on_line)
            return self._run_helper(op, params, on_line)
        except _CallbackError as wrapped:
            raise wrapped.original from None

    def _run_helper(self, op: str, params: dict, on_line) -> str:
        request = _encode(op, params)
        with self._lock:
            self._start()
            try:
                proc = subprocess.Popen(
                    self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, bufsize=0, close_fds=True,
                    start_new_session=True)
            except OSError as exc:
                self._state = _FINISHED
                self._done.set()
                raise HelperError(
                    f"cannot run {self.command[0]}: {exc.strerror or exc}") from exc
            self._proc = proc
            self._writing = True
        # Scrittura fuori dal lock: se l'altro capo non legge (per esempio
        # pkexec in attesa dell'autenticazione) cancel() non resta bloccato.
        try:
            self._send(proc, request)
        finally:
            with self._lock:
                self._writing = False
                if self._cancelled:
                    self._close_stdin(proc)
        sink = _Lines(on_line)
        rc = None
        try:
            stderr = self._collect(proc, sink)
            text = sink.finish()
        finally:
            # EOF su stdin e pipe di uscita chiuse: un helper ancora vivo, anche
            # se fermo in scrittura, riceve EPIPE e prende la via di arresto.
            with self._lock:
                self._close_stdin(proc)
            for stream in (proc.stdout, proc.stderr):
                stream.close()
            if _terminate(proc):
                rc = proc.returncode
            else:
                threading.Thread(target=proc.wait, daemon=True).start()
            self._finish()
        if self._cancelled:
            raise ScanCancelled()
        if rc is None:
            raise HelperError("helper did not exit")
        if rc != 0:
            raise _failure(rc, stderr, "helper")
        return text

    @staticmethod
    def _send(proc: subprocess.Popen, data: bytes) -> None:
        view = memoryview(data)
        try:
            while view:
                written = proc.stdin.write(view)
                view = view[written:]
        except (OSError, ValueError):
            pass  # l'helper è già uscito: lo dirà il codice di uscita

    @staticmethod
    def _collect(proc: subprocess.Popen, sink: _Lines) -> bytes:
        """Legge stdout e stderr fino alla chiusura di entrambi."""
        streams = {proc.stdout.fileno(): "out", proc.stderr.fileno(): "err"}
        stderr = bytearray()
        poller = select.poll()
        for fd in streams:
            poller.register(fd, select.POLLIN | select.POLLERR | select.POLLHUP)
        while streams:
            for fd, _event in poller.poll():
                data = os.read(fd, 65536)
                if not data:
                    poller.unregister(fd)
                    del streams[fd]
                elif streams[fd] == "out":
                    sink.write(data)
                else:
                    stderr += data
                    del stderr[:-MAX_STDERR]
        return bytes(stderr)

    @staticmethod
    def _close_stdin(proc: subprocess.Popen) -> None:
        if proc.stdin is not None and not proc.stdin.closed:
            try:
                proc.stdin.close()
            except OSError:
                pass

    @classmethod
    def _send_cancel(cls, proc: subprocess.Popen) -> None:
        """Scrive ``cancel`` senza mai bloccarsi, poi chiude stdin (EOF)."""
        if proc.stdin is None or proc.stdin.closed:
            return
        try:
            os.set_blocking(proc.stdin.fileno(), False)
            proc.stdin.write(b"cancel\n")
        except (OSError, ValueError):
            pass  # pipe piena o chiusa: basta l'EOF
        cls._close_stdin(proc)

    def _run_direct(self, op: str, params: dict, on_line) -> str:
        _encode(op, params)
        cmd = helper.build_command(op, params)
        argv = [self.which[cmd[0]], *cmd[1:]]
        with self._lock:
            self._start()
            runner = self._direct = helper._Runner()
        sink = _Lines(on_line)
        try:
            with tempfile.TemporaryFile() as errfile:
                runner.stderr = errfile
                try:
                    rc = runner.run(argv, sink)
                except OSError as exc:
                    raise HelperError(f"cannot run {cmd[0]}: {exc.strerror or exc}") from exc
                errfile.seek(0, os.SEEK_END)
                errfile.seek(max(0, errfile.tell() - MAX_STDERR))
                stderr = errfile.read()
            text = sink.finish()
        finally:
            self._finish()
        if self._cancelled:
            raise ScanCancelled()
        if rc != 0:
            raise _failure(rc, stderr, cmd[0])
        return text

    # --- annullamento ------------------------------------------------------------

    def cancel(self) -> None:
        """Annulla l'esecuzione in corso e tutte le successive fino a ``reset()``."""
        with self._lock:
            self._cancelled = True
            if self._state != _RUNNING:
                return
            proc, direct = self._proc, self._direct
            if direct is not None:
                direct.request_stop()
            elif proc is not None and not self._writing:
                self._send_cancel(proc)
            # Se la richiesta è ancora in scrittura, stdin viene chiuso dal
            # thread di run() appena la scrittura termina o fallisce.
        if direct is not None:
            # Il ciclo di esecuzione passa a SIGKILL dopo il tempo di grazia.
            self._done.wait(helper.KILL_GRACE + CANCEL_WAIT)
        elif proc is not None:
            _terminate(proc)
