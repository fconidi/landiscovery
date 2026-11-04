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


class _Lines:
    """Raccoglie stdout e passa al chiamante ogni riga completa."""

    def __init__(self, on_line):
        self.on_line = on_line
        self.data = bytearray()
        self.partial = b""

    def write(self, chunk: bytes) -> None:
        self.data += chunk
        if self.on_line is None:
            return
        self.partial += chunk
        *lines, self.partial = self.partial.split(b"\n")
        for line in lines:
            self.on_line(line.decode("utf-8", errors="replace"))

    def flush(self) -> None:
        pass

    def finish(self) -> str:
        if self.on_line is not None and self.partial:
            self.on_line(self.partial.decode("utf-8", errors="replace"))
            self.partial = b""
        return self.data.decode("utf-8", errors="replace")


class HelperRunner:
    """Esegue un'operazione dell'helper e ne permette l'annullamento.

    ``cancel()`` si può chiamare da qualunque thread e in qualunque momento:
    prima di ``run`` fa sollevare subito ``ScanCancelled`` alla prossima
    esecuzione senza avviare nulla; durante ``run`` ferma l'intera catena di
    processi; a esecuzione conclusa non ha effetto.
    """

    def __init__(self, command: list[str] | None = None, *, direct: bool = False,
                 which: dict[str, str] | None = None):
        self.command = list(DEFAULT_COMMAND if command is None else command)
        self.direct = direct
        self.which = helper.BIN if which is None else which
        self._lock = threading.Lock()
        self._state = _IDLE
        self._pending = False
        self._cancelled = False
        self._proc: subprocess.Popen | None = None
        self._direct: helper._Runner | None = None
        self._done = threading.Event()

    # --- stato ---------------------------------------------------------------

    def _start(self) -> None:
        """Passa allo stato di esecuzione; va chiamato con il lock acquisito."""
        if self._pending:
            self._pending = False
            raise ScanCancelled()
        self._state = _RUNNING
        self._cancelled = False
        self._done.clear()

    def _finish(self) -> None:
        with self._lock:
            self._state = _FINISHED
            self._proc = None
            self._direct = None
        self._done.set()

    # --- esecuzione ------------------------------------------------------------

    def run(self, op: str, params: dict, on_line=None) -> str:
        """Esegue ``op`` e restituisce lo stdout prodotto (XML o testo)."""
        if self.direct:
            return self._run_direct(op, params, on_line)
        return self._run_helper(op, params, on_line)

    def _run_helper(self, op: str, params: dict, on_line) -> str:
        try:
            request = (json.dumps({"op": op, "params": params}) + "\n").encode()
        except (TypeError, ValueError) as exc:
            raise HelperError("request cannot be encoded") from exc
        with self._lock:
            self._start()
            try:
                proc = subprocess.Popen(
                    self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, close_fds=True, start_new_session=True)
            except OSError as exc:
                self._state = _FINISHED
                self._done.set()
                raise HelperError(
                    f"cannot run {self.command[0]}: {exc.strerror or exc}") from exc
            self._proc = proc
            try:
                proc.stdin.write(request)
                proc.stdin.flush()
            except OSError:
                pass  # l'helper è già uscito: lo dirà il codice di uscita
        sink = _Lines(on_line)
        try:
            stderr = self._collect(proc, sink)
            text = sink.finish()
        finally:
            # EOF su stdin: se l'helper è ancora vivo si ferma da solo.
            with self._lock:
                self._close_stdin(proc)
            rc = proc.wait()
            for stream in (proc.stdout, proc.stderr):
                stream.close()
            self._finish()
        if self._cancelled:
            raise ScanCancelled()
        if rc != 0:
            raise _failure(rc, stderr, "helper")
        return text

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

    def _run_direct(self, op: str, params: dict, on_line) -> str:
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
        """Annulla l'esecuzione in corso (o la prossima, se non è ancora iniziata)."""
        with self._lock:
            if self._state == _IDLE:
                self._pending = True
                return
            if self._state == _FINISHED:
                return
            self._cancelled = True
            proc, direct = self._proc, self._direct
            if direct is not None:
                direct.request_stop()
            elif proc is not None and proc.stdin is not None and not proc.stdin.closed:
                try:
                    proc.stdin.write(b"cancel\n")
                    proc.stdin.flush()
                except OSError:
                    pass
                self._close_stdin(proc)
        if direct is not None:
            # Il ciclo di esecuzione passa a SIGKILL dopo il tempo di grazia.
            self._done.wait(helper.KILL_GRACE + CANCEL_WAIT)
            return
        if proc is None:
            return
        for sig, timeout in ((None, CANCEL_WAIT), (signal.SIGTERM, KILL_WAIT),
                             (signal.SIGKILL, CANCEL_WAIT)):
            if sig is not None:
                try:
                    proc.send_signal(sig)
                except OSError:
                    pass  # processo di un altro utente o già terminato
            try:
                proc.wait(timeout=timeout)
                return
            except subprocess.TimeoutExpired:
                continue
