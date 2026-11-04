import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from landiscovery import runner as runner_mod
from landiscovery.helper import HelperError
from landiscovery.runner import DEFAULT_COMMAND, HelperRunner, ScanCancelled

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"

REQ_OP = "os_detect"
REQ_PARAMS = {"targets": ["10.0.0.1"]}


def _alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    try:
        state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
    except (OSError, IndexError):
        return False
    return state != "Z"


def wait_dead(pids, timeout=8.0):
    deadline = time.monotonic() + timeout
    while any(_alive(p) for p in pids):
        assert time.monotonic() < deadline, f"still alive: {[p for p in pids if _alive(p)]}"
        time.sleep(0.02)


def wait_file(path, timeout=10.0):
    deadline = time.monotonic() + timeout
    while not path.exists():
        assert time.monotonic() < deadline, f"{path} not written"
        time.sleep(0.02)
    return [int(x) for x in path.read_text().split()]


FAMILY = r"""#!{python}
import os, signal, subprocess, sys, time
{trap}
p = subprocess.Popen(["sleep", "60"])
with open({out!r} + ".tmp", "w") as f:
    f.write(f"{{os.getpid()}} {{p.pid}}\n")
os.rename({out!r} + ".tmp", {out!r})
sys.stdout.write("<partial/>\n")
sys.stdout.flush()
time.sleep(60)
"""


def make_family(tmp_path, ignore_term=False):
    pids = tmp_path / "pids"
    script = tmp_path / "family"
    trap = "signal.signal(signal.SIGTERM, signal.SIG_IGN)" if ignore_term else ""
    script.write_text(FAMILY.format(python=sys.executable, out=str(pids), trap=trap))
    script.chmod(0o755)
    return {"nmap": str(script), "arp-scan": str(script)}, pids


def make_sh(tmp_path, body, name="fake"):
    script = tmp_path / name
    script.write_text("#!/bin/sh\n" + body + "\n")
    script.chmod(0o755)
    return {"nmap": str(script), "arp-scan": str(script)}


def helper_command(which):
    """Comando che esegue il helper vero (senza pkexec) con binari finti."""
    code = (
        "import sys\n"
        f"sys.path.insert(0, {str(SRC)!r})\n"
        "from landiscovery.helper import main\n"
        f"sys.exit(main([], which={which!r}))\n"
    )
    return [sys.executable, "-c", code]


def cancel_when(path, runner, result):
    def worker():
        result["pids"] = wait_file(path)
        result["t0"] = time.monotonic()
        runner.cancel()
        result["t1"] = time.monotonic()
    t = threading.Thread(target=worker)
    t.start()
    return t


# --- costruzione ---------------------------------------------------------------

def test_default_command_uses_pkexec():
    assert DEFAULT_COMMAND == ["pkexec", "/usr/lib/landiscovery/landiscovery-helper"]
    assert HelperRunner().command == DEFAULT_COMMAND


# --- protocollo con il helper -------------------------------------------------

def test_run_returns_stdout(tmp_path):
    which = make_sh(tmp_path, 'echo "<nmaprun>"; echo "caf\\303\\251 \\377"; echo "</nmaprun>"')
    lines = []
    out = HelperRunner(helper_command(which)).run(REQ_OP, REQ_PARAMS, on_line=lines.append)
    assert out == "<nmaprun>\ncafé �\n</nmaprun>\n"
    assert lines == ["<nmaprun>", "café �", "</nmaprun>"]


def test_request_is_first_line_and_stdin_stays_open(tmp_path):
    seen = tmp_path / "seen"
    code = (
        "import sys, json\n"
        "line = sys.stdin.buffer.readline()\n"
        f"open({str(seen)!r}, 'wb').write(line)\n"
        "print('ok')\n"
    )
    out = HelperRunner([sys.executable, "-c", code]).run("port_scan", {"x": 1})
    assert out == "ok\n"
    line = seen.read_bytes()
    assert line.endswith(b"\n") and line.count(b"\n") == 1
    assert json.loads(line) == {"op": "port_scan", "params": {"x": 1}}


def test_helper_error_raised_with_stderr(tmp_path):
    which = make_sh(tmp_path, "touch ran")
    with pytest.raises(HelperError) as info:
        HelperRunner(helper_command(which)).run("os_detect", {"targets": ["-x"]})
    assert "landiscovery-helper:" in str(info.value)
    assert "\n" not in str(info.value)
    assert info.value.returncode == 2
    assert not (tmp_path / "ran").exists()


def test_nonzero_exit_without_stderr(tmp_path):
    code = "import sys; sys.stdin.readline(); sys.exit(5)"
    with pytest.raises(HelperError) as info:
        HelperRunner([sys.executable, "-c", code]).run(REQ_OP, REQ_PARAMS)
    assert info.value.returncode == 5 and "5" in str(info.value)


def test_missing_command_raises_helper_error(tmp_path):
    with pytest.raises(HelperError):
        HelperRunner([str(tmp_path / "absent")]).run(REQ_OP, REQ_PARAMS)


def test_cancel_via_stdin_kills_grandchild(tmp_path):
    which, pidfile = make_family(tmp_path)
    runner = HelperRunner(helper_command(which))
    result = {}
    t = cancel_when(pidfile, runner, result)
    with pytest.raises(ScanCancelled):
        runner.run(REQ_OP, REQ_PARAMS)
    t.join(timeout=20)
    assert not t.is_alive()
    leader, grandchild = result["pids"]
    wait_dead([leader, grandchild])
    assert result["t1"] - result["t0"] < 5


def test_cancelled_run_raises_scancancelled(tmp_path):
    which, pidfile = make_family(tmp_path, ignore_term=True)
    runner = HelperRunner(helper_command(which))
    result = {}
    t = cancel_when(pidfile, runner, result)
    t0 = time.monotonic()
    with pytest.raises(ScanCancelled):
        runner.run(REQ_OP, REQ_PARAMS)
    t.join(timeout=20)
    wait_dead(result["pids"])
    assert time.monotonic() - t0 < 15


def test_cancel_before_start_is_noop(tmp_path):
    marker = tmp_path / "started"
    runner = HelperRunner([sys.executable, "-c", f"open({str(marker)!r}, 'w')"])
    runner.cancel()
    with pytest.raises(ScanCancelled):
        runner.run(REQ_OP, REQ_PARAMS)
    assert not marker.exists()


def test_cancel_after_finish_is_noop(tmp_path):
    which = make_sh(tmp_path, 'echo "<x/>"')
    runner = HelperRunner(helper_command(which))
    assert runner.run(REQ_OP, REQ_PARAMS) == "<x/>\n"
    runner.cancel()
    runner.cancel()
    assert runner.run(REQ_OP, REQ_PARAMS) == "<x/>\n"


def test_cancel_twice_while_running(tmp_path):
    which, pidfile = make_family(tmp_path)
    runner = HelperRunner(helper_command(which))
    result = {}

    def worker():
        result["pids"] = wait_file(pidfile)
        a = threading.Thread(target=runner.cancel)
        a.start()
        runner.cancel()
        a.join()

    t = threading.Thread(target=worker)
    t.start()
    with pytest.raises(ScanCancelled):
        runner.run(REQ_OP, REQ_PARAMS)
    t.join(timeout=20)
    wait_dead(result["pids"])


def test_unresponsive_helper_gets_sigterm_then_sigkill(tmp_path):
    pidfile = tmp_path / "pid"
    # un "helper" che ignora stdin e SIGTERM: il runner deve comunque chiuderlo
    code = (
        "import os, signal, sys, time\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "sys.stdin.readline()\n"
        f"open({str(pidfile)!r} + '.tmp', 'w').write(str(os.getpid()))\n"
        f"os.rename({str(pidfile)!r} + '.tmp', {str(pidfile)!r})\n"
        "time.sleep(60)\n"
    )
    runner = HelperRunner([sys.executable, "-c", code])
    result = {}
    t = cancel_when(pidfile, runner, result)
    with pytest.raises(ScanCancelled):
        runner.run(REQ_OP, REQ_PARAMS)
    t.join(timeout=20)
    wait_dead(result["pids"])
    elapsed = result["t1"] - result["t0"]
    assert 6.5 <= elapsed < 12


def test_exception_in_callback_stops_helper(tmp_path):
    which, pidfile = make_family(tmp_path)

    def boom(_line):
        raise RuntimeError("stop")

    with pytest.raises(RuntimeError):
        HelperRunner(helper_command(which)).run(REQ_OP, REQ_PARAMS, on_line=boom)
    wait_dead(wait_file(pidfile))


RUNNER_SCRIPT = """
import sys
sys.path.insert(0, {src!r})
from landiscovery.runner import HelperRunner
HelperRunner({cmd!r}).run("os_detect", {{"targets": ["10.0.0.1"]}})
"""


def test_runner_process_death_stops_helper(tmp_path):
    which, pidfile = make_family(tmp_path)
    code = RUNNER_SCRIPT.format(src=str(SRC), cmd=helper_command(which))
    proc = subprocess.Popen([sys.executable, "-c", code])
    pids = wait_file(pidfile)
    proc.kill()
    proc.wait(timeout=10)
    wait_dead(pids)


# --- modalita' ridotta (diretta) ---------------------------------------------

def test_direct_mode_runs_built_command(tmp_path):
    which = make_sh(tmp_path, 'printf "%s\\n" "$@"; pwd')
    runner = HelperRunner(direct=True, which=which)
    out = runner.run("port_scan", {"targets": ["10.0.0.1"], "ports": "22", "service": False})
    args = out.splitlines()
    assert args[:3] == ["-n", "-oX", "-"]
    assert args[-3:] == ["--", "10.0.0.1/32", "/"]
    assert ("-sS" if os.geteuid() == 0 else "-sT") in args


def test_direct_mode_validates_before_starting(tmp_path):
    which = make_sh(tmp_path, f'touch "{tmp_path}/ran"')
    with pytest.raises(HelperError):
        HelperRunner(direct=True, which=which).run("os_detect", {"targets": ["-iL/etc/x"]})
    with pytest.raises(HelperError):
        HelperRunner(direct=True, which=which).run("os_detect", {"targets": ["10.0.0.0/7"]})
    assert not (tmp_path / "ran").exists()


def test_direct_mode_error_uses_stderr(tmp_path):
    which = make_sh(tmp_path, 'echo "first" >&2; echo "nmap: bad thing" >&2; exit 1')
    with pytest.raises(HelperError) as info:
        HelperRunner(direct=True, which=which).run(REQ_OP, REQ_PARAMS)
    assert "nmap: bad thing" in str(info.value) and info.value.returncode == 1


def test_direct_mode_cancel_kills_grandchild(tmp_path):
    which, pidfile = make_family(tmp_path, ignore_term=True)
    runner = HelperRunner(direct=True, which=which)
    result = {}
    t = cancel_when(pidfile, runner, result)
    with pytest.raises(ScanCancelled):
        runner.run(REQ_OP, REQ_PARAMS)
    t.join(timeout=20)
    wait_dead(result["pids"])
    assert result["t1"] - result["t0"] < 6


def test_direct_mode_cancel_before_start(tmp_path):
    which = make_sh(tmp_path, f'touch "{tmp_path}/ran"')
    runner = HelperRunner(direct=True, which=which)
    runner.cancel()
    with pytest.raises(ScanCancelled):
        runner.run(REQ_OP, REQ_PARAMS)
    assert not (tmp_path / "ran").exists()


def test_module_has_no_shell():
    text = Path(runner_mod.__file__).read_text()
    assert "shell=True" not in text and "os.system" not in text
