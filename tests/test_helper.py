import fcntl
import io
import json
import os
import signal
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from landiscovery import helper
from landiscovery.helper import NSE_ALLOWED, HelperError, build_command, main

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"

FORBIDDEN = ("intrusive", "brute", "dos", "exploit", "fuzzer", "vuln", "malware")


def ps(**kw):
    base = {"targets": ["192.168.1.0/24"], "ports": "22,80", "service": False}
    base.update(kw)
    return base


# --- operazioni e parametri -------------------------------------------------

def test_unknown_op_rejected():
    for op in ("shell", "raw", "", "PORT_SCAN", None, 5):
        with pytest.raises(HelperError):
            build_command(op, {"targets": ["10.0.0.1"]})


def test_params_must_be_dict():
    with pytest.raises(HelperError):
        build_command("os_detect", ["10.0.0.1"])


@pytest.mark.parametrize("op,params", [
    ("arp_discover", {"targets": [], "extra": 1}),
    ("port_scan", ps(args="-A")),
    ("os_detect", {"targets": ["10.0.0.1"], "ports": "22"}),
    ("traceroute", {"targets": ["10.0.0.1"], "options": ["--script=x"]}),
    ("nse_safe", {"targets": ["10.0.0.1"], "ports": "80", "scripts": ["banner"],
                  "script_args": "x=1"}),
])
def test_unknown_param_keys_rejected(op, params):
    with pytest.raises(HelperError):
        build_command(op, params)


def test_missing_param_keys_rejected():
    with pytest.raises(HelperError):
        build_command("port_scan", {"targets": ["10.0.0.1"], "ports": "22"})
    with pytest.raises(HelperError):
        build_command("nse_safe", {"targets": ["10.0.0.1"], "ports": "22"})


@pytest.mark.parametrize("bad", [
    "--script=vuln", "-iL/etc/shadow", "-oN/tmp/x", "10.0.0.1;id", "10.0.0.1 -sU",
    "$(id)", "host.example", "", "10.0.0.1\n-oX/tmp/x",
])
def test_target_with_option_rejected(bad):
    with pytest.raises(HelperError):
        build_command("os_detect", {"targets": [bad]})


def test_targets_must_be_list_of_str():
    for bad in ("10.0.0.1", [1], [None], [["10.0.0.1"]]):
        with pytest.raises(HelperError):
            build_command("os_detect", {"targets": bad})


def test_empty_targets_only_for_arp():
    with pytest.raises(HelperError):
        build_command("os_detect", {"targets": []})
    assert build_command("arp_discover", {"targets": []}) == ["arp-scan", "--localnet"]


def test_wide_ipv6_rejected():
    with pytest.raises(HelperError):
        build_command("port_scan", ps(targets=["fd00::/64"]))


@pytest.mark.parametrize("ports", [
    "80; id", "--script=x", "80 -sU", "0", "70000", "90-80", "a", "80,", 80, None,
])
def test_ports_injection_rejected(ports):
    with pytest.raises(HelperError):
        build_command("port_scan", ps(ports=ports))


def test_service_must_be_bool():
    with pytest.raises(HelperError):
        build_command("port_scan", ps(service="yes"))
    with pytest.raises(HelperError):
        build_command("port_scan", ps(service=1))


# --- NSE ----------------------------------------------------------------------

def test_nse_script_not_in_allowlist_rejected():
    for bad in (["vuln"], ["default"], ["safe"], ["http-title,vuln"], ["smb-vuln-ms17-010"],
                ["ssh-brute"], ["../x"], ["http-title", "all"], [], "banner", [1]):
        with pytest.raises(HelperError):
            build_command("nse_safe", {"targets": ["10.0.0.1"], "ports": "80",
                                       "scripts": bad})


def test_nse_allowlist_contents():
    assert isinstance(NSE_ALLOWED, tuple)
    assert len(NSE_ALLOWED) == len(set(NSE_ALLOWED))
    for name in NSE_ALLOWED:
        assert name not in FORBIDDEN and name not in ("all", "default", "safe")
        assert not any(word in name for word in FORBIDDEN)
        assert all(c.isalnum() or c == "-" for c in name)


def test_nse_command_excludes_dangerous_categories():
    cmd = build_command("nse_safe", {"targets": ["10.0.0.1"], "ports": "80,443",
                                     "scripts": ["http-title", "ssl-cert"]}, euid=0)
    assert cmd[0] == "nmap"
    i = cmd.index("--script")
    assert cmd[i + 1] == "http-title,ssl-cert"
    assert cmd.count("--script") == 1
    joined = " ".join(cmd)
    for word in FORBIDDEN:
        assert word not in joined
    assert not any(a.startswith("--script-args") or a.startswith("--script=") for a in cmd)


# --- comando ----------------------------------------------------------------

ALL_REQUESTS = [
    ("arp_discover", {"targets": []}),
    ("arp_discover", {"targets": ["192.168.1.0/24"]}),
    ("port_scan", ps()),
    ("port_scan", ps(ports="top100", service=True)),
    ("port_scan", ps(ports="")),
    ("os_detect", {"targets": ["10.0.0.1"]}),
    ("nse_safe", {"targets": ["10.0.0.1"], "ports": "80", "scripts": ["banner"]}),
    ("traceroute", {"targets": ["10.0.0.0/30"]}),
]


@pytest.mark.parametrize("op,params", ALL_REQUESTS)
def test_command_has_no_shell_and_fixed_binary(op, params):
    cmd = build_command(op, params, euid=0)
    assert isinstance(cmd, list) and all(isinstance(a, str) for a in cmd)
    assert cmd[0] == ("arp-scan" if op == "arp_discover" else "nmap")
    for forbidden in ("sh", "bash", "-c", "--script-args", "-iL", "-oN", "-oA"):
        assert forbidden not in cmd
    if op != "arp_discover":
        assert cmd[1:4] == ["-n", "-oX", "-"]


@pytest.mark.parametrize("op,params", ALL_REQUESTS)
def test_user_values_follow_separator(op, params):
    cmd = build_command(op, params, euid=0)
    if params["targets"]:
        sep = cmd.index("--")
        assert cmd[sep + 1:] == [str(t) for t in cmd[sep + 1:]]
        assert all(not a.startswith("-") for a in cmd[sep + 1:])
        assert len(cmd[sep + 1:]) >= 1
        assert all(not a.startswith("-") or a in helper.FIXED_OPTIONS for a in cmd[1:sep])


def test_targets_normalised():
    cmd = build_command("os_detect", {"targets": ["10.0.0.5/24", "10.0.1.1"]}, euid=0)
    assert cmd[cmd.index("--") + 1:] == ["10.0.0.0/24", "10.0.1.1/32"]


def test_port_scan_type_depends_on_euid():
    root = build_command("port_scan", ps(), euid=0)
    user = build_command("port_scan", ps(), euid=1000)
    assert "-sS" in root and "-sT" not in root
    assert "-sT" in user and "-sS" not in user


def test_port_scan_options():
    cmd = build_command("port_scan", ps(ports="22,80-90", service=True), euid=0)
    assert cmd[cmd.index("-p") + 1] == "22,80-90" and "-sV" in cmd
    top = build_command("port_scan", ps(ports="top100"), euid=0)
    assert top[top.index("--top-ports") + 1] == "100" and "-p" not in top
    ping = build_command("port_scan", ps(ports="", service=True), euid=0)
    assert "-sn" in ping and "-sS" not in ping and "-p" not in ping and "-sV" not in ping


def test_os_and_traceroute_options():
    os_cmd = build_command("os_detect", {"targets": ["10.0.0.1"]}, euid=0)
    assert "-O" in os_cmd and "--osscan-limit" in os_cmd
    tr = build_command("traceroute", {"targets": ["10.0.0.1"]}, euid=0)
    assert "--traceroute" in tr and "-sn" in tr


def test_ipv6_targets():
    cmd = build_command("os_detect", {"targets": ["fd00::1"]}, euid=0)
    assert "-6" in cmd
    with pytest.raises(HelperError):
        build_command("os_detect", {"targets": ["fd00::1", "10.0.0.1"]})
    with pytest.raises(HelperError):
        build_command("arp_discover", {"targets": ["fd00::1"]})


# --- main ---------------------------------------------------------------------

def make_fake(tmp_path, body):
    script = tmp_path / "fake"
    script.write_text("#!/bin/sh\n" + body + "\n")
    script.chmod(0o755)
    return {"nmap": str(script), "arp-scan": str(script)}


def run_main(request, which, raw=None):
    """Esegue main con stdin su una pipe che resta aperta (canale di annullamento)."""
    data = raw if raw is not None else json.dumps(request).encode()
    if not data.endswith(b"\n"):
        data += b"\n"
    r, w = os.pipe()
    fcntl.fcntl(w, fcntl.F_SETPIPE_SZ, max(len(data), 65536))
    os.write(w, data)
    stdin = os.fdopen(r, "rb")
    out, err = io.BytesIO(), io.StringIO()
    try:
        rc = main([], stdin=stdin, stdout=out, stderr=err, which=which)
    finally:
        os.close(w)
    return rc, out.getvalue(), err.getvalue()


def test_main_streams_output_and_returns_exit_code(tmp_path):
    which = make_fake(tmp_path, 'echo "<nmaprun $1 $2 $3/>"; exit 3')
    rc, out, err = run_main({"op": "os_detect", "params": {"targets": ["10.0.0.1"]}}, which)
    assert rc == 3
    assert out == b"<nmaprun -n -oX -/>\n"


def test_main_invalid_request_returns_2(tmp_path):
    which = make_fake(tmp_path, "touch ran")
    for raw in (b"not json", b"[]", b'{"op":"os_detect"}',
                b'{"op":"x","params":{}}', b'{"op":"os_detect","params":{"targets":["-x"]}}',
                b'{"op":"os_detect","params":{"targets":["10.0.0.1"]},"more":1}',
                b"\xff\xfe"):
        rc, out, err = run_main(None, which, raw=raw)
        assert rc == 2 and out == b""
        assert err.count("\n") == 1 and err.strip()
    assert not (tmp_path / "ran").exists()


def test_main_oversized_stdin_rejected(tmp_path):
    which = make_fake(tmp_path, "echo ran")
    pad = " " * (helper.MAX_INPUT + 10)
    raw = (json.dumps({"op": "os_detect", "params": {"targets": ["10.0.0.1"]}}) + pad).encode()
    rc, out, err = run_main(None, which, raw=raw)
    assert rc == 2 and out == b""


def test_main_missing_binary(tmp_path):
    rc, out, err = run_main({"op": "os_detect", "params": {"targets": ["10.0.0.1"]}},
                            {"nmap": str(tmp_path / "absent"), "arp-scan": "x"})
    assert rc == 127 and err.strip()


def test_sigterm_kills_child(tmp_path):
    pidfile = tmp_path / "pid"
    which = make_fake(tmp_path, f'sleep 60 &\necho $! > "{pidfile}"\nwait')
    code = (
        "import sys, json\n"
        f"sys.path.insert(0, {str(SRC)!r})\n"
        "from landiscovery.helper import main\n"
        f"sys.exit(main([], which={which!r}))\n"
    )
    req = json.dumps({"op": "os_detect", "params": {"targets": ["10.0.0.1"]}})
    proc = subprocess.Popen([sys.executable, "-c", code], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.stdin.write(req.encode() + b"\n")
    proc.stdin.flush()
    deadline = time.monotonic() + 10
    while not (pidfile.exists() and pidfile.read_text().strip()):
        assert time.monotonic() < deadline, proc.stderr.read()
        time.sleep(0.05)
    grandchild = int(pidfile.read_text())
    os.kill(grandchild, 0)
    proc.send_signal(signal.SIGTERM)
    assert proc.wait(timeout=10) == 143
    proc.stdin.close()
    deadline = time.monotonic() + 5
    while True:
        try:
            os.kill(grandchild, 0)
        except ProcessLookupError:
            break
        # zombie reaped by init: check state
        stat = Path(f"/proc/{grandchild}/stat")
        if stat.exists() and stat.read_text().split(")")[-1].split()[0] == "Z":
            break
        assert time.monotonic() < deadline, "child still alive"
        time.sleep(0.05)


def test_sigterm_escalates_to_sigkill(tmp_path):
    pidfile = tmp_path / "pid"
    which = make_fake(tmp_path, f"trap '' TERM\necho $$ > \"{pidfile}\"\n"
                                "while :; do sleep 0.1; done")
    code = (
        "import sys\n"
        f"sys.path.insert(0, {str(SRC)!r})\n"
        "from landiscovery.helper import main\n"
        f"sys.exit(main([], which={which!r}))\n"
    )
    req = json.dumps({"op": "traceroute", "params": {"targets": ["10.0.0.1"]}})
    proc = subprocess.Popen([sys.executable, "-c", code], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.stdin.write(req.encode() + b"\n")
    proc.stdin.flush()
    deadline = time.monotonic() + 10
    while not (pidfile.exists() and pidfile.read_text().strip()):
        assert time.monotonic() < deadline
        time.sleep(0.05)
    child = int(pidfile.read_text())
    t0 = time.monotonic()
    proc.send_signal(signal.SIGTERM)
    assert proc.wait(timeout=10) == 143
    proc.stdin.close()
    assert time.monotonic() - t0 < 6
    stat = Path(f"/proc/{child}/stat")
    assert not stat.exists() or stat.read_text().split(")")[-1].split()[0] == "Z"


# --- indurimento -------------------------------------------------------------------

def test_deeply_nested_json_exits_2(tmp_path):
    which = make_fake(tmp_path, "touch ran")
    rc, out, err = run_main(None, which, raw=b"[" * 60000)
    assert rc == 2 and out == b""
    assert err.count("\n") == 1 and err.strip()
    raw = b'{"op":"os_detect","params":' + b'{"a":' * 5000 + b"1" + b"}" * 5001
    rc, out, err = run_main(None, which, raw=raw)
    assert rc == 2 and err.count("\n") == 1
    assert not (tmp_path / "ran").exists()


@pytest.mark.parametrize("target", ["10.0.0.0/7", "0.0.0.0/0", "128.0.0.0/1",
                                    "10.0.0.0/7, 192.168.1.1"])
def test_ipv4_wider_than_slash8_rejected_by_helper(target):
    with pytest.raises(HelperError):
        build_command("os_detect", {"targets": [target]}, euid=0)
    with pytest.raises(HelperError):
        build_command("arp_discover", {"targets": [target]}, euid=0)


def test_ipv4_slash8_still_accepted():
    cmd = build_command("os_detect", {"targets": ["10.0.0.0/8"]}, euid=0)
    assert cmd[-1] == "10.0.0.0/8"


def _value_part(err):
    line = err.strip()
    assert line.startswith("landiscovery-helper: ")
    return line[len("landiscovery-helper: "):]


@pytest.mark.parametrize("params", [
    {"targets": ["10.0.0.1-" + "9" * 500]},
    {"targets": ["$" * 500]},
    {"targets": ["10.0.0.1"], "x" * 500: 1},
])
def test_long_target_error_message_truncated(tmp_path, params):
    which = make_fake(tmp_path, "touch ran")
    rc, out, err = run_main({"op": "os_detect", "params": params}, which)
    assert rc == 2 and err.count("\n") == 1
    # descrizione breve + valore utente al massimo di 80 caratteri
    assert len(_value_part(err)) <= 80 + 40
    assert "..." in err


def test_long_values_truncated_in_build_command():
    long = "a" * 300
    for op, params in (
        (long, {"targets": ["10.0.0.1"]}),
        ("port_scan", ps(ports=long)),
        ("nse_safe", {"targets": ["10.0.0.1"], "ports": "80", "scripts": [long]}),
    ):
        with pytest.raises(HelperError) as info:
            build_command(op, params, euid=0)
        assert len(str(info.value)) <= 80 + 40
        assert long not in str(info.value)


def test_short_values_not_truncated():
    with pytest.raises(HelperError) as info:
        build_command("os_detect", {"targets": ["10.0.0.1;id"]}, euid=0)
    assert "10.0.0.1;id" in str(info.value)


PROBE = r"""#!{python}
import ctypes, os, sys
libc = ctypes.CDLL(None, use_errno=True)
sig = ctypes.c_int(-1)
libc.prctl(2, ctypes.byref(sig), 0, 0, 0)
with open({out!r} + ".tmp", "w") as f:
    f.write(os.getcwd() + "\n" + str(sig.value) + "\n" + str(os.getppid()) + "\n")
os.rename({out!r} + ".tmp", {out!r})
"""


def test_child_has_cwd_root_and_pdeathsig(tmp_path, monkeypatch):
    out = tmp_path / "probe.out"
    script = tmp_path / "probe"
    script.write_text(PROBE.format(python=sys.executable, out=str(out)))
    script.chmod(0o755)
    monkeypatch.chdir(tmp_path)
    which = {"nmap": str(script), "arp-scan": str(script)}
    rc, _, err = run_main({"op": "os_detect", "params": {"targets": ["10.0.0.1"]}}, which)
    assert rc == 0, err
    cwd, sig, ppid = out.read_text().split()
    assert cwd == "/"
    assert int(sig) == signal.SIGKILL
    assert int(ppid) == os.getpid()


def _alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    stat = Path(f"/proc/{pid}/stat")
    try:
        state = stat.read_text().rsplit(")", 1)[1].split()[0]
    except (OSError, IndexError):
        return False
    return state != "Z"


def wait_dead(pids, timeout=8.0):
    deadline = time.monotonic() + timeout
    while any(_alive(p) for p in pids):
        assert time.monotonic() < deadline, f"still alive: {[p for p in pids if _alive(p)]}"
        time.sleep(0.02)


def wait_file(path, proc=None, timeout=10.0):
    deadline = time.monotonic() + timeout
    while not path.exists():
        assert time.monotonic() < deadline, proc.stderr.read() if proc else "timeout"
        if proc is not None:
            assert proc.poll() is None, proc.stderr.read()
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
{tail}
"""


def make_family(tmp_path, ignore_term=False, tail="time.sleep(60)"):
    pids = tmp_path / "pids"
    script = tmp_path / "family"
    trap = "signal.signal(signal.SIGTERM, signal.SIG_IGN)" if ignore_term else ""
    script.write_text(FAMILY.format(python=sys.executable, out=str(pids), trap=trap,
                                    tail=tail))
    script.chmod(0o755)
    return {"nmap": str(script), "arp-scan": str(script)}, pids


def helper_proc(which, **kw):
    code = (
        "import sys\n"
        f"sys.path.insert(0, {str(SRC)!r})\n"
        "from landiscovery.helper import main\n"
        f"sys.exit(main([], which={which!r}))\n"
    )
    return subprocess.Popen([sys.executable, "-c", code], stdin=subprocess.PIPE,
                            stdout=kw.get("stdout", subprocess.PIPE),
                            stderr=subprocess.PIPE)


REQ = (json.dumps({"op": "os_detect", "params": {"targets": ["10.0.0.1"]}}) + "\n").encode()


@pytest.mark.parametrize("how", ["cancel", "eof"])
def test_helper_stdin_channel_stops_family(tmp_path, how):
    which, pidfile = make_family(tmp_path)
    proc = helper_proc(which)
    proc.stdin.write(REQ)
    proc.stdin.flush()
    pids = wait_file(pidfile, proc)
    assert all(_alive(p) for p in pids)
    if how == "cancel":
        proc.stdin.write(b"cancel\n")
        proc.stdin.flush()
    else:
        proc.stdin.close()
    assert proc.wait(timeout=10) == 143
    wait_dead(pids)
    if not proc.stdin.closed:
        proc.stdin.close()


def test_helper_ignores_unknown_lines(tmp_path):
    which, pidfile = make_family(tmp_path, tail="time.sleep(0.5)")
    proc = helper_proc(which)
    proc.stdin.write(REQ + b"hello\n")
    proc.stdin.flush()
    assert proc.wait(timeout=10) == 0
    proc.stdin.close()


def test_eof_right_after_request_cancels_quickly(tmp_path):
    which = make_fake(tmp_path, "exec sleep 60")
    proc = helper_proc(which)
    t0 = time.monotonic()
    proc.stdin.write(REQ)
    proc.stdin.close()
    assert proc.wait(timeout=10) == 143
    assert time.monotonic() - t0 < 5


def test_cancel_escalates_to_sigkill(tmp_path):
    which, pidfile = make_family(tmp_path, ignore_term=True)
    proc = helper_proc(which)
    proc.stdin.write(REQ)
    proc.stdin.flush()
    pids = wait_file(pidfile, proc)
    t0 = time.monotonic()
    proc.stdin.write(b"cancel\n")
    proc.stdin.flush()
    assert proc.wait(timeout=10) == 143
    assert 1.5 <= time.monotonic() - t0 < 6
    wait_dead(pids)
    proc.stdin.close()


def test_broken_stdout_stops_family(tmp_path):
    which, pidfile = make_family(
        tmp_path, tail="while True:\n    sys.stdout.write('x' * 4096 + '\\n'); "
                       "sys.stdout.flush(); time.sleep(0.01)")
    r, w = os.pipe()
    proc = helper_proc(which, stdout=w)
    os.close(w)
    proc.stdin.write(REQ)
    proc.stdin.flush()
    pids = wait_file(pidfile, proc)
    os.read(r, 100)
    os.close(r)
    assert proc.wait(timeout=10) == 143
    wait_dead(pids)
    proc.stdin.close()


def test_helper_sigkill_kills_child_via_pdeathsig(tmp_path):
    # PR_SET_PDEATHSIG vale per il figlio diretto (anche dopo exec), non per
    # i suoi discendenti: il figlio finto quindi non ne crea.
    pidfile = tmp_path / "pid"
    which = make_fake(tmp_path, f'echo $$ > "{pidfile}.tmp"; mv "{pidfile}.tmp" "{pidfile}"\n'
                                "exec sleep 60")
    proc = helper_proc(which)
    proc.stdin.write(REQ)
    proc.stdin.flush()
    (leader,) = wait_file(pidfile, proc)
    assert _alive(leader)
    proc.kill()
    proc.wait(timeout=10)
    wait_dead([leader])
    proc.stdin.close()


def test_leftover_group_killed_after_normal_exit(tmp_path):
    pidfile = tmp_path / "pid"
    which = make_fake(tmp_path, f'sleep 60 >/dev/null 2>&1 &\necho $! > "{pidfile}"\n'
                                'echo "<done/>"\nexit 0')
    rc, out, err = run_main({"op": "os_detect", "params": {"targets": ["10.0.0.1"]}}, which)
    assert rc == 0 and out == b"<done/>\n"
    wait_dead([int(pidfile.read_text())])


def test_leftover_holding_stdout_does_not_hang(tmp_path):
    pidfile = tmp_path / "pid"
    which = make_fake(tmp_path, f'sleep 60 &\necho $! > "{pidfile}"\necho "<done/>"\nexit 0')
    t0 = time.monotonic()
    rc, out, err = run_main({"op": "os_detect", "params": {"targets": ["10.0.0.1"]}}, which)
    assert rc == 0 and out == b"<done/>\n"
    assert time.monotonic() - t0 < 5
    wait_dead([int(pidfile.read_text())])


# --- packaging ------------------------------------------------------------------

def test_policy_xml():
    tree = ET.parse(ROOT / "packaging" / "org.syslinuxos.landiscovery.policy")
    actions = tree.getroot().findall("action")
    assert len(actions) == 1
    action = actions[0]
    assert action.get("id") == "org.syslinuxos.landiscovery.run"
    annotations = {a.get("key"): a.text for a in action.findall("annotate")}
    assert annotations == {
        "org.freedesktop.policykit.exec.path": "/usr/lib/landiscovery/landiscovery-helper"}
    d = action.find("defaults")
    assert d.find("allow_any").text == "auth_admin"
    assert d.find("allow_inactive").text == "auth_admin"
    assert d.find("allow_active").text == "auth_admin_keep"
    lang = "{http://www.w3.org/XML/1998/namespace}lang"
    for tag in ("description", "message"):
        els = action.findall(tag)
        assert {e.get(lang) for e in els} == {None, "it"}


def test_helper_script():
    script = ROOT / "packaging" / "landiscovery-helper"
    assert os.stat(script).st_mode & 0o777 == 0o755
    text = script.read_text()
    assert text.startswith("#!/usr/bin/python3 -I\n")
    assert "/usr/share/landiscovery" in text
    assert ".." not in text and "__file__" not in text and "src" not in text
    code = ("import runpy, sys\n"
            f"sys.path.insert(0, {str(SRC)!r})\n"
            f"runpy.run_path({str(script)!r}, run_name='__main__')\n")
    out = subprocess.run([sys.executable, "-c", code], input=b"bad\n",
                         capture_output=True, timeout=10)
    assert out.returncode == 2 and out.stderr.strip()
