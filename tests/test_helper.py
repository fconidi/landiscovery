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
    stdin = io.BytesIO(raw if raw is not None else json.dumps(request).encode())
    out, err = io.BytesIO(), io.StringIO()
    rc = main([], stdin=stdin, stdout=out, stderr=err, which=which)
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
    proc.stdin.write(req.encode())
    proc.stdin.close()
    deadline = time.monotonic() + 10
    while not (pidfile.exists() and pidfile.read_text().strip()):
        assert time.monotonic() < deadline, proc.stderr.read()
        time.sleep(0.05)
    grandchild = int(pidfile.read_text())
    os.kill(grandchild, 0)
    proc.send_signal(signal.SIGTERM)
    assert proc.wait(timeout=10) == 143
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
    proc.stdin.write(req.encode())
    proc.stdin.close()
    deadline = time.monotonic() + 10
    while not (pidfile.exists() and pidfile.read_text().strip()):
        assert time.monotonic() < deadline
        time.sleep(0.05)
    child = int(pidfile.read_text())
    t0 = time.monotonic()
    proc.send_signal(signal.SIGTERM)
    assert proc.wait(timeout=10) == 143
    assert time.monotonic() - t0 < 6
    stat = Path(f"/proc/{child}/stat")
    assert not stat.exists() or stat.read_text().split(")")[-1].split()[0] == "Z"


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
    out = subprocess.run([sys.executable, str(script)], input=b"bad",
                         capture_output=True, timeout=10)
    assert out.returncode == 2 and out.stderr.strip()
