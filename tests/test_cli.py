import json
from pathlib import Path

from landiscovery import cli
from landiscovery.engine import EngineError
from landiscovery.models import Coverage, Host, ScanResult
from landiscovery.store import Store


def scan(hosts=None, complete=True):
    targets = ["192.168.1.0/24"]
    return ScanResult(started=1, finished=2, targets=targets, profile="quick",
                      hosts=hosts or [], status="done", complete=complete,
                      coverage=Coverage(targets, "quick", "top100", False, False,
                                        False, False, False, False, False, False))


def test_scan_json_output(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    monkeypatch.setattr(cli, "ScanEngine", lambda: type("Engine", (), {
        "scan": lambda self, *_: scan([Host("192.168.1.2")])})())
    assert cli.main(["scan", "192.168.1.0/24", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["hosts"][0]["ip"] == "192.168.1.2"
    assert Store(cli.default_store_path()).list_scans()[0].host_count == 1


def test_invalid_target_exits_2(capsys):
    assert cli.main(["scan", "1.2.3.4;rm", "--yes"]) == 2
    assert "invalid target" in capsys.readouterr().err


def test_public_range_requires_yes(capsys):
    assert cli.main(["scan", "8.8.8.8"]) == 2
    assert "outside private" in capsys.readouterr().err


def test_history_lists_saved_scans(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    Store(cli.default_store_path()).save_scan(scan([Host("192.168.1.2")]))
    assert cli.main(["history"]) == 0
    assert "quick\t1" in capsys.readouterr().out


def test_compare_prints_diff(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    store = Store(cli.default_store_path())
    a = store.save_scan(scan([Host("192.168.1.2")]))
    b = store.save_scan(scan([Host("192.168.1.3")]))
    assert cli.main(["compare", str(a), str(b)]) == 0
    output = capsys.readouterr().out
    assert "new\t192.168.1.3" in output and "gone\t192.168.1.2" in output


def test_missing_tool_exits_1(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    def fail(self, *_):
        raise EngineError("nmap is not available")
    monkeypatch.setattr(cli.ScanEngine, "scan", fail)
    assert cli.main(["scan", "192.168.1.0/24"]) == 1
    assert "nmap" in capsys.readouterr().err


def test_snmp_community_option_not_accepted(capsys):
    assert cli.main(["scan", "192.168.1.1", "--snmp-community", "secret"]) == 2


def test_snmp_community_from_stdin_not_in_output(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    profile = type("Profile", (), {"snmp": True})()
    monkeypatch.setattr(cli, "ProfileStore", lambda _: type("Profiles", (), {
        "load": lambda self: {"snmp": profile}})())
    monkeypatch.setattr(cli.sys, "stdin", type("Input", (), {
        "readline": lambda self: "private-value\n"})())
    seen = []
    def run(self, targets, profile, options):
        seen.append(options.snmp_community)
        return scan()
    monkeypatch.setattr(cli.ScanEngine, "scan", run)
    assert cli.main(["scan", "192.168.1.0/24", "--profile", "snmp",
                     "--snmp-community-stdin"]) == 0
    output = capsys.readouterr()
    assert seen == ["private-value"]
    assert "private-value" not in output.out + output.err
    assert "private-value" not in Path(cli.default_store_path()).read_bytes().decode(
        "utf-8", errors="ignore")


def test_compare_not_comparable_warns(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    store = Store(cli.default_store_path())
    a = store.save_scan(scan([Host("192.168.1.2")]))
    b = store.save_scan(scan([], complete=False))
    assert cli.main(["compare", str(a), str(b)]) == 0
    output = capsys.readouterr()
    assert "unreliable" in output.err
    assert "gone" not in output.out
