import json
import sqlite3
from dataclasses import asdict

import pytest

from landiscovery.models import (Coverage, DiscoveredService, Edge, Finding, Host,
                                 Node, Port, ScanResult, Topology)
from landiscovery.store import Store


def sample():
    coverage = Coverage(["192.168.1.0/24"], "full", "22,80", True, True, True,
                        True, True, True, True, True)
    return ScanResult(started=1.0, finished=2.0, targets=coverage.targets,
                      profile="full", status="done", complete=True,
                      hosts=[Host("192.168.1.2", "AA:BB:CC:DD:EE:FF", "Vendor", "pc",
                                  1.2, "Linux", [Port(22, service="ssh")],
                                  [Finding("192.168.1.2", "info", "title")], ["ssh"])],
                      discovered=[DiscoveredService("192.168.1.2", "mdns", "pc", "")],
                      topology=Topology([Node("a", "PC", "host", "192.168.1.0/24")],
                                        [Edge("a", "b")]), coverage=coverage,
                      warnings=["warning"])


def test_save_and_load_roundtrip(tmp_path):
    store = Store(tmp_path / "history.db")
    scan = sample()
    scan_id = store.save_scan(scan)
    loaded = store.get_scan(scan_id)
    assert loaded == ScanResult(**{**asdict(scan), "id": scan_id,
                                  "hosts": scan.hosts, "discovered": scan.discovered,
                                  "topology": scan.topology, "coverage": scan.coverage})
    assert store.list_scans()[0].host_count == 1
    assert store.list_scans()[0].complete


def test_store_roundtrip_discovery_topology_coverage(tmp_path):
    store = Store(tmp_path / "history.db")
    loaded = store.get_scan(store.save_scan(sample()))
    assert loaded.discovered[0].kind == "mdns"
    assert loaded.topology.inferred is True
    assert loaded.coverage.security_checks is True
    assert loaded.warnings == ["warning"]


def test_migrates_old_schema_keeping_scans(tmp_path):
    path = tmp_path / "old.db"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE schema_version (version INTEGER NOT NULL)")
        db.execute("INSERT INTO schema_version VALUES (1)")
        db.execute("CREATE TABLE scans (id INTEGER PRIMARY KEY, result TEXT NOT NULL)")
        db.execute("INSERT INTO scans(result) VALUES (?)", (json.dumps({
            "started": 1, "targets": ["192.168.1.0/24"], "hosts": [{"ip": "192.168.1.2"}],
            "status": "done"}),))
    store = Store(path)
    assert store.get_scan(1).hosts[0].ip == "192.168.1.2"
    assert store.get_scan(1).complete is False
    assert store.list_devices() == []
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT version FROM schema_version").fetchone()[0] == 2


def test_delete_scan(tmp_path):
    store = Store(tmp_path / "history.db")
    scan_id = store.save_scan(sample())
    store.delete_scan(scan_id)
    assert store.list_scans() == []
    with pytest.raises(KeyError):
        store.get_scan(scan_id)


def test_device_by_mac_survives_ip_change(tmp_path):
    store = Store(tmp_path / "history.db")
    key = "AA:BB:CC:DD:EE:FF"
    store.set_device(key, "Printer", "Office", ["shared"])
    new_host = Host("192.168.1.99", mac=key)
    assert store.get_device(new_host.key).name == "Printer"
    assert store.list_devices()[0].tags == ["shared"]
    store.set_device(key, "Printer 2", "Office", [])
    assert store.get_device(key).name == "Printer 2"
