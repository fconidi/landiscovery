"""Persistent scan history and user-owned device notes."""
from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, dataclass
from pathlib import Path

from .models import (Coverage, DiscoveredService, Edge, Finding, Host, Node,
                     Port, ScanResult, Topology)

SCHEMA_VERSION = 2


@dataclass
class ScanSummary:
    id: int
    started: float
    finished: float | None
    targets: list[str]
    profile: str
    host_count: int
    status: str
    complete: bool


@dataclass
class Device:
    key: str
    name: str
    note: str
    tags: list[str]


def _decode(raw: str, scan_id: int) -> ScanResult:
    data = json.loads(raw)
    data["hosts"] = [Host(**{**h,
                              "ports": [Port(**p) for p in h.get("ports", [])],
                              "findings": [Finding(**f) for f in h.get("findings", [])]})
                     for h in data.get("hosts", [])]
    data["discovered"] = [DiscoveredService(**d) for d in data.get("discovered", [])]
    if data.get("topology") is not None:
        t = data["topology"]
        data["topology"] = Topology(
            nodes=[Node(**n) for n in t.get("nodes", [])],
            edges=[Edge(**e) for e in t.get("edges", [])],
            inferred=t.get("inferred", True))
    if data.get("coverage") is not None:
        data["coverage"] = Coverage(**data["coverage"])
    data["id"] = scan_id
    return ScanResult(**data)


class Store:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
            row = db.execute("SELECT version FROM schema_version").fetchone()
            if row is None:
                db.execute("INSERT INTO schema_version VALUES (?)", (SCHEMA_VERSION,))
            elif row[0] > SCHEMA_VERSION or row[0] < 1:
                raise ValueError(f"unsupported database schema: {row[0]}")
            db.execute("CREATE TABLE IF NOT EXISTS scans ("
                       "id INTEGER PRIMARY KEY, result TEXT NOT NULL)")
            if row is not None and row[0] < 2:
                db.execute("UPDATE schema_version SET version = 2")
            db.execute("CREATE TABLE IF NOT EXISTS devices ("
                       "key TEXT PRIMARY KEY, name TEXT NOT NULL, "
                       "note TEXT NOT NULL, tags TEXT NOT NULL)")

    def _connect(self):
        return sqlite3.connect(self.path)

    def save_scan(self, result: ScanResult) -> int:
        payload = asdict(result)
        payload["id"] = None
        with self._connect() as db:
            cursor = db.execute("INSERT INTO scans(result) VALUES (?)",
                                (json.dumps(payload, ensure_ascii=False),))
            return int(cursor.lastrowid)

    def list_scans(self) -> list[ScanSummary]:
        with self._connect() as db:
            rows = db.execute("SELECT id, result FROM scans ORDER BY id DESC").fetchall()
        out = []
        for scan_id, raw in rows:
            data = json.loads(raw)
            out.append(ScanSummary(scan_id, data.get("started", 0.0),
                                   data.get("finished"), data.get("targets", []),
                                   data.get("profile", ""), len(data.get("hosts", [])),
                                   data.get("status", "running"), data.get("complete", False)))
        return out

    def get_scan(self, scan_id: int) -> ScanResult:
        with self._connect() as db:
            row = db.execute("SELECT result FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row is None:
            raise KeyError(scan_id)
        return _decode(row[0], scan_id)

    def delete_scan(self, scan_id: int) -> None:
        with self._connect() as db:
            db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))

    def set_device(self, key: str, name: str, note: str, tags: list[str]) -> None:
        with self._connect() as db:
            db.execute("INSERT INTO devices VALUES (?, ?, ?, ?) "
                       "ON CONFLICT(key) DO UPDATE SET name=excluded.name, "
                       "note=excluded.note, tags=excluded.tags",
                       (key, name, note, json.dumps(tags, ensure_ascii=False)))

    def delete_device(self, key: str) -> None:
        with self._connect() as db:
            db.execute("DELETE FROM devices WHERE key = ?", (key,))

    def get_device(self, key: str) -> Device | None:
        with self._connect() as db:
            row = db.execute("SELECT key, name, note, tags FROM devices WHERE key = ?",
                             (key,)).fetchone()
        return Device(row[0], row[1], row[2], json.loads(row[3])) if row else None

    def list_devices(self) -> list[Device]:
        with self._connect() as db:
            rows = db.execute("SELECT key, name, note, tags FROM devices ORDER BY key").fetchall()
        return [Device(key, name, note, json.loads(tags)) for key, name, note, tags in rows]
