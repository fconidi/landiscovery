"""Modelli di dati condivisi."""
from __future__ import annotations

from dataclasses import dataclass, field

SEVERITIES = frozenset({"info", "warning", "critical"})


@dataclass
class Port:
    number: int
    proto: str = "tcp"
    state: str = "open"
    service: str = ""
    version: str = ""


@dataclass
class Finding:
    host: str
    severity: str
    title: str
    detail: str = ""

    def __post_init__(self):
        if self.severity not in SEVERITIES:
            raise ValueError(f"gravità non valida: {self.severity!r}")


@dataclass
class Host:
    ip: str
    mac: str | None = None
    vendor: str = ""
    hostname: str = ""
    latency_ms: float | None = None
    os: str = ""
    ports: list[Port] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    services: list[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return self.mac or self.ip


@dataclass
class ScanResult:
    id: int | None = None
    started: float = 0.0
    finished: float | None = None
    targets: list[str] = field(default_factory=list)
    profile: str = ""
    hosts: list[Host] = field(default_factory=list)
    status: str = "running"
    reduced: bool = False
