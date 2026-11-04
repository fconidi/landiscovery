"""Presentation models for history, comparison and security findings."""
from __future__ import annotations

from dataclasses import dataclass

from .compare import Diff
from .models import Finding, ScanResult


@dataclass
class DiffRow:
    state: str
    ip: str
    hostname: str
    detail: str


class DiffRows:
    def __init__(self, diff: Diff):
        self.comparable = diff.comparable
        self.reasons = list(diff.reasons)
        self.rows = []
        if diff.comparable:
            self.rows.extend(DiffRow("new", h.ip, h.hostname, "") for h in diff.new_hosts)
            self.rows.extend(DiffRow("gone", h.ip, h.hostname, "") for h in diff.gone_hosts)
            self.rows.extend(DiffRow("changed", c.new.ip, c.new.hostname,
                                     ", ".join(c.fields)) for c in diff.changed)


def sorted_findings(result: ScanResult) -> list[Finding]:
    order = {"critical": 0, "warning": 1, "info": 2}
    return sorted((finding for host in result.hosts for finding in host.findings),
                  key=lambda f: (order.get(f.severity, 3), f.host, f.title))
