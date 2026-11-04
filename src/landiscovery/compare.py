"""Conservative comparison of two network scans."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from .models import Host, ScanResult


@dataclass
class HostChange:
    key: str
    old: Host
    new: Host
    fields: list[str]


@dataclass
class Diff:
    comparable: bool
    reasons: list[str] = field(default_factory=list)
    new_hosts: list[Host] = field(default_factory=list)
    gone_hosts: list[Host] = field(default_factory=list)
    changed: list[HostChange] = field(default_factory=list)


def _networks(targets: list[str]) -> set[str]:
    networks = set()
    for target in targets:
        try:
            networks.add(str(ipaddress.ip_network(target, strict=False)))
        except ValueError:
            networks.add(target)
    return networks


def _discovery_type(scan: ScanResult) -> str:
    """The engine uses ARP plus nmap on privileged IPv4, nmap otherwise."""
    cov = scan.coverage
    targets = cov.targets if cov else scan.targets
    return "arp+nmap" if cov and cov.privileged and all(
        ":" not in target for target in targets) else "nmap"


def _fields(old: Host, new: Host, a: ScanResult, b: ScanResult) -> list[str]:
    fields = []
    for name in ("ip", "hostname"):
        if getattr(old, name) != getattr(new, name):
            fields.append(name)
    ca, cb = a.coverage, b.coverage
    if ca and cb and ca.ports and ca.ports == cb.ports:
        # Service/version data are meaningful only if collected in both scans.
        def ports(host, services):
            return {(p.number, p.proto): (p.state, p.service if services else "",
                                           p.version if services else "")
                    for p in host.ports}
        if ports(old, ca.service_detect and cb.service_detect) != ports(
                new, ca.service_detect and cb.service_detect):
            fields.append("ports")
        if ca.service_detect and cb.service_detect and old.services != new.services:
            fields.append("services")
    if ca and cb and ca.os_detect and cb.os_detect and old.os != new.os:
        fields.append("os")
    return fields


def compare_scans(old: ScanResult, new: ScanResult) -> Diff:
    reasons = []
    if not old.complete or not new.complete:
        reasons.append("both scans must be complete")
    if old.coverage is None or new.coverage is None:
        reasons.append("scan coverage is unavailable")
    else:
        a, b = old.coverage, new.coverage
        if _networks(a.targets) != _networks(b.targets):
            reasons.append("target networks differ")
        if a.privileged != b.privileged:
            reasons.append("privilege modes differ")
        if _discovery_type(old) != _discovery_type(new):
            reasons.append("host discovery methods differ")
    result = Diff(comparable=not reasons, reasons=reasons)
    if reasons:
        return result
    before = {host.key: host for host in old.hosts}
    after = {host.key: host for host in new.hosts}
    result.new_hosts = [host for key, host in after.items() if key not in before]
    result.gone_hosts = [host for key, host in before.items() if key not in after]
    result.changed = [HostChange(key, before[key], after[key], fields)
                      for key in before.keys() & after.keys()
                      if (fields := _fields(before[key], after[key], old, new))]
    result.changed.sort(key=lambda change: change.key)
    return result
