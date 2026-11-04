"""Validazione dei target di scansione e dei relativi limiti."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

REASON_PUBLIC = "target outside private address ranges"
REASON_WIDE_V4 = "IPv4 network wider than /16"
REASON_WIDE_V6 = "IPv6 network wider than /112 is not allowed"

_SEPARATORS = re.compile(r"[,\s]+")
_PRIVATE_V4 = [ipaddress.ip_network(n) for n in
               ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                "169.254.0.0/16", "127.0.0.0/8")]
_PRIVATE_V6 = [ipaddress.ip_network(n) for n in
               ("fc00::/7", "fe80::/10", "::1/128")]


class TargetError(ValueError):
    """Target non valido."""


@dataclass
class ScopeCheck:
    needs_confirmation: bool = False
    reasons: list[str] = field(default_factory=list)
    allowed: bool = True


def parse_targets(text: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    tokens = [t for t in _SEPARATORS.split(text or "") if t]
    if not tokens:
        raise TargetError("no target given")
    nets = []
    for tok in tokens:
        if tok.startswith("-"):
            raise TargetError(f"invalid target: {tok!r}")
        try:
            nets.append(ipaddress.ip_network(tok, strict=False))
        except ValueError as exc:
            raise TargetError(f"invalid target: {tok!r}") from exc
    return nets


def _is_private(net) -> bool:
    ranges = _PRIVATE_V4 if net.version == 4 else _PRIVATE_V6
    return any(net.subnet_of(r) for r in ranges)


def check_scope(nets) -> ScopeCheck:
    res = ScopeCheck()
    for net in nets:
        if not _is_private(net) and REASON_PUBLIC not in res.reasons:
            res.reasons.append(REASON_PUBLIC)
            res.needs_confirmation = True
        if net.version == 4 and net.prefixlen < 16 and REASON_WIDE_V4 not in res.reasons:
            res.reasons.append(REASON_WIDE_V4)
            res.needs_confirmation = True
        if net.version == 6 and net.prefixlen < 112:
            if REASON_WIDE_V6 not in res.reasons:
                res.reasons.append(REASON_WIDE_V6)
            res.allowed = False
    return res
