"""Ricerca del produttore a partire dal MAC."""
from __future__ import annotations

import re
from pathlib import Path

DEFAULT_PATHS = [
    Path("/usr/share/arp-scan/ieee-oui.txt"),
    Path("/usr/share/nmap/nmap-mac-prefixes"),
]

_NON_HEX = re.compile(r"[^0-9A-Fa-f]")


class OuiDatabase:
    """Carica i file di prefissi OUI (formati arp-scan e nmap)."""

    def __init__(self, paths: list[Path] | None = None):
        self._table: dict[str, str] = {}
        for path in (DEFAULT_PATHS if paths is None else paths):
            self._load(Path(path))

    def _load(self, path: Path) -> None:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            prefix = _NON_HEX.sub("", parts[0]).upper()
            if len(prefix) != 6 or _NON_HEX.search(parts[0]):
                continue
            self._table.setdefault(prefix, parts[1].strip())

    def lookup(self, mac: str) -> str:
        digits = _NON_HEX.sub("", mac or "").upper()
        if len(digits) < 6:
            return ""
        return self._table.get(digits[:6], "")
