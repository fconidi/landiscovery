"""Profili di scansione predefiniti e personalizzati."""
from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import asdict, dataclass, fields
from pathlib import Path

_PORTS_RE = re.compile(r"^[0-9]+([,\-][0-9]+)*$")
_NAME_RE = re.compile(r"^[A-Za-z0-9 _\-]{1,40}$")


def _validate_ports(ports: str) -> None:
    if not isinstance(ports, str):
        raise ValueError("porte non valide")
    if ports in ("", "top100"):
        return
    if not _PORTS_RE.fullmatch(ports):
        raise ValueError(f"porte non valide: {ports!r}")
    for part in ports.split(","):
        nums = [int(n) for n in part.split("-")]
        if any(n < 1 or n > 65535 for n in nums):
            raise ValueError(f"porta fuori intervallo: {part!r}")
        if len(nums) == 2 and nums[0] > nums[1]:
            raise ValueError(f"intervallo non crescente: {part!r}")
        if len(nums) > 2:
            raise ValueError(f"intervallo non valido: {part!r}")


@dataclass
class Profile:
    name: str
    ports: str
    os_detect: bool = False
    service_detect: bool = False
    traceroute: bool = False
    discovery: bool = False
    security_checks: bool = False
    builtin: bool = False

    def __post_init__(self):
        if not isinstance(self.name, str) or not _NAME_RE.fullmatch(self.name):
            raise ValueError(f"nome profilo non valido: {self.name!r}")
        _validate_ports(self.ports)


BUILTIN: dict[str, Profile] = {
    "quick": Profile("quick", "top100", builtin=True),
    "full": Profile("full", "1-65535", os_detect=True, service_detect=True, builtin=True),
    "ping": Profile("ping", "", builtin=True),
    "security": Profile("security", "top100", service_detect=True,
                        security_checks=True, builtin=True),
}


def default_profiles_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME")
    root = Path(base) if base else Path.home() / ".config"
    return root / "landiscovery" / "profiles.json"


class ProfileStore:
    def __init__(self, path: Path):
        self.path = Path(path)

    def _load_custom(self) -> dict[str, Profile]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        if not isinstance(data, list):
            return {}
        names = {f.name for f in fields(Profile)} - {"builtin"}
        out: dict[str, Profile] = {}
        for item in data:
            if not isinstance(item, dict):
                continue
            try:
                prof = Profile(**{k: v for k, v in item.items() if k in names}, builtin=False)
            except (TypeError, ValueError):
                continue
            if prof.name not in BUILTIN:
                out[prof.name] = prof
        return out

    def _write(self, custom: dict[str, Profile]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = [{k: v for k, v in asdict(p).items() if k != "builtin"}
                   for p in custom.values()]
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".profiles-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2)
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def load(self) -> dict[str, Profile]:
        result = dict(BUILTIN)
        result.update(self._load_custom())
        return result

    def save(self, profile: Profile) -> None:
        if profile.name in BUILTIN:
            raise ValueError(f"nome riservato a un profilo predefinito: {profile.name!r}")
        custom = self._load_custom()
        custom[profile.name] = Profile(**{**asdict(profile), "builtin": False})
        self._write(custom)

    def delete(self, name: str) -> None:
        if name in BUILTIN:
            raise ValueError("i profili predefiniti non si possono cancellare")
        custom = self._load_custom()
        if custom.pop(name, None) is not None:
            self._write(custom)
