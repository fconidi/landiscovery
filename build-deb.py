#!/usr/bin/python3
"""Build a Debian package from an explicit product-file list."""
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

MODULES = ("__init__.py", "actions.py", "app.py", "cli.py", "compare.py",
           "discovery.py", "engine.py", "export.py", "helper.py", "i18n.py",
           "mapview.py", "models.py", "nmapxml.py", "oui.py", "profiles.py",
           "runner.py", "security.py", "store.py", "targets.py", "topology.py",
           "views.py", "icon.svg", "style.css")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Build LAN Discovery for Debian")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    output = args.output_dir.expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    source = Path(__file__).resolve().parent
    package = source / "src/landiscovery"
    match = re.search(r'__version__ = "([^\"]+)"',
                      (package / "__init__.py").read_text(encoding="utf-8"))
    if match is None:
        raise ValueError("package version is missing")
    version = match.group(1)
    with tempfile.TemporaryDirectory(prefix="package-", dir=output) as tmp:
        root = Path(tmp)

        def install(origin: Path, relative: str, executable: bool = False):
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(origin, target)
            target.chmod(0o755 if executable else 0o644)

        for name in MODULES:
            install(package / name, f"usr/share/landiscovery/landiscovery/{name}")
        install(source / "packaging/landiscovery", "usr/bin/landiscovery", True)
        install(source / "packaging/landiscovery", "usr/bin/lds", True)
        install(source / "packaging/landiscovery-helper",
                "usr/lib/landiscovery/landiscovery-helper", True)
        install(source / "packaging/org.syslinuxos.landiscovery.policy",
                "usr/share/polkit-1/actions/org.syslinuxos.landiscovery.policy")
        install(source / "packaging/org.syslinuxos.landiscovery.desktop",
                "usr/share/applications/org.syslinuxos.landiscovery.desktop")
        install(package / "icon.svg",
                "usr/share/icons/hicolor/scalable/apps/org.syslinuxos.landiscovery.svg")
        for name in ("README.md", "CHANGELOG.md", "LICENSE"):
            install(source / name, f"usr/share/doc/landiscovery/{name}")
        control = root / "DEBIAN"
        control.mkdir()
        (control / "control").write_text(
            f"Package: landiscovery\nVersion: {version}\nArchitecture: all\n"
            "Section: net\nPriority: optional\n"
            "Maintainer: Franco Conidi <fconidi@gmail.com>\n"
            "Depends: python3 (>= 3.11), python3-gi, gir1.2-gtk-3.0, "
            "python3-gi-cairo, nmap, arp-scan, polkitd | policykit-1\n"
            "Recommends: avahi-utils, snmp\n"
            "Description: Discover hosts, services and inferred network paths\n"
            " LAN Discovery provides a graphical network scanner with history,\n"
            " inventory, comparison and export.\n", encoding="utf-8")
        root.chmod(0o755)
        for directory in root.rglob("*"):
            if directory.is_dir():
                directory.chmod(0o755)
        artifact = output / f"landiscovery_{version}_all.deb"
        subprocess.run(["dpkg-deb", "--root-owner-group", "--build", str(root),
                        str(artifact)], check=True)
        print(artifact)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
