"""Command line access to scanning, history, inventory and export."""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path

from .compare import compare_scans
from .engine import EngineError, ScanEngine, ScanOptions
from .export import export_csv, export_html, export_json
from .profiles import ProfileStore, default_profiles_path
from .store import Store
from .targets import TargetError, check_scope, parse_targets


def default_store_path() -> Path:
    root = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share"))
    return root / "landiscovery" / "history.db"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="landiscovery")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan")
    scan.add_argument("networks", nargs="+")
    scan.add_argument("--profile", default="quick")
    scan.add_argument("--json", action="store_true")
    scan.add_argument("--yes", action="store_true")
    scan.add_argument("--snmp-community-stdin", action="store_true")
    sub.add_parser("history")
    compare = sub.add_parser("compare")
    compare.add_argument("old", type=int)
    compare.add_argument("new", type=int)
    inventory = sub.add_parser("inventory")
    inventory.add_argument("--set", metavar="KEY")
    inventory.add_argument("--name")
    inventory.add_argument("--note", default="")
    inventory.add_argument("--tag", action="append", default=[])
    export = sub.add_parser("export")
    export.add_argument("id", type=int)
    export.add_argument("--format", choices=("csv", "json", "html"), required=True)
    export.add_argument("-o", "--output", type=Path, required=True)
    sub.add_parser("gui")
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return int(exc.code)
    try:
        if args.command == "scan":
            try:
                networks = parse_targets(" ".join(args.networks))
            except TargetError as exc:
                print(exc, file=sys.stderr)
                return 2
            scope = check_scope(networks)
            if not scope.allowed or scope.needs_confirmation and not args.yes:
                print("; ".join(scope.reasons), file=sys.stderr)
                return 2
            profile = ProfileStore(default_profiles_path()).load().get(args.profile)
            if profile is None:
                print(f"unknown profile: {args.profile}", file=sys.stderr)
                return 2
            community = None
            if profile.snmp:
                if args.snmp_community_stdin:
                    community = sys.stdin.readline().rstrip("\r\n")
                elif sys.stdin.isatty():
                    community = getpass.getpass("SNMP community: ")
            result = ScanEngine().scan(networks, profile,
                                       ScanOptions(snmp_community=community))
            scan_id = Store(default_store_path()).save_scan(result)
            if args.json:
                print(json.dumps({**asdict(result), "id": scan_id}, ensure_ascii=False))
            else:
                print(f"Scan {scan_id}: {len(result.hosts)} hosts ({result.status})")
                for host in result.hosts:
                    print(f"{host.ip}\t{host.hostname}\t{host.mac or ''}")
                for warning in result.warnings:
                    print(f"warning: {warning}", file=sys.stderr)
            return 0 if result.status == "done" else 1
        if args.command == "gui":
            from .app import main as gui_main
            return gui_main()
        store = Store(default_store_path())
        if args.command == "history":
            for scan in store.list_scans():
                print(f"{scan.id}\t{scan.profile}\t{scan.host_count}\t"
                      f"{scan.status}\t{','.join(scan.targets)}")
        elif args.command == "compare":
            diff = compare_scans(store.get_scan(args.old), store.get_scan(args.new))
            if not diff.comparable:
                print("Comparison unreliable: " + "; ".join(diff.reasons),
                      file=sys.stderr)
            for label, hosts in (("new", diff.new_hosts), ("gone", diff.gone_hosts)):
                for host in hosts:
                    print(f"{label}\t{host.ip}\t{host.hostname}")
            for change in diff.changed:
                print(f"changed\t{change.new.ip}\t{','.join(change.fields)}")
        elif args.command == "inventory":
            if bool(args.set) != bool(args.name):
                print("--set and --name must be supplied together", file=sys.stderr)
                return 2
            if args.set:
                store.set_device(args.set, args.name, args.note, args.tag)
            for device in store.list_devices():
                print(f"{device.key}\t{device.name}\t{device.note}\t"
                      f"{','.join(device.tags)}")
        elif args.command == "export":
            exporters = {"csv": export_csv, "json": export_json, "html": export_html}
            exporters[args.format](store.get_scan(args.id), args.output)
        return 0
    except (EngineError, KeyError, OSError, ValueError) as exc:
        print(f"landiscovery: {exc}", file=sys.stderr)
        return 1
