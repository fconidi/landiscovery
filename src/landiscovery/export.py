"""Export a scan to portable CSV, JSON or standalone HTML."""
from __future__ import annotations

import csv
import json
from dataclasses import asdict
from html import escape
from pathlib import Path

from .models import ScanResult


def export_csv(result: ScanResult, path: Path) -> None:
    with Path(path).open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(("IP", "Hostname", "MAC", "Vendor", "Latency (ms)",
                         "Open ports", "Services", "OS"))
        for host in result.hosts:
            writer.writerow((host.ip, host.hostname, host.mac or "", host.vendor,
                             "" if host.latency_ms is None else host.latency_ms,
                             ", ".join(f"{p.number}/{p.proto}" for p in host.ports
                                       if p.state == "open"),
                             ", ".join(host.services), host.os))


def export_json(result: ScanResult, path: Path) -> None:
    Path(path).write_text(json.dumps(asdict(result), ensure_ascii=False, indent=2) + "\n",
                          encoding="utf-8")


def export_html(result: ScanResult, path: Path) -> None:
    def cell(value) -> str:
        return f"<td>{escape(str(value), quote=True)}</td>"

    rows = []
    for host in result.hosts:
        ports = ", ".join(f"{p.number}/{p.proto} {p.service} {p.version}".strip()
                          for p in host.ports if p.state == "open")
        rows.append("<tr>" + "".join(map(cell, (host.ip, host.hostname, host.mac or "",
                                             host.vendor, ports, host.os))) + "</tr>")
    title = escape(f"landiscovery — {result.profile}", quote=True)
    content = ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
               f"<title>{title}</title><style>"
               "body{font:16px sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem}"
               "table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;"
               "padding:.5rem;text-align:left;overflow-wrap:anywhere}th{background:#eee}"
               "</style></head><body>"
               f"<h1>{title}</h1><table><thead><tr>"
               "<th>IP</th><th>Hostname</th><th>MAC</th><th>Vendor</th>"
               "<th>Open ports</th><th>OS</th></tr></thead><tbody>"
               + "".join(rows) + "</tbody></table></body></html>\n")
    Path(path).write_text(content, encoding="utf-8")
