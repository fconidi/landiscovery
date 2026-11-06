import csv
import json

from landiscovery.export import export_csv, export_html, export_json
from landiscovery.models import Host, Port, ScanResult


def sample():
    return ScanResult(profile="full", hosts=[Host("192.168.1.2", hostname="pc",
                                                  ports=[Port(22, service="ssh")])])


def test_csv_has_header_and_rows(tmp_path):
    path = tmp_path / "scan.csv"
    export_csv(sample(), path)
    with path.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.reader(stream))
    assert rows[0][0] == "IP"
    assert rows[1][0] == "192.168.1.2"
    assert "22/tcp" in rows[1][5]


def test_json_roundtrip_fields(tmp_path):
    path = tmp_path / "scan.json"
    export_json(sample(), path)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["hosts"][0]["ports"][0]["service"] == "ssh"


def test_html_escapes_hostname(tmp_path):
    result = sample()
    result.hosts[0].hostname = '<script>alert("x")</script>'
    result.hosts[0].ports[0].service = '<img src="x">'
    path = tmp_path / "scan.html"
    export_html(result, path)
    html = path.read_text(encoding="utf-8")
    assert "<script>" not in html and "<img" not in html
    assert "&lt;script&gt;" in html and "&lt;img" in html


def test_export_empty_result(tmp_path):
    result = ScanResult()
    for suffix, export in (("csv", export_csv), ("json", export_json),
                           ("html", export_html)):
        path = tmp_path / f"empty.{suffix}"
        export(result, path)
        assert path.stat().st_size > 0


def test_service_summary_lists_detected_services_of_open_ports():
    from landiscovery.models import Host, Port, service_summary, open_ports
    host = Host("10.0.0.2", services=["_ipp._tcp"],
                ports=[Port(80, "tcp", "open", "http", "nginx 1.2"), Port(22, "tcp", "closed", "ssh")])
    assert [p.number for p in open_ports(host)] == [80]
    assert service_summary(host) == "_ipp._tcp, http nginx 1.2 (80/tcp)"


def test_html_export_has_latency_and_services(tmp_path):
    from landiscovery.export import export_html
    from landiscovery.models import Host, Port, ScanResult
    result = ScanResult(profile="p", hosts=[Host("10.0.0.2", latency_ms=1.5,
                        ports=[Port(80, "tcp", "open", "http")])])
    path = tmp_path / "scan.html"
    export_html(result, path)
    text = path.read_text()
    assert "<th>Latency (ms)</th>" in text and "<th>Services</th>" in text
    assert "<td>1.5</td>" in text and "http (80/tcp)" in text
