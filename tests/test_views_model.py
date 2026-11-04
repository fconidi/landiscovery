from landiscovery.compare import Diff, HostChange
from landiscovery.models import Finding, Host, ScanResult
from landiscovery.views import DiffRows, sorted_findings


def test_diff_rows_states():
    old, new = Host("192.168.1.2"), Host("192.168.1.3")
    rows = DiffRows(Diff(True, new_hosts=[new], gone_hosts=[old],
                         changed=[HostChange("x", old, new, ["hostname"])]))
    assert [r.state for r in rows.rows] == ["new", "gone", "changed"]
    unreliable = DiffRows(Diff(False, ["incomplete"], new_hosts=[new]))
    assert unreliable.rows == [] and unreliable.reasons == ["incomplete"]


def test_findings_sorted_by_severity():
    result = ScanResult(hosts=[Host("192.168.1.2", findings=[
        Finding("192.168.1.2", "info", "i"),
        Finding("192.168.1.2", "critical", "c"),
        Finding("192.168.1.2", "warning", "w")])])
    assert [f.severity for f in sorted_findings(result)] == [
        "critical", "warning", "info"]
