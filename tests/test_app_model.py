from landiscovery.app import ResultsModel
from landiscovery.models import Host, ScanResult


def test_sort_by_ip_numeric_not_lexical(tmp_path):
    model = ResultsModel(tmp_path / "ui.json")
    model.load(ScanResult(hosts=[Host("10.0.0.10"), Host("10.0.0.2")]))
    model.sort("IP")
    assert [h.ip for h in model.rows] == ["10.0.0.2", "10.0.0.10"]


def test_column_visibility_persisted(tmp_path):
    path = tmp_path / "ui.json"
    model = ResultsModel(path)
    model.set_visible_columns(["IP", "Hostname"])
    assert ResultsModel(path).visible_columns == ["IP", "Hostname"]


def test_empty_result_shows_no_rows(tmp_path):
    model = ResultsModel(tmp_path / "ui.json")
    model.load(ScanResult())
    assert model.rows == []
