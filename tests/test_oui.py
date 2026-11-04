from landiscovery.oui import OuiDatabase


def test_oui_lookup_known_prefix(tmp_path):
    a = tmp_path / "ieee-oui.txt"
    a.write_text("# comment\nB827EB\tRaspberry Pi Foundation\n\n001132\tSynology Incorporated\n")
    b = tmp_path / "nmap-mac-prefixes"
    b.write_text("# comment\n00163E Xensource, Inc.\n")
    db = OuiDatabase([a, b])
    assert db.lookup("b8:27:eb:01:02:03") == "Raspberry Pi Foundation"
    assert db.lookup("00-11-32-aa-bb-cc") == "Synology Incorporated"
    assert db.lookup("00163E112233") == "Xensource, Inc."
    assert db.lookup("AA:BB:CC:00:00:00") == ""
    assert db.lookup("") == ""
    assert db.lookup("zz") == ""


def test_oui_missing_files_returns_empty(tmp_path):
    db = OuiDatabase([tmp_path / "nope1", tmp_path / "nope2"])
    assert db.lookup("B8:27:EB:01:02:03") == ""
