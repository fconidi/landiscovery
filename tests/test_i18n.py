from landiscovery import i18n


def test_all_keys_in_both_languages():
    assert all(key and value for key, value in i18n.CATALOG.items())
    i18n.set_language("it")
    assert i18n._("Scan") == "Scansione"
    i18n.set_language("en")
    assert i18n._("Scan") == "Scan"


def test_unknown_key_returns_key():
    i18n.set_language("it")
    assert i18n._("unknown") == "unknown"
    i18n.set_language("en")


def test_auto_falls_back_to_english(monkeypatch):
    monkeypatch.setenv("LANGUAGE", "fr_FR")
    i18n.set_language("auto")
    assert i18n._("Scan") == "Scan"
    i18n.set_language("en")
