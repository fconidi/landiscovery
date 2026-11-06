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


def test_error_text_translates_engine_and_target_messages():
    from landiscovery.app import _error_text
    from landiscovery.i18n import set_language
    set_language("it")
    try:
        assert _error_text("avahi-browse not installed") == "avahi-browse non è installato"
        assert _error_text("invalid target: 'a b'").startswith("Rete non valida: 'a b'")
        assert _error_text("target networks differ") == "le reti esaminate sono diverse"
    finally:
        set_language("en")
