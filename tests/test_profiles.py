import json
import pytest

from landiscovery.profiles import BUILTIN, Profile, ProfileStore, default_profiles_path


def mk(**kw):
    base = dict(name="mio", ports="22,80-90", os_detect=False, service_detect=False,
                traceroute=False, discovery=False, security_checks=False)
    base.update(kw)
    return Profile(**base)


def test_builtin_profiles_present():
    assert set(BUILTIN) == {"quick", "full", "ping", "security"}
    assert all(p.builtin for p in BUILTIN.values())
    assert BUILTIN["quick"].ports == "top100"
    assert BUILTIN["full"].ports == "1-65535" and BUILTIN["full"].os_detect
    assert BUILTIN["ping"].ports == ""
    assert BUILTIN["security"].security_checks and BUILTIN["security"].service_detect
    assert not BUILTIN["security"].os_detect


def test_custom_profile_roundtrip(tmp_path):
    store = ProfileStore(tmp_path / "sub" / "p.json")
    store.save(mk(traceroute=True))
    loaded = store.load()
    assert set(BUILTIN) <= set(loaded)
    assert loaded["mio"].traceroute and loaded["mio"].ports == "22,80-90"
    assert loaded["mio"].builtin is False


def test_builtin_flag_from_file_ignored(tmp_path):
    path = tmp_path / "p.json"
    path.write_text(json.dumps([{"name": "x", "ports": "80", "builtin": True}]))
    assert ProfileStore(path).load()["x"].builtin is False


def test_cannot_shadow_builtin(tmp_path):
    with pytest.raises(ValueError):
        ProfileStore(tmp_path / "p.json").save(mk(name="quick"))


def test_cannot_delete_builtin(tmp_path):
    with pytest.raises(ValueError):
        ProfileStore(tmp_path / "p.json").delete("quick")


def test_delete_custom(tmp_path):
    store = ProfileStore(tmp_path / "p.json")
    store.save(mk())
    store.delete("mio")
    assert "mio" not in store.load()


def test_corrupt_or_missing_file(tmp_path):
    path = tmp_path / "p.json"
    assert set(ProfileStore(path).load()) == set(BUILTIN)
    path.write_text("{not json")
    assert set(ProfileStore(path).load()) == set(BUILTIN)
    path.write_text('"stringa"')
    assert set(ProfileStore(path).load()) == set(BUILTIN)


@pytest.mark.parametrize("ports", ["22; rm", "abc", "0", "65536", "90-80", "1,,2", "-5", "80-", "top10", "1 2"])
def test_ports_field_rejects_arbitrary_text(ports):
    with pytest.raises(ValueError):
        mk(ports=ports)


@pytest.mark.parametrize("ports", ["", "top100", "80", "1-65535", "22,80,443-450"])
def test_ports_valid(ports):
    assert mk(ports=ports).ports == ports


@pytest.mark.parametrize("name", ["", "a" * 41, "a/b", "a\\b", "..", "x.y", "a\nb"])
def test_name_rejected(name):
    with pytest.raises(ValueError):
        mk(name=name)


def test_default_path(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert default_profiles_path() == tmp_path / "landiscovery" / "profiles.json"
    monkeypatch.delenv("XDG_CONFIG_HOME")
    assert default_profiles_path().parts[-3:] == (".config", "landiscovery", "profiles.json")
