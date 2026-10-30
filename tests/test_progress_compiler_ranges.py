"""Progress contributions must obey the same address-range bounds as compiler settings."""

import json

import pytest

from decompnet.app import saves
from decompnet.network import NetworkError

from .test_progress import manifest, project  # noqa: F401


@pytest.fixture
def gba(project):  # noqa: F811
    net, folder, judged = project
    net._update_cfg("game", lambda cfg: cfg.update(platform="gba", segments=[
        {"name": "rom", "rom_start": 0, "rom_end": 0x100, "vram": 4096}]))
    (folder / "src").mkdir(exist_ok=True)
    (folder / "src/f.c").write_text("good original", encoding="utf-8")
    net.progress.sync("game", force=True)
    judged.clear()
    return net, folder, judged


def part(start=4096, end=4100, **extra):
    return {"start": start, "end": end, "toolchain": "agbcc", "flags": ["-O2"], **extra}


@pytest.mark.parametrize("bounds", [{"start": 16}, {"end": 0x2000}, {"end": 4096}])
def test_a_pulled_range_outside_the_rom_preserves_matches(gba, bounds):
    net, folder, judged = gba
    manifest(folder, compiler_ranges=[part(**bounds)])
    contribution = (folder / saves.MANIFEST).read_text()
    with pytest.raises(NetworkError, match="isn't inside the game's code"):
        net.progress.sync("game", force=True)
    row = net.store.one("SELECT status,matched_source FROM functions WHERE name='f'")
    assert (row["status"], row["matched_source"]) == ("matched", "good original")
    cfg = json.loads(net.store.one("SELECT config FROM projects WHERE slug='game'")["config"])
    assert not cfg.get("compiler_ranges")
    assert not judged
    assert (folder / saves.MANIFEST).read_text() == contribution


def test_a_valid_pulled_range_keeps_its_compiler_variant(gba):
    net, folder, judged = gba
    choice = part(variant="old_agbcc")
    manifest(folder, compiler_ranges=[choice])
    net.progress.sync("game", force=True)
    assert net.cfg(net._project("game"))["compiler_ranges"] == [choice]
    assert judged == [("f", "good original")]
    assert net._function("f", "game")["status"] == "matched"


def test_an_existing_invalid_range_can_still_be_repaired(gba, monkeypatch):
    net, folder, _ = gba
    bad = part(start=16)
    # An older app has already stored this mistake. Opening it must not block Check again.
    net._update_cfg("game", lambda cfg: cfg.__setitem__("compiler_ranges", [bad]))
    net.progress.sync("game", force=True)
    monkeypatch.setattr(net, "regression_test", lambda *args, **kwargs: [])
    assert net.drop_ranges_outside("game", log=lambda _: None) == 1
    assert net.cfg(net._project("game"))["compiler_ranges"] == []
    assert json.loads((folder / saves.MANIFEST).read_text())["compiler_ranges"] == []


def test_a_restore_checks_ranges_again_after_rom_segments_are_known(gba):
    net, folder, _ = gba
    data = json.loads((folder / saves.MANIFEST).read_text())
    data["compiler_ranges"] = [part(start=16)]
    # Restore's first manifest read knows only the fingerprint, before importing the ROM.
    with pytest.raises(NetworkError, match="isn't inside the game's code"):
        saves._apply_context(net, "game", folder, data, lambda _: None)
    assert not net.cfg(net._project("game")).get("compiler_ranges")


def test_editing_a_legacy_invalid_range_is_a_new_contribution(gba):
    net, folder, _ = gba
    bad = part(start=16)
    net._update_cfg("game", lambda cfg: cfg.__setitem__("compiler_ranges", [bad]))
    manifest(folder, compiler_ranges=[{**bad, "flags": ["-O1"]}])
    with pytest.raises(NetworkError, match="isn't inside the game's code"):
        net.progress.sync("game", force=True)
    cfg = json.loads(net.store.one("SELECT config FROM projects WHERE slug='game'")["config"])
    assert cfg["compiler_ranges"] == [bad]
