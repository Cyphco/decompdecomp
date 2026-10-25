"""Another binary of a toolchain (agbcc's old_agbcc: Toolchain.variants) as agents name it: try_compiler, search_flags
and suggest take it, and the suggestion, its range check and the range it applies keep it."""

import pytest

from decompnet.app.engine import RomNetwork
from decompnet.network import NetworkError

from .test_loading import tiny_game

GBA = {"toolchain": "agbcc", "flags": ["-mthumb-interwork", "-O2"]}
SOURCE = "int func_0(void) { return 0; }"


class Diff:  # what the judge says about C that compiled
    score, percent = 8, 50.0

    def render(self, **kw):
        return ""


@pytest.fixture
def gba(tmp_path, monkeypatch):
    net = RomNetwork(tmp_path / "app.db", tmp_path)
    tiny_game(net)
    net._update_cfg("game", lambda cfg: cfg.update(platform="gba", compiler=dict(GBA)))
    asked = []

    def judge(proj, fn, toolchain, flags, source, variant=None):
        asked.append((toolchain, variant))
        return (variant == "old_agbcc", Diff(), "")  # it matches only with the older snapshot
    monkeypatch.setattr(net, "_judge_with", judge)
    agent, _ = net.local_agent("claude-opus-1")
    return net, agent, asked


def test_try_compiler_builds_with_old_agbcc(gba):
    """A GBA game's old_agbcc parts were out of agents' reach: no tool took the name, so their C was only ever judged
    with today's agbcc, and an agent wrote "there is only agbcc/agbcp (no old_agbcc)" and dropped the function."""
    net, agent, asked = gba
    said = net.try_compiler(agent, "game", "func_0", "old_agbcc", source=SOURCE)
    assert asked == [("agbcc", "old_agbcc")]
    assert said.startswith("agbcc (old_agbcc) -mthumb-interwork -O2: MATCHES") and 'compiler="old_agbcc"' in said
    assert "MATCHES" in net.try_compiler(agent, "game", "func_0", "agbcc (old_agbcc)", source=SOURCE)
    assert "MATCHES" not in net.try_compiler(agent, "game", "func_0", "agbcc", source=SOURCE)
    with pytest.raises(NetworkError, match="old_agbcc"):  # (what it can name, when it names something else)
        net.try_compiler(agent, "game", "func_0", "agbcc-2", source=SOURCE)


def test_search_flags_in_an_old_agbcc_part_uses_old_agbcc(gba):
    net, agent, asked = gba
    part = {"start": 0x100000, "end": 0x100010, **GBA, "variant": "old_agbcc"}
    net._update_cfg("game", lambda cfg: cfg.__setitem__("compiler_ranges", [part]))
    net.search_flags(agent, "game", "func_0", source=SOURCE)
    assert asked and all(v == "old_agbcc" for _, v in asked)


def test_an_old_agbcc_suggestion_keeps_its_variant_to_the_range(gba, monkeypatch):
    net, agent, _ = gba
    monkeypatch.setattr(net.rangechecks, "recheck", lambda slug, cid=None: None)  # (its neighbours aren't the point here)
    said = net.suggest(agent, "game", "old_agbcc built this", compiler="old_agbcc", function="func_0",
                       ranges="0x100000-0x100010", source=SOURCE)
    assert "matches the game" in said
    cfg = net.cfg(net._project("game"))
    (s,) = cfg["suggestions"]
    assert (s["toolchain"], s["variant"]) == ("agbcc", "old_agbcc")
    assert [c.get("variant") for c in cfg["range_checks"]] == ["old_agbcc"]
    net.resolve_suggestion("game", s["id"], apply=True)
    (r,) = net.cfg(net._project("game"))["compiler_ranges"]
    assert (r["toolchain"], r["variant"], r["start"]) == ("agbcc", "old_agbcc", 0x100000)
    assert [p["compiler"] for p in net.compiler_answer("game")["parts"]] == ["agbcc (old_agbcc)"]


def test_a_range_outside_the_game_is_refused(gba, monkeypatch):
    """A GBA game's agent wrote 0x38E04-0x80390E4 for 0x08038E04: its range check grew it to nearly the whole game,
    and the user's Apply could only fail (1,447 matches broken). A range must start and end in the game now."""
    net, agent, _ = gba
    monkeypatch.setattr(net.rangechecks, "recheck", lambda slug, cid=None: None)
    net._update_cfg("game", lambda cfg: cfg.__setitem__("segments", [
        {"name": "rom", "rom_start": 0, "rom_end": 0x800000, "vram": 0x08000000}]))
    with pytest.raises(NetworkError, match="0x38E04-0x80390E4 isn't inside the game's code"):
        net.suggest(agent, "game", "C++", compiler="agbcp", ranges="0x38E04-0x80390E4")
    with pytest.raises(NetworkError, match="isn't inside the game's code"):
        net.set_compiler_ranges("game", [[0x08000000, 0x09000000]], "agbcp")
    assert net.cfg(net._project("game")).get("suggestions", []) == []
    net.set_compiler_ranges("game", [[0x08038E04, 0x08038EA4]], "agbcp")  # (the range it meant)
    assert [(r["start"], r["toolchain"]) for r in net.cfg(net._project("game"))["compiler_ranges"]] == [(0x08038E04, "agbcp")]
