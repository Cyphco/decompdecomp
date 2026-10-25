"""Function-end reports on a GBA game: agents said "GBA boundary-report support appears unavailable" and released the
function. A report is checked by halfwords (Thumb), and an approved one is cut the GBA's own way, by bytes and by
luvdis's listing, with the rest set aside."""

import json

import pytest

from decompnet.app.engine import RomNetwork
from decompnet.network import NetworkError

from .test_loading import tiny_game

# push {r4, lr}; movs r0, #1; pop {r4}; pop {r1}; bx r1; then two bytes of padding and a word of data
CODE = bytes.fromhex("10b5" "0120" "10bc" "02bc" "0847" "0000" "efbeadde")
ASM = ("\tthumb_func_start func_0\nfunc_0:\n\tpush {r4, lr}\n\tmovs r0, #1\n\tpop {r4}\n\tpop {r1}\n\tbx r1\n"
       "_0810000A:\n\t.byte 0x00, 0x00\n_0810000C: .4byte 0xDEADBEEF\n")


@pytest.fixture
def gba(tmp_path):
    net = RomNetwork(tmp_path / "app.db", tmp_path)
    tiny_game(net, functions=1)
    net._update_cfg("game", lambda cfg: cfg.update(platform="gba", compiler={"toolchain": "agbcc", "flags": ["-O2"]}))
    with net.store.tx() as db:
        db.execute("UPDATE functions SET vram=?, size=?, n_insns=?, target=?, asm=?, rom_offset=? WHERE name='func_0'",
                   (0x08100000, len(CODE), len(CODE) // 2, CODE, ASM, 0x100000))
    agent, _ = net.local_agent("claude-opus-1")
    return net, agent


def test_a_gba_function_end_is_reported_by_halfwords_and_cut_its_own_way(gba):
    net, agent = gba
    with pytest.raises(NetworkError, match="isn't an instruction's end"):  # (not a halfword)
        net.request_boundary(agent, "game", "func_0", "0x08100009", "padding")
    said = net.request_boundary(agent, "game", "func_0", "0x0810000A", "after bx r1: two bytes of padding and a word")
    assert said.startswith("Reported: func_0 ends at 0x0810000A (6 bytes")
    (req,) = net.overview("game")["boundaries"]
    assert req["rest"] == "0000 BEEF DEAD"  # (halfwords, as Thumb code reads)
    net.resolve_boundary("game", req["id"], apply=True)
    fn = net.store.one("SELECT * FROM functions WHERE name='func_0'")
    assert (fn["size"], bytes(fn["target"]), fn["status"]) == (10, CODE[:10], "open")
    assert "_0810000A" not in fn["asm"] and fn["asm"].rstrip().endswith("bx r1")
    pad = net.store.one("SELECT * FROM functions WHERE name='pad_0810000A'")
    assert (pad["status"], pad["size"], pad["vram"], pad["rom_offset"]) == ("asm", 6, 0x0810000A, 0x10000A)
    assert "two bytes of padding" in json.loads(pad["meta"])["asm_code"]
    assert pad["asm"].startswith("_0810000A:")
    last = net.store.one("SELECT kind, detail FROM events ORDER BY id DESC LIMIT 1")
    assert (last["kind"], last["detail"]) == ("boundary", "func_0 ends at 0x0810000A")


def test_a_listing_that_runs_into_the_next_function_is_cut_at_its_end(gba):
    """luvdis listed a function up to the next one it found itself, so one only the second pass found was listed as
    part of the function before it: agents read the next function's prologue there and released the function, sure
    its bytes ran into the next one's. The listing ends where the function does now, also in a project imported
    before (Check again, once after the update), and nothing else changes."""
    net, _ = gba
    with net.store.tx() as db:  # the function's bytes end at 0x0810000A; the listing goes on into the next one
        db.execute("UPDATE functions SET size=10, target=? WHERE name='func_0'", (CODE[:10],))
    before = net.store.one("SELECT * FROM functions WHERE name='func_0'")
    assert "_0810000C:" in before["asm"]
    net.recheck("game", log=lambda *_: None)
    fn = net.store.one("SELECT * FROM functions WHERE name='func_0'")
    assert fn["asm"].split("\n@ it ends here")[0] == ASM.split("\n_0810000A:")[0]
    assert "0x0810000A" in fn["asm"] and "_0810000C" not in fn["asm"]
    assert (bytes(fn["target"]), fn["size"]) == (bytes(before["target"]), before["size"])
    assert any("assembly ends where they end" in e["detail"] for e in net.store.all("SELECT detail FROM events"))
    net.recheck("game", log=lambda *_: None)  # (again: nothing more to cut)
    assert net.store.one("SELECT asm FROM functions WHERE name='func_0'")["asm"] == fn["asm"]
