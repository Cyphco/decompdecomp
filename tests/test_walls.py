"""Walls: functions released again and again are claimed last, and long notes are clipped in briefs. No compiler needed."""

import json

import pytest

from decompnet.network import NOTE_CHARS, WALL_ABANDONS, Network, _clip


@pytest.fixture
def net(tmp_path):
    n = Network(tmp_path / "t.db")
    with n.store.tx() as db:
        db.execute("INSERT INTO projects(id,slug,name,arch,root,config) VALUES(1,'p','P','arm','.',?)", (json.dumps({}),))
        for name, insns, abandons in (("wall", 5, WALL_ABANDONS), ("big", 50, 0), ("small", 20, 0)):
            db.execute("INSERT INTO functions(project_id,name,n_insns,abandons) VALUES(1,?,?,?)", (name, insns, abandons))
    return n


def test_automatic_claims_leave_walls_for_last(net):
    a = net.authenticate(net.register_agent("a", "a"))
    b = net.authenticate(net.register_agent("b", "b"))
    first = net.claim_row(a, "p")
    assert first["name"] == "small"  # not "wall", the smallest
    assert net.claim_row(b, "p")["name"] == "big"
    net.release(a, "small", "", "p")
    net.release(b, "big", "", "p")
    with net.store.tx() as db:  # everything left is a wall: still handed out, rather than nothing
        db.execute("UPDATE functions SET abandons=?", (WALL_ABANDONS,))
        db.execute("DELETE FROM events WHERE kind='release'")
    assert net.claim_row(a, "p") is not None


def test_a_wall_can_still_be_claimed_by_name(net):
    a = net.authenticate(net.register_agent("a", "a"))
    assert net.claim_row(a, "p", function="wall")["name"] == "wall"


def test_long_notes_are_clipped():
    assert _clip("short") == "short"
    clipped = _clip("x" * (NOTE_CHARS + 500))
    assert clipped.startswith("x" * NOTE_CHARS) and clipped.endswith("[500 more characters]")
