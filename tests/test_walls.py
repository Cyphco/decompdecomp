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


def test_the_walls_can_be_listed(tmp_path):
    from decompnet.app.engine import RomNetwork

    n = RomNetwork(tmp_path / "t.db", tmp_path)
    with n.store.tx() as db:
        db.execute("INSERT INTO projects(id,slug,name,arch,root,config) VALUES(1,'p','P','arm','.',?)", (json.dumps({}),))
        for name, abandons in (("wall", WALL_ABANDONS), ("fresh", 0)):
            db.execute("INSERT INTO functions(project_id,name,vram,n_insns,abandons) VALUES(1,?,4096,5,?)", (name, abandons))
    out = n.list_functions("p", "walls")
    assert "wall" in out and "fresh" not in out


def test_a_declaration_after_a_statement_gets_a_c89_hint():
    from decompnet.network import compile_hints

    source = "void f(int *a) {\n    int x[2];\n    g(x);\n\n    int y = x[0];\n    *a = y;\n}\n"
    log = "func.c: In function `f':\nfunc.c:5: syntax error before `y'\nfunc.c:6: `y' undeclared (first use in this function)"
    hint = compile_hints(source, log)
    assert "C89" in hint and "int y = x[0];" in hint
    loop = "void f(void) {\n    for (int i = 0; i < 3; i++) {}\n}\n"
    assert "for (int i" in compile_hints(loop, "func.c:2: syntax error before `int'")
    assert compile_hints("int f(void) { return 0 }", "func.c:1: syntax error before `}'") == ""  # not this mistake: no hint


def test_the_same_failing_source_is_recognised_whatever_its_spacing():
    from decompnet.network import same_source

    assert same_source("void f(void) {\n  g();\n}\n", "void f(void){ g(); }")
    assert not same_source("void f(void) { g(); }", "void f(void) { h(); }")
    assert not same_source(None, "x") and not same_source("", "")
