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


class _Compiled:
    def __init__(self, source):
        self.ok = not source.startswith("bad")
        self.obj = int(source[1:]) if self.ok else None
        self.log = "func.c:1: syntax error before `x'" if not self.ok else ""


def _judge_net(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from decompnet import scoring
    from decompnet.app.engine import RomNetwork

    n = RomNetwork(tmp_path / "t.db", tmp_path)
    with n.store.tx() as db:
        db.execute("INSERT INTO projects(id,slug,name,arch,root,config) VALUES(1,'p','P','arm','.',?)", (json.dumps({}),))
        db.execute("INSERT INTO functions(project_id,name,vram,n_insns) VALUES(1,'f',4096,5)")
    n._context = lambda pid, unit: {"header": "", "version": 1}
    n._target_obj = lambda fn, proj: None
    n._compile = lambda proj, header, source, fn=None: _Compiled(source)
    n._evaluate = lambda fn, proj, obj: (obj, None, [])
    monkeypatch.setattr(scoring, "diff", lambda target, cand: SimpleNamespace(
        score=cand, max_score=100, rows=[(" ", "a", "a")], percent=100 - cand, bytes_match=cand == 0, verdict=None))
    recorded = []
    n.attempt = lambda agent, function, source, project=None: recorded.append(source) or {"text": f"RECORDED {source}"}
    return n, recorded


def test_variants_are_judged_together_and_the_best_is_recorded(tmp_path, monkeypatch):
    n, recorded = _judge_net(tmp_path, monkeypatch)
    agent = n.authenticate(n.register_agent("a", "a"))
    out = n.try_variants(agent, "f", ["s10", "bad1", "s3", "s7"], "p")
    assert "variant 1: score 10" in out and "variant 2: did not compile" in out and "variant 3: score 3" in out
    assert "variant 3" in out.splitlines()[2] and "<- best" in out.splitlines()[2]
    assert recorded == ["s3"] and "RECORDED s3" in out  # only the best is recorded, as the agent's attempt
    n.try_variants(agent, "f", ["bad1", "bad2"], "p")
    assert recorded[-1] == "bad1"  # nothing compiled: the first, so its error and the stall count reach the agent
    assert n.try_variants(agent, "f", ["s5"], "p") == "RECORDED s5"  # one is just compile_and_diff


def test_variants_have_limits_and_respect_claims(tmp_path, monkeypatch):
    from decompnet.network import NetworkError

    n, _ = _judge_net(tmp_path, monkeypatch)
    a = n.authenticate(n.register_agent("a", "a"))
    b = n.authenticate(n.register_agent("b", "b"))
    with pytest.raises(NetworkError, match="at most 8"):
        n.try_variants(a, "f", [f"s{k}" for k in range(9)], "p")
    with pytest.raises(NetworkError, match="list of complete C sources"):
        n.try_variants(a, "f", ["", "  "], "p")
    with n.store.tx() as db:
        db.execute("INSERT INTO claims VALUES(1,?,0,9999999999)", (b.id,))
    with pytest.raises(NetworkError, match="claimed by"):
        n.try_variants(a, "f", ["s1", "s2"], "p")


def test_the_variants_tool_is_offered_to_cli_and_api_agents():
    from decompnet.app import agents, tools

    assert "compile_variants" in tools.HANDLERS
    schema = next(t for t in agents.api_tool_schemas() if t["function"]["name"] == "compile_variants")["function"]["parameters"]
    assert schema["properties"]["sources"]["type"] == "array" and set(schema["required"]) == {"function", "sources"}


def test_a_long_functions_assembly_comes_in_parts(tmp_path, monkeypatch):
    n = Network(tmp_path / "t.db")
    with n.store.tx() as db:
        db.execute("INSERT INTO projects(id,slug,name,arch,root,config) VALUES(1,'p','P','arm','.',?)",
                   (json.dumps({"compiler": {"toolchain": "agbcc", "flags": ["-O2"]}}),))
        db.execute("INSERT INTO functions(project_id,name,vram,n_insns) VALUES(1,'huge',4096,2000)")
        db.execute("INSERT INTO functions(project_id,name,vram,n_insns) VALUES(1,'small',8192,10)")
    n._context = lambda pid, unit: {"header": "", "version": 1}
    monkeypatch.setattr(n, "_extra_brief", lambda fn, proj: [], raising=False)
    n._asm_text = lambda fn, proj: "\n".join(f"  op{k} r0, r1" for k in range(1200))
    agent = n.authenticate(n.register_agent("a", "a"))

    brief = n.get_function("huge", "p", agent)
    assert "lines 1-500 of 1200" in brief and "op499 " in brief and "op500 " not in brief
    assert 'get_function("huge", start_line=500, max_lines=500)' in brief
    part = n.get_function("huge", "p", agent, start_line=1000, max_lines=500)
    assert "lines 1001-1200 of 1200" in part and "op1199 " in part and "the next part" not in part
    assert "op0 " not in part
    whole = n.get_function("small", "p", agent)  # short functions are shown whole, as before
    assert "### Target assembly\n" in whole and "op1199 " in whole


def test_the_queue_does_not_hand_back_what_a_helper_just_released(tmp_path):
    from decompnet.app.engine import RomNetwork

    n = RomNetwork(tmp_path / "t.db", tmp_path)
    with n.store.tx() as db:
        db.execute("INSERT INTO projects(id,slug,name,arch,root,config) VALUES(1,'p','P','arm','.',?)",
                   (json.dumps({"priority": ["big", "next"]}),))
        for name, vram in (("big", 4096), ("next", 8192), ("other", 12288)):
            db.execute("INSERT INTO functions(project_id,name,vram,n_insns) VALUES(1,?,?,5)", (name, vram))
    a = n.authenticate(n.register_agent("a", "a"))
    assert n.claim_row(a, "p")["name"] == "big"  # the queue's first
    n.release(a, "big", "too large", "p")
    assert n.claim_row(a, "p")["name"] == "next"  # not "big" again: a gave it up
    n.release(a, "next", "", "p")
    assert n.claim_row(a, "p")["name"] == "other"  # the queue is used up for a
    n.release(a, "other", "", "p")
    assert n.claim_row(a, "p") is None  # everything has been given up by a: nothing is handed back


def test_extent_repair_candidates_and_row_update(tmp_path):
    from decompnet.app.engine import RomNetwork

    n = RomNetwork(tmp_path / "t.db", tmp_path)
    with n.store.tx() as db:
        db.execute("INSERT INTO projects(id,slug,name,arch,root,config) VALUES(1,'p','P','arm','.',?)", (json.dumps({}),))
        db.execute("INSERT INTO functions(id,project_id,name,vram,size,n_insns,target,relocs,best_source) "
                   "VALUES(1,1,'f',4096,22,11,x'00',?, 'best')", (json.dumps([]),))
        db.execute("INSERT INTO symbols(project_id,name,address,size,kind) VALUES(1,'f',4096,22,'func')")
        for k, src in enumerate(["best", "a", "a", "b", "bad"]):  # the best one again, a duplicate, and one that failed
            db.execute("INSERT INTO attempts(function_id,agent_id,score,compiled,source,created_at) VALUES(1,1,10,?,?,?)",
                       (0 if src == "bad" else 1, src, k))
    fn = n.store.one("SELECT * FROM functions WHERE id=1")
    assert n._extent_candidates(fn) == ["best", "b", "a"]  # newest first, no repeats, compiled ones only
    proj = n.store.one("SELECT * FROM projects WHERE id=1")
    n._set_extent(proj, fn, 32, b"\x01" * 32, [(4, 2, 0x03000000)])
    row = n.store.one("SELECT size,n_insns,length(target) AS n,relocs FROM functions WHERE id=1")
    assert (row["size"], row["n_insns"], row["n"]) == (32, 16, 32) and json.loads(row["relocs"]) == [[4, 2, 0x03000000]]
    assert n.store.one("SELECT size FROM symbols WHERE name='f'")["size"] == 32
    assert n.store.one("SELECT detail FROM events WHERE kind='boundary'")["detail"].startswith("f: 22 -> 32")
