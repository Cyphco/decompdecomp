"""Retry limits and source evidence survive sessions without weakening the judge."""

import json
from types import SimpleNamespace

import pytest

from decompnet.app.engine import RomNetwork
from decompnet.app.permute import MAX_TURNS, Permuter, State
from decompnet.network import NetworkError
from decompnet.workstate import RETRY_ATTEMPTS, candidate_brief, coverage, identity


@pytest.fixture
def net(tmp_path):
    n = RomNetwork(tmp_path / "test.db", tmp_path)
    cfg = {"kind": "rom", "platform": "gba", "compiler": {"toolchain": "agbcc", "flags": ["-O2"]}}
    with n.store.tx() as db:
        db.execute("INSERT INTO projects(id,slug,root,config) VALUES(1,'toy',?,?)", (str(tmp_path), json.dumps(cfg)))
        db.execute("INSERT INTO context_versions(project_id,version,header,unit) VALUES(1,1,'','')")
        db.execute("INSERT INTO functions(id,project_id,name,size,n_insns,vram,target,relocs,asm,best_score,best_source,abandons) "
                   "VALUES(1,1,'toy_fn',4,2,134217728,?, '[]','',3,'int toy_fn(void) { return 1; }',6)", (b'\x00\x20\x70\x47',))
    return n


def actor(net):
    return net.local_agent("test-agent")[0]


def test_retry_plan_survives_restart_and_requires_new_evidence(net, tmp_path):
    a = actor(net)
    fn, proj = net._function("toy_fn", "toy"), net._project("toy")
    with pytest.raises(NetworkError, match="plan_attempt"):
        net.check_retry(fn, proj)
    hypothesis = "Use the observed unsigned halfword field instead of a signed word; the original uses ldrh."
    net.plan_attempt(a, "toy", "toy_fn", hypothesis)
    restarted = RomNetwork(tmp_path / "test.db", tmp_path)
    restarted.check_retry(restarted._function("toy_fn", "toy"), restarted._project("toy"))
    with restarted.store.tx() as db:
        db.execute("UPDATE functions SET attempts=?", (RETRY_ATTEMPTS,))
    with pytest.raises(NetworkError, match="budget"):
        restarted.check_retry(restarted._function("toy_fn", "toy"), restarted._project("toy"))
    with pytest.raises(NetworkError, match="already tried"):
        restarted.plan_attempt(a, "toy", "toy_fn", hypothesis)


def test_another_worker_cannot_replace_a_retry_plan(net):
    a = actor(net)
    other = net.local_agent("other")[0]
    net.claim_row(a, "toy", "toy_fn")
    with pytest.raises(NetworkError, match="another agent"):
        net.plan_attempt(other, "toy", "toy_fn", "Test a distinct inline accessor based on the neighboring exact match.")


def test_automatic_claims_skip_walls_and_reach_large_untried_work(net):
    a = actor(net)
    with net.store.tx() as db:
        db.execute("INSERT INTO functions(project_id,name,size,n_insns,target,relocs,asm) VALUES(1,'large',8000,4000,?,'[]','')", (b'',))
    assert net.claim_row(a, "toy")["name"] == "large"
    net.release(a, "large", "Need a structure model", "toy")
    assert net.claim_row(a, "toy") is None


def test_behavior_checkpoint_keeps_sources_and_exposes_staleness(net):
    a = actor(net)
    before = dict(net._function("toy_fn", "toy"))
    net.preserve_candidate(a, "toy", "toy_fn", "int toy_fn(void) { return 0; }",
                           "Inspected memory widths against the original; execution has not been tested.", "reviewed")
    net.preserve_candidate(a, "toy", "toy_fn", before["best_source"],
                           "Rejected: signed word load reads beyond the original unsigned halfword field.", "rejected")
    assert dict(net._function("toy_fn", "toy")) == before
    assert Permuter(net).candidates(net._project("toy")) == []
    with net.store.tx() as db:
        db.execute("UPDATE context_versions SET header='typedef unsigned short u16;'")
    text = "\n".join(candidate_brief(net, net._function("toy_fn", "toy"), net._project("toy")))
    assert "rejected" in text and "reviewed" in text and "recheck" in text


def test_identity_changes_with_compiler_symbols_target_and_context(net):
    fn, proj = net._function("toy_fn", "toy"), net._project("toy")
    first = identity(net, fn, proj)
    with net.store.tx() as db:
        db.execute("INSERT INTO symbols VALUES(1,'callee',134217744,4,'func',NULL)")
    assert identity(net, fn, proj) != first


def test_permuter_budget_survives_restart_and_new_source_gets_a_budget(net):
    proj, fn = net._project("toy"), net._function("toy_fn", "toy")
    p = Permuter(net)
    with net.store.tx() as db:
        db.execute("INSERT INTO permuter_runs VALUES(?,?,?)", (fn["id"], p._identity(proj, fn), MAX_TURNS))
    assert Permuter(net).candidates(proj) == []
    with net.store.tx() as db:
        db.execute("UPDATE functions SET best_source='int toy_fn(void) { return 2; }'")
    assert len(Permuter(net).candidates(proj)) == 1


def test_permuter_reports_compile_failures_and_deduplicates_across_turns(net, monkeypatch):
    from decompnet.app import permute

    fn, proj = net._function("toy_fn", "toy"), net._project("toy")
    monkeypatch.setattr(permute, "MAX_VARIANTS", 3)
    monkeypatch.setattr(permute, "mutate", lambda *_: "bad source")
    calls = []
    def fail(*args):
        calls.append(args)
        return SimpleNamespace(ok=False, log="synthetic compile error")
    monkeypatch.setattr(net, "_compile", fail)
    p, st = Permuter(net), State()
    p._permute(actor(net), proj, fn, st)
    Permuter(net)._permute(actor(net), proj, fn, st)
    assert len(calls) == 1
    assert st.compile_failed == 1 and st.scored == 0 and st.duplicates > 0
    assert st.last_error == "synthetic compile error"
    assert not net.store.all("SELECT * FROM claims")


def test_permuter_evaluation_failure_is_not_a_compile_failure(net, monkeypatch):
    monkeypatch.setattr(net, "_compile", lambda *_: SimpleNamespace(ok=True, obj=b"obj"))
    monkeypatch.setattr(net, "_evaluate", lambda *_: (None, None, ["no function in object"]))
    value, outcome, error = Permuter(net)._score(actor(net), net._project("toy"), net._function("toy_fn", "toy"), "x", 3, None)
    assert value is None and outcome == "evaluation_failed" and "no function" in error


def test_coverage_excludes_data_and_counts_overlapping_ranges_once():
    def row(status, start, size, reason=""):
        return {"status": status, "vram": start, "size": size, "meta": json.dumps({"asm_code": reason})}
    result = coverage([row("matched", 0, 10), row("open", 8, 12), row("asm", 20, 4),
                       row("asm", 10, 8, "part of parent (merged into it)"), row("asm", 24, 100, "not code: table")])
    assert result["code_bytes"] == 24
    assert result["bytes"]["matched"] == 10 and result["overlap_bytes"] == 2
    assert result["counts"]["excluded"] == 2


def test_deleting_project_removes_retry_and_candidate_history(net):
    a = actor(net)
    net.plan_attempt(a, "toy", "toy_fn", "Test the unsigned halfword layout indicated by the original load width.")
    net.preserve_candidate(a, "toy", "toy_fn", "source", "Reviewed the load width; no behavioral test was performed.", "reviewed")
    with net.store.tx() as db:
        db.execute("INSERT INTO permuter_runs VALUES(1,'key',1)")
        db.execute("INSERT INTO permuter_trials VALUES(1,'key','hash','compile_failed')")
    net.remove_project("toy")
    for table in ("retry_plans", "candidate_checks", "permuter_runs", "permuter_trials"):
        assert not net.store.all(f"SELECT * FROM {table}")


def test_candidate_tools_are_exposed_only_to_rom_api_workers():
    from decompnet.app.agents import api_tool_schemas
    from decompnet.app.tools import tool_names

    for name in ("plan_attempt", "preserve_candidate"):
        assert name in tool_names(False)
        assert name not in tool_names(True)
        assert name in str(api_tool_schemas(False))
        assert name not in str(api_tool_schemas(True))


def test_mutations_do_not_cast_typedef_names_or_move_statements_across_declarations():
    import random

    from decompnet.permuter import _add_cast, _swap_statements

    lines = ['void f(void) {', '    output = 1;', '    u8 value;', '}']
    assert _swap_statements(lines, random.Random(0)) is None
    assert _add_cast(['void f(void) {', '    pair base = (pair){0};', '}'], random.Random(0)) is None
