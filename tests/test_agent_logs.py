"""Helper logs: a file per helper with what the agent printed, readable from the app, secrets blanked."""

import pytest

from decompnet.app import agents


def session(tmp_path, **kw):
    s = agents.Session("opencode-3", "opencode", "opencode #3", "p", "opencode-3", {})
    s.log_path = tmp_path / "agent-logs" / "opencode-3.log"
    s.secrets.extend(kw.get("secrets", []))
    return s


def manager(tmp_path):
    return agents.Manager.__new__(agents.Manager) if False else _bare(tmp_path)


def _bare(tmp_path):
    m = agents.Manager.__new__(agents.Manager)
    m.sessions, m.log_dir = {}, tmp_path / "agent-logs"
    return m


def test_a_log_holds_raw_output_events_and_no_secrets(tmp_path):
    s = session(tmp_path, secrets=["tok-123"])
    s.raw("cmd", "opencode run --token tok-123")
    s.raw("err", "Streaming response failed: [503] Service temporarily overloaded")
    s.push("error", "exited with code 1")
    text = s.log_path.read_text(encoding="utf-8")
    assert "tok-123" not in text and "--token ***" in text
    assert "[503]" in text and "error  exited with code 1" in text
    assert all(line[2] == ":" for line in text.splitlines())  # every line is timestamped


def test_a_log_rolls_over_instead_of_growing_forever(tmp_path, monkeypatch):
    monkeypatch.setattr(agents, "LOG_MAX", 200)
    s = session(tmp_path)
    for k in range(30):
        s.raw("out", f"line {k} " + "x" * 40)
    assert s.log_path.stat().st_size < 400 and s.log_path.with_name("opencode-3.log.1").exists()


def test_the_app_reads_the_tail_of_a_log_and_lists_them(tmp_path):
    m = _bare(tmp_path)
    s = session(tmp_path)
    m.sessions["opencode-3"] = s
    for k in range(50):
        s.raw("out", f"event {k}")
    got = m.read_log("opencode-3", tail=300)
    assert got["truncated"] and got["text"].endswith("event 49\n") and "event 0\n" not in got["text"]
    assert not got["text"].startswith("event")  # starts at a line, not in the middle of one
    assert [r["id"] for r in m.logs()] == ["opencode-3"] and m.logs()[0]["label"] == "opencode #3 · opencode-3"
    assert m.read_log("opencode-3")["id"] == "opencode-3"  # by session id too: it resolves to the agent's file
    m.sessions.clear()  # after a restart the file is still there
    assert m.logs()[0]["state"] == "ended"


@pytest.mark.parametrize("bad", ["../settings", "a/b", "", "x" * 3 + "\\y"])
def test_a_log_id_cannot_leave_the_log_folder(tmp_path, bad):
    with pytest.raises(ValueError):
        _bare(tmp_path).read_log(bad)


def test_opencodes_reasoning_reaches_the_feed_and_the_log(tmp_path):
    line = '{"type":"reasoning","part":{"type":"reasoning","text":"The diff is one register off."}}'
    assert agents.parse_line("opencode", line) == [("think", "The diff is one register off.")]
    s = session(tmp_path)
    s.raw("out", line)
    s.push("think", "The diff is one register off.")
    assert s.log_path.read_text(encoding="utf-8").count("The diff is one register off.") == 2


def test_a_flag_is_only_passed_to_an_opencode_that_knows_it(monkeypatch):
    import subprocess as sp

    agents._flags.clear()
    monkeypatch.setattr(sp, "run", lambda *a, **k: sp.CompletedProcess(a, 0, stdout="  --thinking  show thinking", stderr=""))
    assert agents._has_flag("opencode", "--thinking")
    agents._flags.clear()
    monkeypatch.setattr(sp, "run", lambda *a, **k: sp.CompletedProcess(a, 0, stdout="  --format", stderr=""))
    assert not agents._has_flag("opencode", "--thinking")
    agents._flags.clear()


def test_a_long_json_line_stays_json(tmp_path):
    import json

    big = {"type": "tool_use", "part": {"tool": "decomp_get_context", "state": {"output": "x" * 50000}}}
    s = session(tmp_path)
    s.raw("out", json.dumps(big))
    line = s.log_path.read_text(encoding="utf-8").splitlines()[0]
    obj = json.loads(line.split(None, 2)[2])  # still parses: the viewer reads tool names and results from it
    assert obj["part"]["tool"] == "decomp_get_context" and "more characters" in obj["part"]["state"]["output"]
    assert len(line) < agents.LOG_LINE + 20


def test_helpers_on_one_provider_wait_together():
    m = agents.Manager.__new__(agents.Manager)
    m.pauses = {}
    a = agents.Session("opencode-1", "opencode", "opencode #1", "p", "a", {"model": "zai-coding-plan/glm-5.3"})
    b = agents.Session("opencode-2", "opencode", "opencode #2", "p", "b", {"model": "zai-coding-plan/glm-5.2"})
    c = agents.Session("opencode-3", "opencode", "opencode #3", "p", "c", {"model": "opencode/deepseek-v4.1-flash-free"})
    assert m.provider(a) == m.provider(b) != m.provider(c)
    m.pause_provider(a, 600, "Usage limit reached")
    until, why = m.pauses[m.provider(b)]  # b never hit it: it waits because a did
    assert until > __import__("time").time() + 500 and why == "Usage limit reached"
    assert m.provider(c) not in m.pauses
    m.pause_provider(a, 10, "shorter")  # a shorter pause never shortens a longer one
    assert m.pauses[m.provider(a)][1] == "Usage limit reached"


def test_the_providers_own_words_are_kept():
    said = ('Streaming failed. "message":"Usage limit reached for 5 hour. Your limit will reset at 2026-10-18 02:22:34",'
            '"statusCode":429')
    words = agents._provider_words(agents._LIMIT, said)
    assert "Usage limit reached for 5 hour" in words and "reset at 2026-10-18 02:22:34" in words
    assert agents._provider_words(agents._LIMIT, "all fine") == ""


def test_a_helper_reports_its_waiting_and_progress(tmp_path):
    s = session(tmp_path)
    s.state, s.wait_until, s.wait_reason, s.shell_calls, s.last_progress = "waiting", 123.0, "limit", 4, 99.0
    snap = s.snapshot()
    assert (snap["wait_until"], snap["wait_reason"], snap["shell_calls"], snap["last_progress"]) == (123.0, "limit", 4, 99.0)
    s.state = "working"
    assert s.snapshot()["wait_until"] == 0  # not waiting any more


def test_old_logs_are_deleted_and_recent_ones_stay(tmp_path):
    import os
    import time

    m = _bare(tmp_path)
    m.log_dir.mkdir()
    old, new, half = (m.log_dir / n for n in ("old.log", "new.log", "old.log.1"))
    for p in (old, new, half):
        p.write_text("x")
    week_ago = time.time() - 8 * 86400
    os.utime(old, (week_ago, week_ago))
    os.utime(half, (week_ago, week_ago))
    assert m.prune_logs() == 2 and new.exists() and not old.exists() and not half.exists()
    assert m.log_file("new").name == "new.log"
