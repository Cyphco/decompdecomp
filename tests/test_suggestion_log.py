"""The Suggestions tab: every suggestion with its outcome, newest first, with the range check that decided it."""

from decompnet.app.engine.gui import GuiMixin


def test_the_log_keeps_every_outcome_newest_first():
    cfg = {"suggestions": [
        {"id": 1, "text": "a", "toolchain": "agbcc", "flags": ["-O2"], "ranges": [[1, 2]], "agents": ["x"],
         "check": "range check #1: a quirk", "status": "dismissed", "t": 10},
        {"id": 2, "text": "b", "toolchain": None, "flags": [], "ranges": [], "agents": ["y"], "check": None,
         "status": "open", "t": 30},
        {"id": 3, "text": "c", "toolchain": "agbcc", "flags": [], "ranges": [], "agents": ["z"],
         "check": "f does not match with it", "status": "refused", "t": 20}],
        "range_checks": [{"id": 1, "suggestion": 1, "status": "quirk", "said": "a quirk: neighbours disagree"}]}
    log = GuiMixin._suggestion_log(cfg)
    assert [r["id"] for r in log] == [2, 3, 1]
    assert [r["status"] for r in log] == ["open", "refused", "dismissed"]
    assert log[2]["range_check"] == {"id": 1, "status": "quirk", "said": "a quirk: neighbours disagree"}
    assert log[0]["range_check"] is None
    assert len(GuiMixin._suggestion_log(cfg, limit=2)) == 2
