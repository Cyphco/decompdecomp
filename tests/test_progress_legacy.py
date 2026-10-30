"""Old saves retain empty rows absorbed into another function, along with their attempt history."""

import json

import pytest

from decompnet.app import saves
from decompnet.app.progress import Progress, _manifest
from decompnet.network import NetworkError

from .test_progress import project  # noqa: F401


def saved(size=0, reason="part of parent (merged into it)", address=4100):
    data = {"format": saves.FORMAT, "game": {"sha1": "demo"}, "headers": {"": "common.h"},
            "layout": [{"name": "empty", "vram": 4100, "size": size}],
            "set_aside": [{"name": "empty", "vram": address, "asm_code": reason}]}
    return {saves.MANIFEST: json.dumps(data), "include/common.h": "", "best/empty.c": "old candidate"}


def test_a_legacy_empty_merged_row_keeps_its_saved_candidate():
    data = _manifest(saved(), {"rom": {"sha1": "demo"}})
    assert data["layout"] == [{"name": "empty", "vram": 4100, "size": 0}]
    assert data["functions"]["empty"]["vram"] == 4100


@pytest.mark.parametrize("changes", [{"size": -1}, {"reason": "handwritten assembly"}, {"address": 4104}])
def test_zero_or_negative_unclassified_rows_still_fail_validation(changes):
    with pytest.raises(NetworkError, match="Fix progress"):
        _manifest(saved(**changes), {"rom": {"sha1": "demo"}})


def test_first_sync_preserves_a_legacy_empty_merged_row(project):  # noqa: F811
    net, folder, judged = project
    with net.store.tx() as db:
        db.execute("UPDATE functions SET size=0,status='asm',target=X'',best_source='old candidate',best_score=100,"
                   "meta=? WHERE name='g'", (json.dumps({"asm_code": "part of f (merged into it)"}),))
    net.progress.sync("game", force=True)
    path = folder / saves.MANIFEST
    data = json.loads(path.read_text())
    for entry in data["layout"]:
        entry.pop("status", None)  # older saves stored this only in set_aside
    data.pop("revision", None)
    path.write_text(json.dumps(data), encoding="utf-8")
    before = dict(net.store.one("SELECT * FROM functions WHERE name='g'"))
    with net.store.tx() as db:
        db.execute("DELETE FROM progress_state")
        db.execute("DELETE FROM progress_files")
    net.progress = Progress(net)
    net.progress.sync("game", force=True)
    assert dict(net.store.one("SELECT * FROM functions WHERE name='g'")) == before
    assert (folder / "best/g.c").read_text().strip() == "old candidate"
    assert not judged
    assert not net.progress.sync("game", force=True)


def legacy_restart(net, folder):
    path = folder / saves.MANIFEST
    data = json.loads(path.read_text())
    data.pop("revision", None)
    path.write_text(json.dumps(data), encoding="utf-8")
    with net.store.tx() as db:
        db.execute("DELETE FROM progress_state")
        db.execute("DELETE FROM progress_files")
    net.progress = Progress(net)


@pytest.mark.parametrize("changed_address", [False, True])
def test_first_sync_compares_symbols_by_identity(project, changed_address):  # noqa: F811
    net, folder, judged = project
    with net.store.tx() as db:
        db.execute("INSERT INTO symbols(project_id,name,address,size,kind) VALUES(1,'first',4096,4,'func')")
        db.execute("INSERT INTO symbols(project_id,name,address,size,kind) VALUES(1,'second',4100,4,'func')")
        db.execute("UPDATE functions SET status='matched',matched_source='good original' WHERE name='f'")
    net.progress.sync("game", force=True)
    path = folder / saves.MANIFEST
    data = json.loads(path.read_text())
    data["symbols"].reverse()
    if changed_address:
        data["symbols"][0]["address"] += 4
    path.write_text(json.dumps(data), encoding="utf-8")
    legacy_restart(net, folder)
    judged.clear()
    net.progress.sync("game", force=True)
    assert bool(judged) == changed_address


def test_first_sync_restores_the_spelling_trimmed_by_an_old_save(project):  # noqa: F811
    net, folder, judged = project
    original = "\nint good_value;\r\nint good_f(void) { return __LINE__; }\r\n\r\n"
    with net.store.tx() as db:
        db.execute("UPDATE functions SET status='matched',matched_source=? WHERE name='f'", (original,))
    net.progress.sync("game", force=True)
    path = folder / "src/f.c"
    path.write_text(original.strip() + "\n", encoding="utf-8")
    legacy_restart(net, folder)
    before = dict(net.store.one("SELECT * FROM functions WHERE name='f'"))
    judged.clear()
    messages = []
    net.progress.sync("game", force=True, logger=messages.append)
    assert not judged
    assert not any(line.startswith(("checking ", "judging ")) for line in messages)
    assert any("0 source checks" in line for line in messages)
    assert dict(net.store.one("SELECT * FROM functions WHERE name='f'")) == before
    assert path.read_text().startswith("\nint good_value")  # retain __LINE__, not the old trimmed spelling
    assert not net.progress.sync("game", force=True)


def test_first_sync_still_judges_an_actual_source_edit(project):  # noqa: F811
    net, folder, judged = project
    with net.store.tx() as db:
        db.execute("UPDATE functions SET status='matched',matched_source='good original',matched_at=1 WHERE name='f'")
    net.progress.sync("game", force=True)
    (folder / "src/f.c").write_text("good changed", encoding="utf-8")
    legacy_restart(net, folder)
    judged.clear()
    messages = []
    net.progress.sync("game", force=True, logger=messages.append)
    assert ("f", "good changed") in judged
    assert "checking f" in messages
    assert any("1 source checks" in line for line in messages)
