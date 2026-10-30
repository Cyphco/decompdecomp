"""Export reads edited progress files before choosing the sources to rebuild."""

import json
from types import SimpleNamespace

import pytest

from decompnet.app import saves
from decompnet.network import NetworkError

from .test_progress import project  # noqa: F401


def test_export_rejudges_an_in_place_source_edit_before_selecting_sources(project, monkeypatch):  # noqa: F811
    net, folder, judged = project
    (folder / "src").mkdir()
    source = folder / "src/f.c"
    source.write_text("good original")
    net.progress.sync("game", force=True)
    source.write_text("good changed")
    exported = []

    def export(net, slug, out, log):
        exported.append(net._function("f", slug)["matched_source"])
        return {"path": str(out), "identical": True}

    monkeypatch.setattr(net, "console", lambda _: SimpleNamespace(export=export))
    net.export_rom("game", log=lambda _: None)
    assert exported == ["good changed"]
    assert judged == [("f", "good original"), ("f", "good changed")]


def test_export_refuses_conflicted_progress_before_touching_the_output(project, monkeypatch):  # noqa: F811
    net, folder, _ = project
    (folder / saves.MANIFEST).write_text("<<<<<<< HEAD\n=======\n>>>>>>> other")
    monkeypatch.setattr(net, "console", lambda _: pytest.fail("export reached the console"))
    with pytest.raises(NetworkError):
        net.export_rom("game", log=lambda _: None)


def test_complete_knowledge_survives_progress_save_and_reload(project):  # noqa: F811
    net, folder, _ = project
    recipe = "Ownership details:\n" + "    keep(&temporary);\n" * 80 + "Final operation."
    agent, _ = net.local_agent("writer")
    net.knowledge.share(agent, "game", recipe)
    number = net.knowledge.listing("game")["items"][0]["id"]
    net.knowledge.decide("game", number, True)
    net.progress.sync("game", force=True)
    manifest = json.loads((folder / saves.MANIFEST).read_text())
    assert manifest["knowledge"] == [recipe]
    manifest["knowledge"] = [recipe + "\nAnother finding."]
    (folder / saves.MANIFEST).write_text(json.dumps(manifest), encoding="utf-8")
    net.progress.sync("game", force=True)
    assert net.knowledge.listing("game")["items"][0]["text"] == recipe + "\nAnother finding."


def test_export_refuses_unjudged_edits_when_the_compiler_is_unknown(project, monkeypatch):  # noqa: F811
    net, folder, judged = project
    (folder / "src").mkdir()
    source = folder / "src/f.c"
    source.write_text("good original")
    net.progress.sync("game", force=True)
    compiler = {"toolchain": "missing-test-compiler"}
    net._update_cfg("game", lambda cfg: cfg.__setitem__("compiler", compiler))
    manifest = json.loads((folder / saves.MANIFEST).read_text())
    manifest["compiler"] = compiler
    (folder / saves.MANIFEST).write_text(json.dumps(manifest), encoding="utf-8")
    source.write_text("good changed")
    monkeypatch.setattr(net, "console", lambda _: pytest.fail("export reached the console"))
    with pytest.raises(NetworkError, match="isn't a compiler"):
        net.export_rom("game", log=lambda _: None)
    assert judged == [("f", "good original")]
    assert source.read_text() == "good changed"
