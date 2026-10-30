"""The exported GBA build compiles independently, with bounded work and stable linker input order."""

import importlib.util
import json
import shutil
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from decompnet.consoles.gba import export


@pytest.fixture
def build(tmp_path):
    source = Path(__file__).resolve().parents[1] / "src/decompnet/consoles/gba/export_build.py"
    shutil.copyfile(source, tmp_path / "build.py")
    (tmp_path / "asm").mkdir()
    (tmp_path / "asm/pieces.json").write_text("[]", encoding="utf-8")
    (tmp_path / "src").mkdir()
    functions = []
    for index in range(16):
        name = f"func_{index}"
        path = f"src/{name}.c"
        (tmp_path / path).write_text(name, encoding="utf-8")
        functions.append({"name": name, "addr": 0x08000000 + index * 2, "c": path})
    (tmp_path / "build.json").write_text(json.dumps({"compiler": {}, "functions": functions}), encoding="utf-8")
    spec = importlib.util.spec_from_file_location("exported_gba_build", tmp_path / "build.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_c_builds_are_bounded_parallel_and_results_keep_function_order(build, monkeypatch):
    barrier = threading.Barrier(8)
    lock = threading.Lock()
    active = peak = 0
    trimmed = []

    def compile_source(cfg, header, source):
        nonlocal active, peak
        assert str(build.ROOT / "include") in cfg.include_dirs
        with lock:
            active += 1
            peak = max(peak, active)
        if int(source.split("_")[1]) < 8:
            barrier.wait(timeout=5)
        with lock:
            active -= 1
        return SimpleNamespace(ok=True, obj=source.encode(), log="")

    monkeypatch.setattr(build, "compiler_config", lambda *_: SimpleNamespace(include_dirs=()))
    monkeypatch.setattr(build, "compile_source", compile_source)
    monkeypatch.setattr(build, "trim", lambda path, alignment: trimmed.append((path.name, alignment)))
    pieces, objects = build.build_objects()
    assert not pieces
    assert peak == 8
    assert list(objects) == [f"func_{index}" for index in range(16)]
    for index in range(16):
        assert (build.ROOT / objects[f"func_{index}"]).read_bytes() == f"func_{index}".encode()
        assert (f"func_{index}.o", 2 if index % 2 else 4) in trimmed


def test_a_failed_parallel_compile_still_fails_the_build(build, monkeypatch):
    monkeypatch.setattr(build, "compiler_config", lambda *_: SimpleNamespace(include_dirs=()))
    monkeypatch.setattr(build, "compile_source", lambda *_: SimpleNamespace(ok=False, log="syntax error"))
    with pytest.raises(SystemExit, match="compiling src/func_0.c failed.*"):
        build.build_objects()


@pytest.fixture
def preflight(tmp_path, monkeypatch):
    (tmp_path / "rom.gba").write_bytes(bytes(64))
    cfg = {"rom": {"file": "rom.gba"}, "compiler": {"toolchain": "agbcc", "flags": ["-O2"]}}
    proj = {"id": 1, "root": str(tmp_path), "name": "Demo", "config": json.dumps(cfg)}
    rows = [{"name": f"func_{i}", "vram": 0x08000000 + 2 * i, "target": bytes(2), "meta": None,
             "asm": "", "status": "matched", "matched_source": f"int func_{i}(void) {{ return {i}; }}"}
            for i in range(18)]
    rows[16].update(status="open", matched_source=None)
    rows[17]["meta"] = json.dumps({"asm_code": "not code"})
    net = SimpleNamespace(_project=lambda _: proj, cfg=lambda _: cfg,
                          store=SimpleNamespace(all=lambda *_: rows),
                          symbols=lambda _: SimpleNamespace(by_name={}),
                          _unit_contexts=lambda _: set(), _context=lambda _: {"header": ""})
    builds = []

    def run(*args, **kwargs):
        builds.append(args)
        return SimpleNamespace(returncode=0, stdout="identical", stderr="")

    monkeypatch.setattr(export.subprocess, "run", run)
    monkeypatch.setattr(export, "capped", lambda command: command)
    return net, tmp_path / "out", builds


def test_preflight_keeps_address_order_and_individual_fallbacks(preflight, monkeypatch):
    net, out, builds = preflight
    barrier = threading.Barrier(8)
    lock = threading.Lock()
    active = peak = 0

    def check(net, proj, row, thumb, units, fn):
        nonlocal active, peak
        index = int(row["name"].split("_")[1])
        with lock:
            active += 1
            peak = max(peak, active)
        if index < 8:
            barrier.wait(timeout=5)
        if index == 5:
            fn["language"] = "c++"
        with lock:
            active -= 1
        return "no longer matches" if index in (3, 9) else None

    monkeypatch.setattr(export, "_check_c", check)
    result = export.export_gba(net, "demo", out, log=lambda _: None)
    manifest = json.loads((out / "build.json").read_text())
    assert peak == 8
    assert [fn["name"] for fn in manifest["functions"]] == [f"func_{i}" for i in range(17)]
    assert result["fallback"] == [("func_3", "no longer matches"), ("func_9", "no longer matches")]
    assert result["matched"] == 14 and result["functions"] == 17
    assert manifest["functions"][5]["c"] == "src/func_5.cpp"
    assert all("c" not in manifest["functions"][i] for i in (3, 9, 16))
    assert not (out / "src/func_3.c").exists()
    assert len(builds) == 1 and result["identical"]


def test_an_unexpected_preflight_error_does_not_start_the_build(preflight, monkeypatch):
    net, out, builds = preflight

    def broken(*args):
        raise ValueError("preflight failed")

    monkeypatch.setattr(export, "_check_c", broken)
    with pytest.raises(ValueError, match="preflight failed"):
        export.export_gba(net, "demo", out, log=lambda _: None)
    assert not builds
