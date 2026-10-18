"""GBA C++ compilers are pinned, selected per function, and preserved by export."""

import json
import runpy
import shutil
from pathlib import Path
from types import SimpleNamespace

from decompnet import toolchains
from decompnet.compiler import CompileResult
from decompnet.project import compiler_config, compiler_for
from decompnet.rom import export_gba


def test_cpp_range_keeps_existing_c_assignments_and_drops_another_compilers_variant():
    cfg = {"compiler": {"toolchain": "agbcc", "flags": ["-O2"], "variant": "old_agbcc"},
           "compiler_ranges": [{"start": 0x100, "end": 0x200, "toolchain": "agbcp", "flags": ["-O2"]},
                               {"start": 0x300, "end": 0x400, "toolchain": "agbcc", "flags": ["-O2"],
                                "variant": "old_agbcc"}]}
    assert compiler_for(cfg, 0x80) == cfg["compiler"]
    assert compiler_for(cfg, 0x120) == {"toolchain": "agbcp", "flags": ["-O2"]}
    assert compiler_for(cfg, 0x320)["variant"] == "old_agbcc"


def test_cpp_prelude_uses_the_pinned_directory_mounted_in_the_sandbox(tmp_path, monkeypatch):
    pinned = tmp_path / "pinned"
    monkeypatch.setattr(toolchains, "runtime_dirs", lambda tid: (pinned,))
    monkeypatch.setattr(toolchains, "path", lambda *args: tmp_path / "arm-gnu")
    monkeypatch.setattr(toolchains.wsl, "wanted", lambda: False)
    cfg = compiler_config(tmp_path, {"compiler": {"toolchain": "agbcp"}})
    assert cfg.cplusplus
    assert "{tc}" not in cfg.prelude
    assert f"{pinned}/cpp-include" in cfg.prelude
    assert str(pinned) in cfg.ro_paths
    assert all(len(part["sha256"]) == 64 for part in toolchains.get("agbcp").parts)


def test_export_keeps_cpp_template_helpers_and_out_of_line_methods():
    source = "template<class T> struct Alloc {T* make(int n);};\n"
    source += "template<class T> T* Alloc<T>::make(int n) {return (T*)0;}\n"
    source += "template<class T> T value(T x) {return x;}\n"
    source += 'extern "C" { int entry(int x) {return value(x);} }\n'
    assert export_gba.standalone_source(source, "entry") == source


def test_export_isolates_functions_inside_a_c_linkage_block():
    source = 'extern "C" { int helper(int x) {return x+1;} int entry(int x) {return helper(x);} }\n'
    isolated = export_gba.standalone_source(source, "entry")
    assert 'extern "C" {' in isolated
    assert "int helper(int x);" in isolated
    assert "return x+1;" not in isolated
    assert "int entry(int x) {return helper(x);}" in isolated
    assert export_gba.standalone_source(isolated, "entry") == isolated


def test_nested_linkage_blocks_do_not_expose_class_method_bodies():
    source = ('extern "C++" { struct Thing {int get() {return 3;}};\n'
              'extern "C" {int helper() {return 1;} int entry() {return helper();}} }\n')
    isolated = export_gba.standalone_source(source, "entry")
    assert "int get() {return 3;}" in isolated
    assert "int helper();" in isolated and "int helper() {" not in isolated
    assert "int entry() {return helper();}" in isolated


def test_exported_cpp_uses_the_same_prelude_and_language_selection_as_the_judge(tmp_path, monkeypatch):
    shutil.copyfile(Path(export_gba.__file__).with_name("export_gba_build.py"), tmp_path / "build.py")
    fn = {"name": "entry", "addr": 0x08000200, "size": 2, "compiler": {"toolchain": "agbcp"}}
    (tmp_path / "build.json").write_text(json.dumps({"compiler": {"toolchain": "agbcc"}, "functions": [fn]}))
    (tmp_path / "asm").mkdir()
    (tmp_path / "asm/pieces.json").write_text("[]")
    (tmp_path / "src").mkdir()
    (tmp_path / "src/entry.cpp").write_text('#include "common.h"\nclass Example {};\n')
    (tmp_path / "include").mkdir()
    (tmp_path / "include/common.h").write_text("typedef int Number;\n")
    builder = runpy.run_path(str(tmp_path / "build.py"), run_name="export_test")
    namespace = builder["build_objects"].__globals__
    seen = []
    cfg = SimpleNamespace(include_dirs=(), prelude="#include <vector>\n", cplusplus=True)
    monkeypatch.setitem(namespace, "compiler_config", lambda root, settings: cfg if settings["compiler"]["toolchain"] == "agbcp" else None)

    def compile_candidate(settings, context, source):
        seen.append((settings.prelude, settings.cplusplus, settings.include_dirs, context, source))
        return CompileResult(True, b"object", "", "c++")

    monkeypatch.setitem(namespace, "compile_source", compile_candidate)
    monkeypatch.setitem(namespace, "trim", lambda *args: None)
    pieces, objects = builder["build_objects"]()
    assert pieces == []
    assert objects == {"entry": "build/src/entry.o"}
    assert (tmp_path / objects["entry"]).read_bytes() == b"object"
    assert seen == [(cfg.prelude, True, (str(tmp_path / "include"),), "", '#include "common.h"\nclass Example {};\n')]
