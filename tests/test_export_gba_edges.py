"""GBA exports preserve repaired inventories and assembly that shares literal pools."""

import json
import runpy
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from decompnet import toolchains
from decompnet.rom import export_gba
from decompnet.rom.symbols import Symbol, SymbolTable


def test_batch_sources_keep_other_game_functions_as_prototypes():
    source = "int helper(int n) { return n + 1; }\nint entry(int n) { return helper(n); }\n"
    isolated = export_gba.standalone_source(source, "entry")
    assert "int helper(int n);" in isolated
    assert "int entry(int n) { return helper(n); }" in isolated
    assert "return n + 1" not in isolated
    assert export_gba.standalone_source(isolated, "entry") == isolated


def test_existing_data_addresses_do_not_allocate_new_common_objects():
    source = "u8 D_08001234[];\nextern u32 D_08005678;\nstatic u32 count;\n"
    isolated = export_gba.standalone_source(source, "entry")
    assert isolated == "extern u8 D_08001234[];\nextern u32 D_08005678;\nstatic u32 count;\n"


def test_source_isolation_preserves_attributed_types_and_same_line_definitions():
    source = "typedef struct __attribute__((packed, aligned(2))) {unsigned short x,y;} Pair;\n"
    source += "void first(Pair *p) {p->x=1;} void entry(Pair *p) {p->y=2;} void last(Pair *p) {p->x=3;}\n"
    isolated = export_gba.standalone_source(source, "entry")
    assert source.splitlines()[0] in isolated
    assert "void first(Pair *p);" in isolated
    assert "void last(Pair *p);" in isolated
    assert "void entry(Pair *p) {p->y=2;}" in isolated
    assert export_gba.standalone_source(isolated, "entry") == isolated


def test_data_declarations_do_not_rewrite_array_return_expressions():
    source = "extern short D_08001234[];\nshort entry(int i)\n{\n return D_08001234[(i+4)&255];\n}\n"
    assert export_gba.standalone_source(source, "entry") == source


def test_export_does_not_turn_data_and_absorbed_blocks_back_into_functions(tmp_path, monkeypatch):
    base = 0x08000000
    (tmp_path / "rom.gba").write_bytes(bytes(32))
    rows = [dict(name=name, vram=base + off, target=bytes(4), asm="", status="open", meta=json.dumps(meta))
            for name, off, meta in [("entry", 0, {}), ("data", 4, {"asm_code": "not code (data)"}),
                                     ("block", 8, {"asm_code": "part of entry (merged into it)"})]]
    table = SymbolTable([Symbol(r["name"], r["vram"], 4, "func") for r in rows])
    net = SimpleNamespace(
        _project=lambda slug: {"id": 1, "root": str(tmp_path), "name": "test"},
        cfg=lambda p: {"rom": {"file": "rom.gba"}, "compiler": {}},
        store=SimpleNamespace(all=lambda *args: rows), symbols=lambda pid: table,
        _unit_contexts=lambda pid: {}, _context=lambda pid: {"header": ""})
    monkeypatch.setattr(export_gba.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=0, stdout="identical", stderr=""))
    out = tmp_path / "export"
    export_gba.export_gba(net, "test", out, log=lambda *_: None)
    config = json.loads((out / "build.json").read_text())
    assert [f["name"] for f in config["functions"]] == ["entry"]
    assert config["symbols"]["data"] == base + 4
    assert config["symbols"]["block"] == base + 8


@pytest.mark.skipif(toolchains.installed("arm-gnu") is None, reason="needs the Arm GNU toolchain")
def test_shared_literal_load_assembles_to_its_original_bytes(tmp_path):
    source = Path(export_gba.__file__).with_name("export_gba_build.py")
    shutil.copyfile(source, tmp_path / "build.py")
    (tmp_path / "build.json").write_text("{}")
    builder = runpy.run_path(str(tmp_path / "build.py"), run_name="export_test")
    (tmp_path / "asm").mkdir()
    text = ".syntax unified\n.thumb\n.text\nldr r0, _08000208\nbx lr\n"
    (tmp_path / "asm" / "entry.s").write_text(text)
    path = builder["assembly_input"]({"src": "asm/entry.s", "addr": 0x08000200})
    arm = toolchains.ensure("arm-gnu", log=lambda *_: None) / "bin"
    subprocess.run([str(arm / "arm-none-eabi-as"), "-mcpu=arm7tdmi", "-o", "out.o", path], cwd=tmp_path, check=True)
    subprocess.run([str(arm / "arm-none-eabi-objcopy"), "-O", "binary", "out.o", "out.bin"], cwd=tmp_path, check=True)
    assert (tmp_path / "out.bin").read_bytes() == bytes.fromhex("0148 7047")
    assert (tmp_path / "asm" / "entry.s").read_text() == text


@pytest.mark.skipif(toolchains.installed("arm-gnu") is None, reason="needs the Arm GNU toolchain")
@pytest.mark.parametrize("callee", ["sub_08000210", "D_08000210", "_08000210"])
def test_renamed_thumb_calls_link_without_adding_veneers(tmp_path, callee):
    shutil.copyfile(Path(export_gba.__file__).with_name("export_gba_build.py"), tmp_path / "build.py")
    config = {"base": 0x08000200, "symbols": {},
              "functions": [{"name": "entry", "addr": 0x08000200, "size": 6, "thumb": True}]}
    (tmp_path / "build.json").write_text(json.dumps(config))
    builder = runpy.run_path(str(tmp_path / "build.py"), run_name="export_test")
    (tmp_path / "asm").mkdir()
    (tmp_path / "asm" / "pieces.json").write_text("[]")
    (tmp_path / "build" / "src").mkdir(parents=True)
    (tmp_path / "entry.s").write_text(f".syntax unified\n.thumb\n.text\n.global entry\n.thumb_func\nentry:\nbl {callee}\nbx lr\n")
    arm = toolchains.ensure("arm-gnu", log=lambda *_: None) / "bin"
    obj = "build/src/entry.o"
    subprocess.run([str(arm / "arm-none-eabi-as"), "-mcpu=arm7tdmi", "-o", obj, "entry.s"], cwd=tmp_path, check=True)
    script = builder["linker_script"]([(0x08000200, obj, ".text")], {"entry": obj})
    (tmp_path / "game.ld").write_text(script)
    subprocess.run([str(arm / "arm-none-eabi-ld"), "-T", "game.ld", "-o", "out.elf", obj], cwd=tmp_path, check=True)
    subprocess.run([str(arm / "arm-none-eabi-objcopy"), "-O", "binary", "out.elf", "out.bin"], cwd=tmp_path, check=True)
    assert (tmp_path / "out.bin").read_bytes() == bytes.fromhex("00f0 06f8 7047")


@pytest.mark.skipif(toolchains.installed("arm-gnu") is None, reason="needs the Arm GNU toolchain")
def test_a_verified_halfword_function_links_at_its_recorded_address(tmp_path):
    shutil.copyfile(Path(export_gba.__file__).with_name("export_gba_build.py"), tmp_path / "build.py")
    config = {"base": 0x08000200, "symbols": {},
              "functions": [{"name": "entry", "addr": 0x08000202, "size": 2, "thumb": True}]}
    (tmp_path / "build.json").write_text(json.dumps(config))
    builder = runpy.run_path(str(tmp_path / "build.py"), run_name="export_test")
    (tmp_path / "asm").mkdir()
    (tmp_path / "asm" / "pieces.json").write_text("[]")
    (tmp_path / "build" / "src").mkdir(parents=True)
    (tmp_path / "entry.s").write_text(".syntax unified\n.thumb\n.text\n.balign 4\n.global entry\n.type entry,%function\n.thumb_func\nentry:\nbx lr\n.size entry,.-entry\n")
    arm = toolchains.ensure("arm-gnu", log=lambda *_: None) / "bin"
    obj = "build/src/entry.o"
    subprocess.run([str(arm / "arm-none-eabi-as"), "-mcpu=arm7tdmi", "-o", obj, "entry.s"], cwd=tmp_path, check=True)
    builder["trim"](tmp_path / obj, alignment=2)
    script = builder["linker_script"]([(0x08000202, obj, ".text")], {"entry": obj})
    (tmp_path / "game.ld").write_text(script)
    subprocess.run([str(arm / "arm-none-eabi-ld"), "-T", "game.ld", "-o", "out.elf", obj], cwd=tmp_path, check=True)
    subprocess.run([str(arm / "arm-none-eabi-objcopy"), "-O", "binary", "out.elf", "out.bin"], cwd=tmp_path, check=True)
    assert (tmp_path / "out.bin").read_bytes() == bytes.fromhex("0000 7047")


@pytest.mark.skipif(toolchains.installed("arm-gnu") is None, reason="needs the Arm GNU toolchain")
@pytest.mark.parametrize("thumb", [False, True, "mixed"])
@pytest.mark.parametrize("addend", [0, 4])
def test_pointer_to_a_function_outside_the_export_inventory_keeps_its_mode(tmp_path, thumb, addend):
    shutil.copyfile(Path(export_gba.__file__).with_name("export_gba_build.py"), tmp_path / "build.py")
    mixed = thumb == "mixed"
    expected = bytes.fromhex("0048 7047") + (0x08000210 + addend + int(thumb is True)).to_bytes(4, "little")
    if mixed:
        expected += (0x08000211 + addend).to_bytes(4, "little")
    (tmp_path / "base.gba").write_bytes(expected)
    config = {"base": 0x08000200, "image": "base.gba", "symbols": {"sub_08000210": 0x08000210},
              "functions": [{"name": "entry", "addr": 0x08000200, "size": len(expected), "thumb": True}]}
    (tmp_path / "build.json").write_text(json.dumps(config))
    builder = runpy.run_path(str(tmp_path / "build.py"), run_name="export_test")
    (tmp_path / "asm").mkdir()
    (tmp_path / "asm/pieces.json").write_text("[]")
    (tmp_path / "build/src").mkdir(parents=True)
    (tmp_path / "entry.s").write_text('.syntax unified\n.thumb\n.text\n.global entry\n.thumb_func\n'
                                      f'entry:\nldr r0, pool\nbx lr\npool: .word sub_08000210+{addend}\n'
                                      + (f'.word sub_08000210+{addend}\n' if mixed else ''))
    arm = toolchains.ensure("arm-gnu", log=lambda *_: None) / "bin"
    obj = "build/src/entry.o"
    subprocess.run([str(arm / "arm-none-eabi-as"), "-mcpu=arm7tdmi", "-o", obj, "entry.s"], cwd=tmp_path, check=True)
    items = [(0x08000200, obj, ".text")]
    if mixed:
        with pytest.raises(SystemExit, match="conflicting pointer modes"):
            builder["linker_script"](items, {"entry": obj})
        return
    script = builder["linker_script"](items, {"entry": obj})
    (tmp_path / "game.ld").write_text(script)
    subprocess.run([str(arm / "arm-none-eabi-ld"), "-T", "game.ld", "-o", "out.elf",
                    *[item[1] for item in items]], cwd=tmp_path, check=True)
    subprocess.run([str(arm / "arm-none-eabi-objcopy"), "-O", "binary", "out.elf", "out.bin"], cwd=tmp_path, check=True)
    assert (tmp_path / "out.bin").read_bytes() == expected


@pytest.mark.skipif(toolchains.installed("arm-gnu") is None, reason="needs the Arm GNU toolchain")
def test_reference_piece_padding_does_not_overlap_a_halfword_c_function(tmp_path):
    from elftools.elf.elffile import ELFFile

    shutil.copyfile(Path(export_gba.__file__).with_name("export_gba_build.py"), tmp_path / "build.py")
    (tmp_path / "build.json").write_text("{}")
    builder = runpy.run_path(str(tmp_path / "build.py"), run_name="export_test")
    (tmp_path / "entry.s").write_text(".syntax unified\n.thumb\n.text\n.balign 4\n.global entry\n.type entry,%function\nentry:\nmovs r0,0\n")
    arm = toolchains.ensure("arm-gnu", log=lambda *_: None) / "bin"
    subprocess.run([str(arm / "arm-none-eabi-as"), "-mcpu=arm7tdmi", "-o", "entry.o", "entry.s"], cwd=tmp_path, check=True)
    builder["trim"](tmp_path / "entry.o", extent=2)
    with open(tmp_path / "entry.o", "rb") as stream:
        assert ELFFile(stream).get_section_by_name(".text").data() == bytes.fromhex("0020")


@pytest.mark.skipif(any(toolchains.installed(t) is None for t in ("agbcc", "arm-gnu")), reason="needs both bundled agbcc compilers")
@pytest.mark.parametrize("saved_variant", [False, True])
def test_export_recovers_and_records_the_matching_bundled_compiler(tmp_path, saved_variant):
    from io import BytesIO

    from elftools.elf.elffile import ELFFile

    from decompnet.compiler import compile_source
    from decompnet.elfobj import _function_symbols
    from decompnet.project import compiler_config

    compiler = {"toolchain": "agbcc", "flags": ["-mthumb-interwork", "-O2"]}
    source = ("typedef short s16; typedef int s32; typedef unsigned long long u64;\n"
              "u64 entry(s16 *out,s16 *p){s32 x=p[5],y=p[7];out[0]=x-7;out[1]=y-4;out[2]=x+7;out[3]=y+5;}\n")
    old = compile_source(compiler_config(tmp_path, {"compiler": compiler | {"variant": "old_agbcc"}}), "", source)
    assert old.ok, old.log
    elf = ELFFile(BytesIO(old.obj))
    section, offset, size = _function_symbols(elf)["entry"]
    offset &= ~1
    target = elf.get_section(section).data()[offset:offset + size]
    config = {"compiler": compiler}
    if saved_variant:
        config["compiler_ranges"] = [{"start": 0x08000200, "end": 0x08000200 + len(target),
                                      **compiler, "variant": "old_agbcc"}]
    calls = []

    def compile_one(proj, header, candidate, row):
        cfg = json.loads(proj["config"])
        from decompnet.project import compiler_for
        cfg["compiler"] = compiler_for(cfg, row["vram"])
        calls.append(cfg["compiler"].get("variant"))
        return compile_source(compiler_config(tmp_path, cfg), header, candidate)

    net = SimpleNamespace(_context=lambda pid, unit: {"header": ""}, _effective_unit=lambda row, units: "",
                          _compile=compile_one, symbols=lambda pid: SymbolTable([]), reader=lambda p: lambda a, n: None)
    proj = {"id": 1, "config": json.dumps(config)}
    row = {"name": "entry", "vram": 0x08000200, "target": target, "matched_source": source}
    fn = {}
    assert export_gba._check_c(net, proj, row, True, {}, fn) is None
    assert calls == (["old_agbcc"] if saved_variant else [None, "old_agbcc"])
    assert fn["compiler"] == {"variant": "old_agbcc"}
    assert json.loads(proj["config"]) == config


@pytest.mark.skipif(toolchains.installed("agbcc") is None, reason="needs the pinned agbcc toolchain")
def test_compiler_variant_cannot_select_an_arbitrary_executable(tmp_path):
    from decompnet.project import compiler_config

    with pytest.raises(ValueError, match="supported compiler variant"):
        compiler_config(tmp_path, {"compiler": {"toolchain": "agbcc", "variant": "../other"}})


@pytest.mark.parametrize("broken", [False, True])
def test_saved_compiler_variants_are_scoped_and_preserve_matches(broken):
    from contextlib import nullcontext

    from decompnet.app.engine.compilers import CompilerMixin
    from decompnet.network import NetworkError
    from decompnet.project import compiler_for

    cfg = {"compiler": {"toolchain": "agbcc", "flags": ["-O2"]}}
    fn = {"name": "entry", "vram": 0x08000200, "unit": ""}

    class Net(CompilerMixin):
        def fork_slug(self, slug):
            return False

        def _project(self, slug):
            return {"id": 1}

        def cfg(self, proj):
            return cfg

        def _update_cfg(self, slug, change):
            change(cfg)

        def regression_test(self, proj, header, only, header_for):
            assert only == [fn]
            assert compiler_for(cfg, fn["vram"])["variant"] == "old_agbcc"
            assert "variant" not in compiler_for(cfg, fn["vram"] + 4)
            return [("entry", "mismatch")] if broken else []

        def _event(self, *args):
            pass

    net = Net()
    net.store = SimpleNamespace(all=lambda *args: [fn], tx=lambda: nullcontext(None))
    if broken:
        with pytest.raises(NetworkError, match="wouldn't match"):
            net.set_compiler_ranges("game", [[fn["vram"], fn["vram"] + 4]], "agbcc", ["-O2"], variant="old_agbcc")
        assert cfg["compiler_ranges"] == []
    else:
        net.set_compiler_ranges("game", [[fn["vram"], fn["vram"] + 4]], "agbcc", ["-O2"], variant="old_agbcc")
        assert cfg["compiler_ranges"][0]["variant"] == "old_agbcc"
    with pytest.raises(NetworkError, match="supported compiler variant"):
        net.set_compiler_ranges("game", [[0, 4]], "agbcc", variant="../other")


@pytest.mark.parametrize("score", [None, 3, 0])
def test_only_matching_source_corrections_replace_saved_source(score):
    import sqlite3
    from contextlib import nullcontext

    from decompnet.network import Network, NetworkError

    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.execute("CREATE TABLE functions(id, project_id, name, status, matched_source, best_source, matched_agent_id, matched_at)")
    db.execute("INSERT INTO functions VALUES(1, 2, 'entry', 'matched', 'original', 'original', 7, 123)")
    net = SimpleNamespace(_function=lambda *args: db.execute("SELECT * FROM functions").fetchone(),
                          attempt=lambda *args: {"score": score}, store=SimpleNamespace(tx=lambda: nullcontext(db)),
                          _event=lambda *args: None)
    if score == 0:
        assert Network.replace_matched_source(net, SimpleNamespace(id=8), "entry", "corrected")["matched"]
    else:
        with pytest.raises(NetworkError, match="must still match"):
            Network.replace_matched_source(net, SimpleNamespace(id=8), "entry", "corrected")
    row = db.execute("SELECT * FROM functions").fetchone()
    assert row["matched_source"] == row["best_source"] == ("corrected" if score == 0 else "original")
    assert (row["status"], row["matched_agent_id"], row["matched_at"]) == ("matched", 7, 123)
    db.execute("UPDATE functions SET status='open'")
    with pytest.raises(NetworkError, match="only a matched function"):
        Network.replace_matched_source(net, SimpleNamespace(id=8), "entry", "corrected")
    db.close()
