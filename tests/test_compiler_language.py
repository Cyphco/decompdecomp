"""Declared C++-only wrappers skip an impossible C attempt without inspecting the source's spelling."""

import pytest

from decompnet import compiler, project, toolchains, wsl
from decompnet.compiler import CompilerConfig, CompileResult, compile_source


@pytest.mark.parametrize("source", ["int class(void) { return 1; }", 'extern "C" int f() { return 1; }'])
def test_declared_cpp_only_compiles_once(monkeypatch, source):
    asked = []

    def compile_as(cfg, work, root, text, ext):
        asked.append(ext)
        return CompileResult(True, b"object", "", "c++")

    monkeypatch.setattr(compiler, "_compile_as", compile_as)
    result = compile_source(CompilerConfig(["unused"], language="c++"), "", source)
    assert asked == ["cpp"] and result.language == "c++"


@pytest.mark.parametrize("c_succeeds", [False, True])
def test_dual_language_keeps_c_first(monkeypatch, c_succeeds):
    asked = []

    def compile_as(cfg, work, root, source, ext):
        asked.append(ext)
        ok = c_succeeds or ext == "cpp"
        return CompileResult(ok, b"object" if ok else None, "compiler exited with 1", ext)

    monkeypatch.setattr(compiler, "_compile_as", compile_as)
    compile_source(CompilerConfig(["unused"], cplusplus=True), "", 'extern "C" int f() { return 1; }')
    assert asked == (["c"] if c_succeeds else ["c", "cpp"])


def test_cpp_only_errors_and_timeouts_are_not_retried(monkeypatch):
    asked = []

    def compile_as(cfg, work, root, source, ext):
        asked.append(ext)
        return CompileResult(False, None, "compiler timed out after 15s")

    monkeypatch.setattr(compiler, "_compile_as", compile_as)
    result = compile_source(CompilerConfig(["unused"], cplusplus=True, language="c++"), "", "int f();")
    assert asked == ["cpp"] and result.log.startswith("compiler timed out")


def test_cpp_only_still_checks_every_submission(monkeypatch):
    def unexpected(*args, **kwargs):
        pytest.fail("rejected source reached the compiler")

    monkeypatch.setattr(compiler, "_compile_as", unexpected)
    cfg = CompilerConfig(["unused"], language="c++")
    for _ in range(2):
        result = compile_source(cfg, "", 'void f() { asm("nop"); }')
        assert not result.ok and result.log.startswith("rejected:")


def test_cpp_only_honors_cancellation_before_subprocess(monkeypatch):
    class Cancelled(Exception):
        pass

    def cancel():
        raise Cancelled()

    def unexpected(*args, **kwargs):
        pytest.fail("cancelled compile launched a process")

    monkeypatch.setattr(compiler, "_exec", unexpected)
    with compiler.cancellable(cancel), pytest.raises(Cancelled):
        compile_source(CompilerConfig(["unused"], sandbox="none", language="c++"), "", "int f();")


def test_registry_language_applies_only_to_its_own_command(tmp_path, monkeypatch):
    monkeypatch.setattr(wsl, "wanted", lambda: False)
    monkeypatch.setattr(toolchains, "runtime_dirs", lambda tid: (tmp_path / tid, tmp_path / "arm-gnu"))
    assert toolchains.get("agbcp").language == "c++"
    assert project.compiler_config(tmp_path, {"compiler": {"toolchain": "agbcp"}}).language == "c++"
    for settings in ({"toolchain": "agbcp", "cmd": ["custom"]}, {"cmd": ["custom"]}, {"toolchain": "agbcc"}):
        assert project.compiler_config(tmp_path, {"compiler": settings}).language == "c"
