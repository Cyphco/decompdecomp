"""A toolchain that builds C and C++: what doesn't compile as C is tried as C++, and the error the agent reads is
the one that says something."""

from decompnet import compiler
from decompnet.compiler import CompilerConfig, CompileResult, compile_source


def _compilers(monkeypatch, c_log, cpp_log):
    asked = []

    def compile_as(cfg, work, root, source, ext):
        asked.append(ext)
        return CompileResult(False, None, c_log if ext == "c" else cpp_log)
    monkeypatch.setattr(compiler, "_compile_as", compile_as)
    return asked


def test_an_extern_c_function_gets_its_cpp_error(monkeypatch):
    """agbcp refuses C with a bare exit 1: an `extern "C"` function with a C++ mistake (a void* assigned to an int*)
    answered "compiler exited with 1", and two agents dropped functions on it, sure agbcp couldn't build them."""
    asked = _compilers(monkeypatch, "compiler exited with 1", "func.cpp:1: invalid conversion from `void *' to `int *'")
    cfg = CompilerConfig(["unused"], sandbox="none", cplusplus=True)
    result = compile_source(cfg, "", 'extern "C" int f(void *p) { int *q = p; return *q; }')
    assert asked == ["c", "cpp"] and "invalid conversion" in result.log


def test_c_that_the_compiler_explained_keeps_its_c_error(monkeypatch):
    """C that a C++-capable compiler rejected with a reason keeps that reason, not C++'s complaints about it."""
    _compilers(monkeypatch, "func.c:1: parse error before `}'", "func.cpp:1: lots of C++ noise")
    cfg = CompilerConfig(["unused"], sandbox="none", cplusplus=True)
    assert compile_source(cfg, "", "int f(void) { return 0 }").log == "func.c:1: parse error before `}'"
    # (and a silent C compiler's C, with nothing C++ about it, gets C++'s message: the only one there is)
    _compilers(monkeypatch, "compiler exited with 1", "func.cpp:1: parse error before `}'")
    assert compile_source(cfg, "", "int f(void) { return 0 }").log == "func.cpp:1: parse error before `}'"
