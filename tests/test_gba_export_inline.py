"""GBA exports retain inline bodies without leaking duplicate global helper symbols."""
from io import BytesIO

import pytest
from elftools.elf.elffile import ELFFile

from decompnet import toolchains
from decompnet.compiler import compile_source
from decompnet.consoles.gba.export import standalone_source
from decompnet.project import compiler_config


@pytest.mark.parametrize('spelling', ['inline', '__inline', '__inline__', 'static inline', 'extern inline'])
def test_export_keeps_inline_helpers_private_and_byte_identical(tmp_path, spelling):
    if any(toolchains.installed(t) is None for t in ('agbcc', 'arm-gnu')):
        pytest.skip('needs agbcc and the Arm GNU toolchain')
    source = f'{spelling} int helper(int x) {{ return x + 7; }}\nint target(int x) {{ return helper(x); }}\n'
    cfg = compiler_config(tmp_path, {'compiler': {'toolchain': 'agbcc', 'flags': ['-mthumb-interwork', '-O2']}})
    original = compile_source(cfg, '', source)
    exported = compile_source(cfg, '', standalone_source(source, 'target'))
    assert original.ok and exported.ok, original.log + exported.log

    def function_bytes(obj):
        elf = ELFFile(BytesIO(obj))
        symbol = elf.get_section_by_name('.symtab').get_symbol_by_name('target')[0]
        offset = symbol['st_value'] & ~1
        return elf.get_section(symbol['st_shndx']).data()[offset:offset + symbol['st_size']]

    assert function_bytes(exported.obj) == function_bytes(original.obj)
    symbols = ELFFile(BytesIO(exported.obj)).get_section_by_name('.symtab')
    assert not any(s.name == 'helper' and s['st_info']['bind'] == 'STB_GLOBAL' for s in symbols.iter_symbols())


def test_export_still_removes_other_game_function_definitions():
    source = 'int other(void) { return 4; }\nint target(void) { return other(); }\n'
    result = standalone_source(source, 'target')
    assert 'int other(void);' in result
    assert 'return 4;' not in result
    assert 'return other();' in result
