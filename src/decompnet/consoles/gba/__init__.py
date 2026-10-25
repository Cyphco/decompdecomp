"""Game Boy Advance: the ARM7TDMI (mostly Thumb code, little-endian), agbcc and agbcp (its C++ frontend), ROM mode.

splat doesn't read ARM, so the GBA finds its own functions and has its own judge:
- split.py: the ROM's header, and its functions: luvdis follows the code from the entry point, then passes over
  what's left find code nothing calls (candidates.py); each function's bytes run to the end of its literal pool.
- candidates.py: function starts luvdis didn't reach (prologues, leaf functions after a return, Thumb pointers).
- luvdis_run.py: runs luvdis in its own environment, with a fix to its stack emulation.
- edit.py: split_function: a function luvdis merged into the one before it, or never found, made one of its own.
- export.py: the rebuildable tree (luvdis's assembly, the matched C, a linker script with every piece at its
  address); export_build.py is that tree's build.py, which rebuilds the ROM and checks it byte for byte.
- ../../rom/match_arm.py: the judge: a compiled candidate linked at the function's address (Thumb `bl` pairs,
  literal-pool words, data the candidate defines itself) and compared with the ROM, byte for byte.
- guides/agbcc.md: what agents read about matching agbcc's code.

A game built by more than one compiler gives a range of addresses its own (compiler_ranges): agbcp for C++ code,
agbcc's `old_agbcc` variant for some library code.

Its demo game is projects/demo-gba (homemade Thumb code built with agbcc).
"""

from __future__ import annotations

from pathlib import Path

from ...rom import Picked
from .. import BETA, EXPORT, ROM, Compiler, Console

# where a GBA program's code and data live: EWRAM, IWRAM, the I/O registers, palette, VRAM, OAM, then the ROM itself
RAM = (0x02000000, 0x0A000000)


class GameBoyAdvance(Console):
    id = "gba"
    name = "Game Boy Advance"
    short = "GBA"
    status = BETA  # matched and rebuilt on real games with the 1.0.2 code this is ported from; not yet rebuilt here
    arch = "arm"  # Thumb mostly; the ELF objects say "arm" for both (arch/arm.py)
    big_endian = False
    mode = ROM
    layout = "luvdis"
    compilers = (
        Compiler("agbcc", "agbcc", "most Game Boy Advance games (pret's rebuild of the GCC 2.95-era compiler)",
                 guess="AGBCC"),
        Compiler("agbcp", "agbcp (C++)", "GBA games written in C++ (agbcc's C++ frontend with STLport)"),
    )
    guides = ("arm",)
    compiler_guide = "agbcc"
    m2c = "gba-gcc"
    ram = RAM
    demo = "demo-gba"
    demo_tools = ("agbcc", "arm-gnu", "luvdis")
    own_features = frozenset({EXPORT})
    as_flags = ("-mcpu=arm7tdmi",)
    image_ext = ".gba"
    splat = False

    def sniff(self, head: bytes, file) -> bool:
        from .split import is_gba

        return is_gba(head)

    def read_game(self, file, name: str = "") -> Picked:
        from .split import read_info

        data = Path(file).read_bytes() if isinstance(file, (str, Path)) else bytes(file)
        return Picked(self.id, data, "rom.gba", read_info(data), False)

    def import_game(self, net, file, *, toolchain: str | None = None, flags: list[str] | None = None,
                    name: str = "", log=print, scope: str | None = None) -> str:
        """luvdis finds the functions (split.py), not splat; the engine stores them as any ROM project's."""
        from .split import BASE, split

        picked = self.read_game(file, name)
        segments = [{"name": "rom", "rom_start": 0, "rom_end": picked.info["size"], "vram": BASE}]
        return net.import_found(self, picked, lambda workdir: split(workdir / picked.filename, workdir, log=log),
                                segments=segments, toolchain=toolchain, flags=flags, log=log)

    def rom_target_obj(self, fn):
        """The ROM's bytes as they are: the judge compares them whole (no relocations to mask)."""
        from ...elfobj import FunctionObj

        return FunctionObj(fn["name"], "thumb", False, fn["target"], [])

    def rom_link(self, obj: bytes, fn, symbols, read):
        from ...rom import match_arm

        return match_arm.link(obj, fn["name"], match_arm.ArmTarget(fn["name"], fn["vram"], fn["target"]), symbols, read)

    def export(self, net, slug: str, out: Path, log=print) -> dict:
        from .export import export_gba

        return export_gba(net, slug, out, log=log)

    def split_function(self, net, agent, proj, fn, addr: int, new_name: str, syms) -> str:
        from .edit import split

        return split(net, agent, proj, fn, addr, new_name, syms)

    def up_front_guide(self, compiler: str) -> str:
        return "agbcc"


GBA = GameBoyAdvance()
