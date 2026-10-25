"""Build Demo Quest GBA, a Game Boy Advance ROM made only from code we may share: the same Demo Quest game, main loop
and tiny libc as the N64 demo (CC0, ../demo-rom/src, ../demo-n64/original) and zlib 1.1.4 (Zlib license), compiled
the way GBA games were: the C preprocessor, agbcc (pret's rebuild of the GBA's GCC) at -O2 -mthumb-interwork, and the
GNU assembler, as in pret's projects.

    uv run python projects/demo-gba/build.py    ->  build/demoquest.gba (+ build/demoq_gba.elf with symbols)

agbcc is a Linux program: it runs in decompdecomp's compiler sandbox (WSL 2 on Windows), on copies of the sources.
The start-up code is assembled and the ROM linked with the Arm GNU Toolchain on this computer.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

from decompnet import toolchains
from decompnet.compiler import run_in
from decompnet.project import compiler_config

HERE = Path(__file__).resolve().parent
BUILD = HERE / "build"
DEMO = HERE.parent / "demo-rom" / "src"
GAME = HERE.parent / "demo-n64" / "original"
ZLIB = HERE.parent / "zlib-n64"
ZLIB_UNITS = ["adler32", "compress", "crc32", "deflate", "inflate", "infblock", "infcodes", "inffast", "inftrees",
              "infutil", "trees", "uncompr", "zutil"]


def run(argv, cwd=BUILD):
    res = subprocess.run([str(a) for a in argv], capture_output=True, text=True, cwd=cwd)
    if res.returncode != 0:
        sys.exit(f"failed: {' '.join(map(str, argv))}\n{res.stdout}{res.stderr}")


def write_key(game: Path, elf: Path) -> None:
    """build/demo.json: the game this build made and the address of every symbol, so tests/test_consoles.py knows
    which of the project's functions is which."""
    from elftools.elf.elffile import ELFFile

    with open(elf, "rb") as f:
        symbols = {s.name: s["st_value"] & ~1 for s in ELFFile(f).get_section_by_name(".symtab").iter_symbols()
                   if s.name and not s.name.startswith("$")}
    (BUILD / "demo.json").write_text(json.dumps({"game": game.name, "symbols": symbols}, indent=1), encoding="utf-8")


def main() -> None:
    if BUILD.exists():
        shutil.rmtree(BUILD)
    (BUILD / "src" / "include").mkdir(parents=True)
    toolchains.ensure("agbcc", log=print)
    toolchains.ensure("arm-gnu", log=print)  # this computer's own build (agbcc's, in WSL on Windows, is another)
    arm = toolchains.binary("arm-gnu").parent  # bin/: as, ld, objcopy
    # the sources, and one folder with every header they include (agbcc's command takes one include folder)
    for name, src in (("demo", DEMO), ("game", GAME), ("zlib", ZLIB / "original")):
        shutil.copytree(src, BUILD / "src" / name)
    shutil.copy(HERE / "gbart.c", BUILD / "src" / "gbart.c")
    for folder in (GAME, ZLIB / "original", ZLIB / "sysinclude"):
        for header in folder.rglob("*.h"):
            target = BUILD / "src" / "include" / header.relative_to(folder)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(header, target)
    jobs = ["src/gbart.c", "src/demo/main.c", "src/demo/libc.c", "src/game/game.c"]
    jobs += [f"src/zlib/{u}.c" for u in ZLIB_UNITS]
    cfg = compiler_config(BUILD, {"compiler": {"toolchain": "agbcc"}})  # its own flags: what a project gets
    objs = []
    for src in jobs:
        obj = f"{Path(src).stem}.o"
        argv = [a.replace("{src}", src).replace("{obj}", obj).replace("{include}", "src/include") for a in cfg.cmd]
        res = run_in(cfg, BUILD, argv, inputs=["src"], outputs=[obj])
        if res.returncode != 0:
            sys.exit(f"failed: {src}\n{res.stdout}{res.stderr}")
        objs.append(obj)
    shutil.copy(HERE / "crt0.s", BUILD / "crt0.s")
    run([arm / "arm-none-eabi-as", "-mcpu=arm7tdmi", "-o", "crt0.o", "crt0.s"])
    run([arm / "arm-none-eabi-ld", "-T", HERE / "rom.ld", "-o", "demoq_gba.elf", "crt0.o", *objs])
    run([arm / "arm-none-eabi-objcopy", "-O", "binary", "demoq_gba.elf", "demoquest.gba"])
    rom = bytearray((BUILD / "demoquest.gba").read_bytes())
    rom[0xBD] = (-(sum(rom[0xA0:0xBD]) + 0x19)) & 0xFF  # header checksum
    (BUILD / "demoquest.gba").write_bytes(bytes(rom))
    write_key(BUILD / "demoquest.gba", BUILD / "demoq_gba.elf")
    print(f"built build/demoquest.gba ({len(rom)} bytes)")


if __name__ == "__main__":
    main()
