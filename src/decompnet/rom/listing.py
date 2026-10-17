"""Repairing a function's assembly listing where the disassembler gave up.

A Thumb switch is `mov pc, r0` followed by a table of code addresses, and the case bodies after it. The listing the
split makes (luvdis) stops decoding at the table and shows everything after it as raw `.byte` data, so an agent sees
half of the function: sub_080204E0 is 500 instructions and its listing decodes about 250 (the rest is 120 lines of
`.byte 0x30, 0x1C, 0x00, 0xF0, ...`), and agents give such functions up unattempted ("only the first part can be
diffed"). The bytes are in the ROM, so the raw runs are decoded here, for what an agent reads. The judge compares
bytes and is not involved.
"""

from __future__ import annotations

import re
import struct
from collections.abc import Callable

_BYTE = re.compile(r"^\s*\.byte\s+(.*)$")
_WORD = re.compile(r"^\s*(?:_[0-9A-Fa-f]{8}:\s*)?\.4byte\s+0x([0-9A-Fa-f]{8})\s*$")
_HEX = re.compile(r"0x([0-9A-Fa-f]{2})")
_IMM = re.compile(r"#(-?0x[0-9a-fA-F]+|-?\d+)")
_BRANCH = re.compile(r"^b(?:eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)?$")
MAX_BAD = 0.2  # a run that doesn't decode (more than this share of it is not valid code) is data, and stays as it is


def _capstone():
    try:
        import capstone
    except ImportError:  # the listing stays as it was
        return None
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
    md.detail = False
    return md


def _runs(lines: list[str]) -> list[tuple[int, int, bytes]]:
    """(first line, last line + 1, bytes) of each stretch of consecutive `.byte` lines."""
    out, i = [], 0
    while i < len(lines):
        if _BYTE.match(lines[i]):
            j, data = i, bytearray()
            while j < len(lines) and (m := _BYTE.match(lines[j])):
                data += bytes(int(h, 16) for h in _HEX.findall(m.group(1)))
                j += 1
            out.append((i, j, bytes(data)))
            i = j
        else:
            i += 1
    return out


def _decode(md, data: bytes, base: int, end: int, targets: set[int], label: Callable[[int], str],
            lo: int, hi: int) -> tuple[list[str], float]:
    """Thumb code for data[base-lo : end-lo] at address `base`: literal-pool words (found from the `ldr rN, [pc, #x]`
    reading them) as `.4byte`, branch targets as labels. Returns the lines and the share that was not valid code."""
    pool: set[int] = set()
    body: list[tuple[int, str]] = []
    bad = total = 0
    addr = base
    while addr < end:
        off = addr - lo
        if addr in pool and addr % 4 == 0 and addr + 4 <= end:
            body.append((addr, f"\t.4byte 0x{struct.unpack_from('<I', data, off)[0]:08X}"))
            addr += 4
            continue
        chunk = data[off:off + 4]
        ins = next(iter(md.disasm(chunk, addr, 1)), None)
        total += 1
        half = struct.unpack_from("<H", data, off)[0] if off + 2 <= len(data) else 0
        if ins is None or half == 0:  # alignment padding before a pool, or not code
            bad += ins is None
            body.append((addr, f"\t.2byte 0x{half:04X}"))
            addr += 2
            continue
        text, size = f"{ins.mnemonic} {ins.op_str}".strip(), ins.size
        imm = _IMM.search(ins.op_str)
        if ins.mnemonic in ("bl", "blx") and imm:
            text = f"{ins.mnemonic} {label(int(imm.group(1), 0))}"
        elif _BRANCH.match(ins.mnemonic) and imm:
            tgt = int(imm.group(1), 0)
            targets.add(tgt)
            text = f"{ins.mnemonic} _{tgt:08X}"
        elif ins.mnemonic == "ldr" and "[pc, #" in ins.op_str:
            reg = ins.op_str.split(",", 1)[0]
            imm = int(_IMM.search(ins.op_str).group(1), 0)
            pa = ((addr + 4) & ~3) + imm
            if lo <= pa < hi:
                pool.add(pa)
                value = struct.unpack_from("<I", data, pa - lo)[0]
                text = f"ldr {reg}, _{pa:08X} @ =0x{value:08X}"
        body.append((addr, "\t" + text))
        addr += size
    lines: list[str] = []
    for a, t in body:
        if a in targets:
            lines.append(f"_{a:08X}:")
        if a in pool:
            lines.append(f"_{a:08X}: {t.strip()}")
        else:
            lines.append(t)
    return lines, (bad / total if total else 1.0)


def repair(text: str, vram: int, data: bytes, label: Callable[[int], str] = lambda a: f"sub_{a:08X}") -> str:
    """The listing with the raw `.byte` stretches that follow a jump table decoded as code (see the module's docstring).
    Anything that isn't plainly that is left exactly as it was."""
    if not text or not data or ".byte" not in text:
        return text
    md = _capstone()
    if md is None:
        return text
    lines = text.splitlines()
    runs = _runs(lines)
    if not runs:
        return text
    lo, hi = vram, vram + len(data)
    # where the tables point: the `.4byte` entries already decoded, and the words that start a raw stretch
    targets = {int(m.group(1), 16) for ln in lines if (m := _WORD.match(ln)) and lo <= int(m.group(1), 16) < hi}
    plan: list[tuple[int, int, int, int, int]] = []  # (first line, last line + 1, table words, code start, code end)
    seen_table, pos = False, 0
    for first, last, raw in runs:
        off = data.find(raw[:24], pos) if len(raw) >= 4 else -1
        if off < 0:
            continue
        pos = off + len(raw)
        words = 0
        while 4 * words + 4 <= len(raw) and off % 4 == 0:
            v = struct.unpack_from("<I", data, off + 4 * words)[0]
            if not lo <= v < hi:
                break
            targets.add(v & ~1)
            words += 1
        if not words and not seen_table:
            # the table's last words were decoded as `.4byte` already and the case bodies start the stretch
            before = lines[first - 1] if first else ""
            if not ((m := _WORD.match(before)) and lo <= int(m.group(1), 16) < hi
                    and any("mov pc, r" in ln for ln in lines[:first])):
                continue
        seen_table = True
        plan.append((first, last, words, vram + off + 4 * words, vram + off + len(raw)))
    if not plan:
        return text
    for _, _, _, start, end in plan:  # first pass: every branch target, whichever stretch it is in
        _decode(md, data, start, end, targets, label, lo, hi)
    out, cursor = [], 0
    for first, last, words, start, end in plan:
        new, bad = _decode(md, data, start, end, set(targets), label, lo, hi)
        if bad > MAX_BAD:
            continue
        table = [f"\t.4byte 0x{struct.unpack_from('<I', data, start - vram - 4 * words + 4 * k)[0]:08X}" for k in range(words)]
        out += lines[cursor:first] + table + new
        cursor = last
    if not cursor:
        return text
    out += lines[cursor:]
    return "\n".join(out)
