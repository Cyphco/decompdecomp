"""Handmade ELF relocations must preserve the call's offset, condition and instruction set."""

import struct

import pytest

from decompnet.rom import match_arm
from decompnet.rom.symbols import Symbol, SymbolTable


def branch_object(code, rtype, thumb):
    """A minimal ELF32 REL object; no assembler or proprietary compiler is needed by these regressions."""
    strings = b"\0entry\0foo\0"
    symbols = bytes(16) + struct.pack("<IIIBBH", 1, int(thumb), len(code), 0x12, 0, 1)
    symbols += struct.pack("<IIIBBH", 7, 0, 0, 0x12, 0, 0)
    names = b"\0.text\0.strtab\0.symtab\0.rel.text\0.shstrtab\0"
    sections = [(".text", 1, 6, code, 0, 0, 2, 0), (".strtab", 3, 0, strings, 0, 0, 1, 0),
                (".symtab", 2, 0, symbols, 2, 1, 4, 16),
                (".rel.text", 9, 0, struct.pack("<II", 0, (2 << 8) | rtype), 3, 1, 4, 8),
                (".shstrtab", 3, 0, names, 0, 0, 1, 0)]
    image = bytearray(52)
    headers = [bytes(40)]
    for name, kind, flags, data, link, info, align, size in sections:
        image += bytes((-len(image)) % align)
        offset = len(image)
        image += data
        headers.append(struct.pack("<IIIIIIIIII", names.index(name.encode()), kind, flags, 0, offset,
                                   len(data), link, info, align, size))
    image += bytes((-len(image)) % 4)
    shoff = len(image)
    image += b"".join(headers)
    image[:52] = struct.pack("<16sHHIIIIIHHHHHH", b"\x7fELF\x01\x01\x01" + bytes(9), 1, 40, 1, 0, 0,
                             shoff, 0, 52, 0, 0, 40, len(headers), 5)
    return bytes(image)


def judge(code, target, rtype, thumb):
    symbols = SymbolTable([Symbol("foo", 0x08000200, 8, "func")])
    return match_arm.link(branch_object(code, rtype, thumb), "entry",
                          match_arm.ArmTarget("entry", 0x08000100, target, thumb), symbols, lambda a, n: None)


@pytest.mark.parametrize("rtype", [match_arm.R_ARM_PC24, match_arm.R_ARM_CALL, match_arm.R_ARM_JUMP24])
@pytest.mark.parametrize("addend", [-4, 0, 4])
def test_arm_branch_addends_are_linked_to_the_actual_destination(rtype, addend):
    # The REL immediate includes the ARM PC bias of -8. The original calls foo, not foo+/-4.
    code = struct.pack("<II", 0xEB000000 | (((addend - 8) >> 2) & 0xFFFFFF), 0xE12FFF1E)
    target = bytes.fromhex("3e0000eb1eff2fe1")
    result = judge(code, target, rtype, False)
    assert result.exact == (addend == 0), result.problems
    assert bool(result.problems) == (addend != 0)


@pytest.mark.parametrize("raw", ["fff7fcff", "fff7feff", "00f000f8"])
def test_thumb_branch_addends_are_linked_to_the_actual_destination(raw):
    result = judge(bytes.fromhex(raw + "7047"), bytes.fromhex("00f07ef87047"), match_arm.R_ARM_THM_CALL, True)
    assert result.exact == (raw == "fff7feff"), result.problems
    assert bool(result.problems) == (raw != "fff7feff")


@pytest.mark.parametrize("opcode", [0xEAFFFFFE, 0x1BFFFFFE, 0xE1A00000])
def test_an_arm_call_cannot_change_to_a_jump_condition_or_another_instruction(opcode):
    result = judge(struct.pack("<II", opcode, 0xE12FFF1E), bytes.fromhex("3e0000eb1eff2fe1"),
                   match_arm.R_ARM_CALL, False)
    assert not result.exact and result.problems


def test_a_thumb_call_cannot_change_to_an_exchange_or_a_non_call_instruction():
    for raw in ["fff7feef", "00000000"]:
        result = judge(bytes.fromhex(raw + "7047"), bytes.fromhex("00f07ef87047"), match_arm.R_ARM_THM_CALL, True)
        assert not result.exact and result.problems


def test_nonzero_branch_addends_match_when_the_rom_calls_the_same_offset():
    arm = judge(bytes.fromhex("ffffffeb1eff2fe1"), bytes.fromhex("3f0000eb1eff2fe1"),
                match_arm.R_ARM_CALL, False)
    thumb = judge(bytes.fromhex("00f000f87047"), bytes.fromhex("00f080f87047"),
                  match_arm.R_ARM_THM_CALL, True)
    assert arm.exact and not arm.problems
    assert thumb.exact and not thumb.problems
