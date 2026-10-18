"""Homemade Thumb callbacks whose switch tables interrupt linear function discovery."""

import struct

import pytest

from decompnet.rom import gba_candidates as gba


def switch_callback():
    rom = bytearray(0x3100)
    # push lr; scale index; load the table pointer; load a case address; mov pc,r0.
    rom[0x100:0x10C] = bytes.fromhex("00b5 8000 0249 4018 0068 8746")
    struct.pack_into("<III", rom, 0x110, gba.BASE + 0x114, gba.BASE + 0x900, gba.BASE + 0x3000)
    rom[0x900:0x902] = bytes.fromhex("fee7")  # one case loops, the other returns far beyond the linear scan limit
    rom[0x3000:0x3006] = bytes.fromhex("0220 02bc 0847")  # movs r0,2; pop r1; bx r1
    struct.pack_into("<I", rom, 0x40, gba.BASE + 0x101)  # callback pointer, rather than a direct bl
    return rom


def test_a_large_switch_callback_is_plausible_and_discovered():
    rom = switch_callback()
    assert gba.plausible_function(rom, 0x100)
    found = gba.candidates(rom, [])
    assert gba.BASE + 0x100 in found
    assert gba.BASE + 0x900 not in found  # case labels are not function starts
    assert gba.BASE + 0x3000 not in found


@pytest.mark.parametrize("destination", [0x100, 0x110, 0x3200])
def test_a_switch_with_no_valid_path_to_a_return_is_rejected(destination):
    rom = switch_callback()
    struct.pack_into("<I", rom, 0x118, gba.BASE + destination)
    assert not gba.plausible_function(rom, 0x100)


def test_a_table_without_a_function_prologue_does_not_become_a_callback():
    rom = switch_callback()
    rom[0x100:0x102] = bytes.fromhex("c046")
    assert not gba.plausible_function(rom, 0x100)


def test_a_short_leaf_switch_can_still_pass_the_original_linear_scan():
    rom = switch_callback()[:0x160]
    rom[0x100:0x102] = bytes.fromhex("c046")
    struct.pack_into("<II", rom, 0x114, gba.BASE + 0x130, gba.BASE + 0x140)
    rom[0x130:0x132] = bytes.fromhex("7047")
    rom[0x140:0x142] = bytes.fromhex("7047")
    assert gba.plausible_function(rom, 0x100)


def test_short_functions_and_truncated_data_keep_their_verdicts():
    assert gba.plausible_function(bytes.fromhex("00b5 00bd"), 0)
    assert gba.plausible_function(bytes.fromhex("7047"), 0)
    assert not gba.plausible_function(bytes.fromhex("00b5 ff"), 0)
    assert not gba.plausible_function(bytes.fromhex("00b5 8746 ff"), 0)  # truncated switch literal


def test_a_long_bl_to_an_internal_tail_is_not_a_second_function():
    rom = bytearray(0x140)
    rom[0x100:0x108] = bytes.fromhex("00b5 00f0 05f8 03e0")  # push lr; bl 0x110; b 0x110
    rom[0x110:0x116] = bytes.fromhex("0120 02bc 0847")
    assert gba.plausible_function(rom, 0x110)
    assert gba.BASE + 0x110 not in gba.candidates(rom, [gba.BASE + 0x100])
