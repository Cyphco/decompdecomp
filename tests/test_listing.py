"""The listing of a function with a jump table: its case bodies are decoded, and the function ends after them."""

import struct

from decompnet.rom import gba_candidates, listing

BASE = 0x08000000


def _rom(words, tail):
    return b"\x87\x46\x00\x00" + b"".join(struct.pack("<I", w) for w in words) + tail


def test_case_bodies_after_a_jump_table_are_decoded():
    # mov pc, r0 / padding / table of three cases / movs r0,#1 ; movs r0,#2 ; bx lr
    data = _rom([BASE + 0x10, BASE + 0x12, BASE + 0x14], bytes([0x01, 0x20, 0x02, 0x20, 0x70, 0x47]))
    text = ("\tthumb_func_start sub_08000000\nsub_08000000:\n\tmov pc, r0\n\t.byte 0x00, 0x00\n_08000004: .4byte 0x08000010\n"
            "\t.byte 0x12, 0x00, 0x00, 0x08, 0x14, 0x00, 0x00, 0x08, 0x01, 0x20, 0x02, 0x20, 0x70, 0x47")
    out = repair = listing.repair(text, BASE, data)
    assert ".byte 0x12" not in repair and "movs r0, #1" in out and "movs r0, #2" in out and "bx lr" in out
    assert "_08000010:" in out and "_08000012:" in out and "_08000014:" in out  # each case has its label
    assert out.index("_08000010:") < out.index("movs r0, #1") < out.index("_08000012:") < out.index("movs r0, #2")
    assert ".4byte 0x08000012" in out and ".4byte 0x08000014" in out  # the table, as words


def test_branches_and_calls_in_decoded_bodies_name_their_targets():
    # table of one case; body: b +0 (to the next halfword) ; bl 0x08000100 ; bx lr
    body = bytes([0xFF, 0xE7]) + bytes([0x00, 0xF0, 0xF0, 0xF8]) + bytes([0x70, 0x47])  # b . ; bl +0xE0.. ; bx lr
    data = _rom([BASE + 0x8], body)
    text = "\tmov pc, r0\n\t.byte 0x00, 0x00\n_08000004: .4byte 0x08000008\n\t.byte " + ", ".join(f"0x{b:02X}" for b in body)
    out = listing.repair(text, BASE, data)
    assert "bl sub_" in out and "bx lr" in out


def test_data_that_is_not_code_is_left_alone():
    data = bytes(range(200, 240)) + bytes(40)
    text = "\t.byte " + ", ".join(f"0x{b:02X}" for b in data[:16]) + "\n\t.byte " + ", ".join(f"0x{b:02X}" for b in data[16:32])
    assert listing.repair(text, BASE, data) == text  # no table: not this function's case bodies
    assert listing.repair("\tmovs r0, #1\n\tbx lr", BASE, b"\x01\x20\x70\x47") == "\tmovs r0, #1\n\tbx lr"


def test_a_function_with_a_switch_ends_after_its_case_bodies():
    # mov pc, r0 / pad / table (3 cases) / three bodies each ending in bx lr
    bodies = b"".join(bytes([n, 0x20, 0x70, 0x47]) for n in (1, 2, 3))
    rom = _rom([BASE + 0x10, BASE + 0x14, BASE + 0x18], bodies) + bytes(64)
    (start, end, _), = gba_candidates.bodies(rom, [BASE], set(), switches=True)
    assert (start, end) == (0, 0x1C)  # after the last case body, not at the table
