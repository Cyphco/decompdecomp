"""split_function on a GBA game: luvdis merges a function into the one before it (code after an early return, a
function nothing calls) or never finds it, and an agent who reads the assembly says where it starts.

A GBA function is its bytes as the ROM has them, with its literal pool, and luvdis's listing of it (not splat's
lines), so it's cut by bytes and by that listing's labels; code after the last function nobody found becomes a
function of its own.
"""

from __future__ import annotations

import json
import re

from ...network import NetworkError
from ...rom.symbols import Symbol
from . import candidates
from .split import BASE, _refs


def split(net, agent, proj, fn, addr: int, new_name: str, syms) -> str:
    """Cut a GBA function's bytes and assembly in two at `addr` (Thumb: a halfword boundary)."""
    off = addr - fn["vram"]
    if off >= fn["size"] and off % 2 == 0:  # code after the function that nobody found yet: make it a function
        return _add(net, agent, proj, fn, addr, new_name, syms)
    if off <= 0 or off >= fn["size"] or off % 2:
        raise NetworkError(f"0x{addr:08X} isn't inside {fn['name']} (0x{fn['vram']:08X}, {fn['size']} bytes)")
    head, tail = fn["target"][:off], fn["target"][off:]
    cut = re.search(rf"^(?:_|\.L){addr:08X}:|^\t(?:thumb|arm)_func_start \w*{addr:08X}\b", fn["asm"], re.M)
    asm_head, asm_tail = ((fn["asm"][:cut.start()], fn["asm"][cut.start():]) if cut else
                          (fn["asm"], f"\tthumb_func_start {new_name}\n@ split from {fn['name']}: see its assembly\n"))
    refs = json.loads(fn["relocs"])
    refs_head = [r for r in refs if r[0] < off]
    refs_tail = [[r[0] - off, r[1], r[2]] for r in refs if r[0] >= off]
    syms.add(Symbol(new_name, addr, len(tail), "func"))
    with net.store.tx() as db:
        db.execute("UPDATE functions SET size=?, n_insns=?, target=?, relocs=?, asm=?, seed=NULL, best_score=NULL "
                   "WHERE id=?", (len(head), max(1, len(head) // 2), head, json.dumps(refs_head), asm_head, fn["id"]))
        db.execute("INSERT INTO functions(project_id,name,size,n_insns,target,relocs,asm,seed,unit,vram,rom_offset) "
                   "VALUES(?,?,?,?,?,?,?,?,?,?,?)", (proj["id"], new_name, len(tail), max(1, len(tail) // 2), tail,
                                                    json.dumps(refs_tail), asm_tail, None, fn["unit"], addr,
                                                    fn["rom_offset"] + off))
        db.execute("UPDATE symbols SET size=? WHERE project_id=? AND name=?", (len(head), proj["id"], fn["name"]))
        db.execute("INSERT OR REPLACE INTO symbols(project_id,name,address,size,kind) VALUES(?,?,?,?,?)",
                   (proj["id"], new_name, addr, len(tail), "func"))
        net._event(db, proj["id"], agent.id, "split", f"{fn['name']} / {new_name}")
    net._xrefs.pop(proj["id"], None)
    net._ops.pop(proj["id"], None)
    return (f"✅ split: {fn['name']} is now {len(head)} bytes; {new_name} at 0x{addr:08X} has {len(tail)}. "
            f"Continue with {fn['name']} (get_function shows its new assembly).")


def _add(net, agent, proj, prev, addr: int, new_name: str, syms) -> str:
    """A function nobody found, after `prev`: from `addr` to its return, then its literal pool, never past the next
    function."""
    nxt = net.store.one("SELECT vram FROM functions WHERE project_id=? AND vram>? ORDER BY vram LIMIT 1",
                        proj["id"], prev["vram"])
    rom, _ = net._rom(proj)
    off, limit = addr - BASE, (nxt["vram"] - BASE) if nxt else len(rom)
    if not off < limit or not candidates.plausible_function(rom, off):
        raise NetworkError(f"0x{addr:08X} doesn't look like the start of a function")
    literals = candidates.literal_words(rom, [addr])
    end = min(next(candidates.bodies(rom, [addr], literals))[1], limit)
    while end + 4 <= limit and end in literals:
        end += 4
    code = rom[off:end]
    syms.add(Symbol(new_name, addr, len(code), "func"))
    with net.store.tx() as db:
        db.execute("INSERT INTO functions(project_id,name,size,n_insns,target,relocs,asm,seed,unit,vram,rom_offset) "
                   "VALUES(?,?,?,?,?,?,?,?,?,?,?)", (proj["id"], new_name, len(code), max(1, len(code) // 2), code,
                                                    json.dumps(_refs(code, addr, literals, off)),
                                                    f"\tthumb_func_start {new_name}\n@ found by an agent after {prev['name']}\n",
                                                    None, prev["unit"], addr, off))
        db.execute("INSERT OR REPLACE INTO symbols(project_id,name,address,size,kind) VALUES(?,?,?,?,?)",
                   (proj["id"], new_name, addr, len(code), "func"))
        net._event(db, proj["id"], agent.id, "split", f"{prev['name']} / {new_name}")
    net._xrefs.pop(proj["id"], None)
    net._ops.pop(proj["id"], None)
    return f"✅ new function {new_name} at 0x{addr:08X}, {len(code)} bytes."
