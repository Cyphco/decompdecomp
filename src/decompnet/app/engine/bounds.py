"""Changing where GBA functions start and end, and what is merged into what.

The split is sometimes a halfword off (it keeps the upper half of a literal as the start of the next function, or stops
inside the function's own literal pool) and sometimes cuts one function into pieces (the blocks of a switch or of a
hand-written routine become "functions" with no prologue). Agents found these by their scores and reported them as
suggestions, but a boundary report only worked for MIPS. set_bounds makes the change, from what the ROM says: the bytes
of the new range, the literals the function's own `ldr`s read, and the rows that lie inside it.
"""

from __future__ import annotations

import bisect
import json
import struct
from io import BytesIO

from elftools.elf.elffile import ELFFile

from ...elfobj import _function_symbols
from ...network import NetworkError
from ...rom import gba, gba_candidates, listing, match_arm

MAX_FUNCTION = 0x8000  # bytes: a function larger than this is not a function
GAP_SCAN = 0x1000  # bytes of unowned code followed past a branch target, at most
SMALL_JUNK = 6  # bytes: a "function" this small with no prologue and no return is a halfword of padding or a literal


def _listing(name: str, data: bytes, vram: int, label) -> str:
    """The assembly agents read for a function whose bytes changed: decoded from them (labels for every branch target,
    literal-pool words, calls by name), as the split's listing would show it."""
    md = listing._capstone()
    if md is None:
        return f"\tthumb_func_start {name}\n{name}:\n"
    end = vram + len(data)
    # a switch's jump table is data: decode around it, and its words are labels (the case bodies)
    tables: list[tuple[int, int]] = []
    for a, mn, ops, n in _thumb(md, data, vram):
        if mn == "mov" and ops.startswith("pc,") and not any(lo <= a < hi for lo, hi in tables):
            # past the literal words after `mov pc` (the table's own address among them) to the first word that
            # points back into this function: the table runs while they do
            k = (a + n - vram + 3) & ~3
            inside = lambda off: off + 4 <= len(data) and vram <= struct.unpack_from("<I", data, off)[0] < end  # noqa: E731
            while k < min(len(data), a + n - vram + 72) and not inside(k):
                k += 4
            if inside(k) and struct.unpack_from("<I", data, k)[0] == vram + k + 4:
                k += 4  # the pool word holding the table's address, right before it: the ldr's, not the table's
            first = k
            while inside(k):
                k += 4
            if k > first:
                tables.append((vram + first, vram + k))
    targets: set[int] = {struct.unpack_from("<I", data, k - vram)[0] & ~1 for lo, hi in tables for k in range(lo, hi, 4)}
    segments, at = [], vram
    for lo, hi in sorted(tables) + [(end, end)]:
        segments.append((at, lo))
        at = hi
    for _ in range(2):  # every label first, then the lines
        found = set(targets)
        out: list[str] = []
        for (lo, hi), table in zip(segments, sorted(tables) + [None]):
            if hi > lo:
                lines, _bad = listing._decode(md, data, lo, hi, found, label, vram, end)
                out += lines
            if table is not None:
                for k in range(table[0], table[1], 4):
                    out.append(f"\t.4byte 0x{struct.unpack_from('<I', data, k - vram)[0]:08X}")
        targets |= found
    return f"\tthumb_func_start {name}\n{name}:\n" + "\n".join(out) + "\n"


def _thumb(md, code: bytes, vram: int):
    """(address, mnemonic, operands, size) of each instruction, stepping over what doesn't decode."""
    pos = 0
    while pos + 2 <= len(code):
        ins = next(md.disasm(code[pos:pos + 4], vram + pos, 1), None)
        if ins is None:
            pos += 2
            continue
        yield ins.address, ins.mnemonic, ins.op_str, ins.size
        pos += ins.size


def _flow(md, rom: bytes, vram: int, size: int) -> tuple[set[int], set[int], bool]:
    """(literal words its `ldr rN, [pc, #x]` read, addresses its branches and jump tables reach, whether it has a
    prologue) for the code at vram..vram+size."""
    code = rom[vram - gba.BASE:vram - gba.BASE + size]
    literals, targets, prologue = set(), set(), False
    for k, (addr, mn, ops, n) in enumerate(_thumb(md, code, vram)):
        if k == 0:
            prologue = mn == "push" and "lr" in ops
        if mn == "ldr" and "[pc, #" in ops:
            literals.add(((addr + 4) & ~3) + int(ops.split("#")[1].rstrip("]"), 0))
        elif mn.startswith("b") and mn not in ("bl", "blx", "bx", "bic", "bics") and ops.startswith("#"):
            targets.add(int(ops[1:], 0))
        elif mn == "mov" and ops.startswith("pc,"):
            after, cases = gba_candidates._switch_table(rom, addr + n - gba.BASE, vram - gba.BASE, vram - gba.BASE + 0x8000)
            targets.update(c + gba.BASE for c in cases)
    return literals, targets, prologue


class BoundsMixin:
    def set_bounds(self, slug: str, name: str, start: int | None = None, end: int | None = None,
                   absorb: list[str] | None = None, reason: str = "", allow_prologue: bool = False) -> dict:
        """Set where `name` starts and ends (None: as it is). The rows that lie inside the new range have to be named in
        `absorb` (set aside as assembly, "part of `name`"); the function's bytes, refs, size and symbol follow the ROM.
        Then the function's own C is tried against the new range: a match is recorded. Returns what happened."""
        fn = self._function(name, slug)
        proj = self._project(slug)
        if self.cfg(proj).get("platform") != "gba":
            raise NetworkError("function bounds are set for GBA games")
        if fn["status"] == "matched":
            raise NetworkError(f"{fn['name']} is matched: its bounds are proven")
        new_start = fn["vram"] if start is None else int(start)
        new_end = fn["vram"] + fn["size"] if end is None else int(end)
        size = new_end - new_start
        if new_start % 2 or new_end % 2 or not 0 < size <= MAX_FUNCTION:
            raise NetworkError(f"0x{new_start:08X}..0x{new_end:08X} is not a halfword-aligned range of at most 0x{MAX_FUNCTION:X} bytes")
        absorb = list(absorb or [])
        others = self.store.all("SELECT * FROM functions WHERE project_id=? AND id!=? AND vram<? AND vram+size>?",
                                proj["id"], fn["id"], new_end, new_start)
        known = {r["name"] for r in others}
        stray = [r["name"] for r in others if r["name"] not in absorb]
        if stray:
            raise NetworkError(f"{', '.join(stray)} lie inside 0x{new_start:08X}..0x{new_end:08X}: name them in absorb "
                               "to merge them, or choose another range")
        rows = []
        for n in absorb:
            r = self._function(n, slug)
            if r["status"] == "matched":
                raise NetworkError(f"{r['name']} is matched: it can't be merged into {fn['name']}")
            if r["name"] not in known and r["id"] != fn["id"]:
                raise NetworkError(f"{r['name']} is not inside the new range")
            rows.append(r)
        rom, _segments = self._rom(proj)
        data = rom[new_start - gba.BASE:new_end - gba.BASE]
        if len(data) != size:
            raise NetworkError("that range is outside the ROM")
        old_end = fn["vram"] + fn["size"]
        if new_end > old_end and not allow_prologue:  # growing: never over the start of another function
            import capstone

            md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
            push = next((a for a, mn, ops, _ in _thumb(md, rom[old_end - gba.BASE:new_end - gba.BASE], old_end)
                         if mn == "push" and "lr" in ops), None)
            if push is not None:
                raise NetworkError(f"0x{push:08X} starts another function (a push with lr): {fn['name']} can't take it in "
                                   "(allow_prologue=True if it really is this function's)")
        starts = sorted(r["vram"] for r in self.store.all("SELECT vram FROM functions WHERE project_id=?", proj["id"]))
        refs = gba._refs(data, new_start, gba_candidates.literal_words(rom, starts), new_start - gba.BASE)
        was = (fn["vram"], fn["size"])
        note = f" ({' '.join(reason.split())[:200]})" if reason.strip() else ""
        with self.store.tx() as db:
            for r in rows:
                meta = json.loads(r["meta"] or "{}")
                meta["asm_code"] = f"part of {fn['name']} (merged into it){note}"
                db.execute("UPDATE functions SET status='asm', meta=? WHERE id=?", (json.dumps(meta), r["id"]))
                db.execute("DELETE FROM claims WHERE function_id=?", (r["id"],))
            db.execute("UPDATE functions SET vram=?, rom_offset=?, size=?, n_insns=?, target=?, relocs=?, asm=?, seed=NULL, "
                       "best_score=NULL WHERE id=?",
                       (new_start, new_start - gba.BASE, size, max(1, size // 2), data,
                        json.dumps([list(x) for x in refs or []]),
                        _listing(fn["name"], data, new_start, self.symbols(proj["id"]).label), fn["id"]))
            db.execute("UPDATE symbols SET address=?, size=? WHERE project_id=? AND name=?",
                       (new_start, size, proj["id"], fn["name"]))
            self._event(db, proj["id"], None, "boundary",
                        f"{fn['name']}: 0x{was[0]:08X}+{was[1]} -> 0x{new_start:08X}+{size}"
                        + (f", merged {', '.join(r['name'] for r in rows)}" if rows else "") + note)
        self._xrefs.pop(proj["id"], None)
        out = {"function": fn["name"], "start": new_start, "end": new_end, "size": size,
               "absorbed": [r["name"] for r in rows], "matched": False}
        fresh = self._function(fn["name"], slug)
        source = self._exact_source(fresh, proj)
        if source is not None:
            agent, _ = self.local_agent("extent-repair")
            out["matched"] = bool(self.attempt(agent, fn["name"], source, slug).get("matched"))
        return out

    def _exact_source(self, fn, proj) -> str | None:
        """The first of the function's own C (best, then the latest compiled attempts) that is byte-identical to the
        function's current bytes, or None."""
        sources = [fn["best_source"]] if fn["best_source"] else []
        for r in self.store.all("SELECT source FROM attempts WHERE function_id=? AND compiled=1 AND source IS NOT NULL "
                                "ORDER BY id DESC LIMIT 60", fn["id"]):
            if r["source"] not in sources:
                sources.append(r["source"])
        if not sources:
            return None
        read = self.reader(proj)
        syms = self.symbols(proj["id"])
        ctx = self._context(proj["id"], fn["unit"])
        target = match_arm.ArmTarget(fn["name"], fn["vram"], fn["target"])
        for source in sources[:14]:
            result = self._compile(proj, ctx["header"], source, fn)
            if not result.ok or not _function_symbols(ELFFile(BytesIO(result.obj))).get(fn["name"]):
                continue
            res = match_arm.link(result.obj, fn["name"], target, syms, read)
            if res.candidate is not None and res.exact:
                return source
        return None

    def doctor_bounds(self, slug: str) -> list[dict]:
        """Functions whose recorded range the ROM itself contradicts, with the change that fixes each (nothing is
        changed here; apply_doctor makes them):
        - own literal: its code reads a literal word past its end (it stops inside, or before, its own pool);
        - continuation: rows right after it have no prologue and its branches or jump table land in them (the case
          bodies, shared tail or epilogue of a switch, split off as "functions");
        - junk: a row of at most SMALL_JUNK bytes with no prologue and no return, all of it inside the literal words
          the function before it reads, or zero halfwords (padding).
        A matched row is never moved or merged; a row with a prologue is never merged into another."""
        import capstone

        proj = self._project(slug)
        if self.cfg(proj).get("platform") != "gba":
            raise NetworkError("function bounds are checked for GBA games")
        rom, _segments = self._rom(proj)
        md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
        rows = self.store.all("SELECT name, vram, size, status FROM functions WHERE project_id=? ORDER BY vram", proj["id"])
        info = {r["name"]: _flow(md, rom, r["vram"], r["size"]) for r in rows}
        taken: set[str] = set()
        out: list[dict] = []
        starts = [r["vram"] for r in rows]
        for i, r in enumerate(rows):
            if r["status"] != "open" or r["name"] in taken:
                continue
            end = r["vram"] + r["size"]
            literals, targets, _ = info[r["name"]]
            absorb: list[str] = []
            why: list[str] = []
            while end - r["vram"] < MAX_FUNCTION:
                lit_need = max((a + 4 for a in literals if end < a + 4 and a < end + 0x400), default=0)
                reach = max([t + 2 for t in targets if end <= t < end + 0x2000] + [lit_need])
                if reach <= end:
                    break
                j = bisect.bisect_left(starts, end)
                nxt = rows[j] if j < len(rows) else None
                limit = nxt["vram"] if nxt is not None else len(rom) + gba.BASE
                if reach <= limit:  # into bytes no row owns (the split left them as data): they are this function's.
                    # A literal: up to its end. A branch target: through the code there, up to its return (the pool
                    # after it is picked up next round), never past a prologue (a function the split never found) and
                    # never further than GAP_SCAN (the bytes after the last function can be megabytes of data)
                    stop = reach
                    if reach != lit_need:
                        stop = None
                        for a, mn, ops, n in _thumb(md, rom[reach - 2 - gba.BASE:min(limit, reach + GAP_SCAN) - gba.BASE], reach - 2):
                            if mn == "push" and "lr" in ops and a > reach - 2:
                                stop = a
                                break
                            if mn == "bx" or (mn == "pop" and "pc" in ops):
                                stop = a + n
                                break
                        if stop is None:
                            break
                    added_lo, end = end, stop
                    why.append(f"its {'literal' if reach == lit_need else 'branches reach'} 0x{reach - (4 if reach == lit_need else 2):08X}, "
                               f"in unowned bytes up to 0x{end:08X}")
                else:  # a row is in the way: only a fragment with no prologue, not matched, is taken in
                    n_lit, n_targets, n_prologue = info[nxt["name"]]
                    if nxt["status"] != "open" or n_prologue or nxt["name"] in taken or nxt["name"] in absorb:
                        break
                    added_lo, end = end, nxt["vram"] + nxt["size"]
                    absorb.append(nxt["name"])
                    why.append(f"its {'literal' if reach == lit_need else 'branches'} reach into {nxt['name']}")
                if end <= added_lo:  # nothing gained (an empty row): stop here rather than go round again
                    end = added_lo
                    break
                more = _flow(md, rom, added_lo, end - added_lo)
                literals, targets = literals | more[0], targets | more[1]
            if end != r["vram"] + r["size"] and end - r["vram"] <= MAX_FUNCTION:
                taken.update(absorb)
                out.append({"function": r["name"], "start": r["vram"], "end": end, "was": r["size"], "absorb": absorb,
                            "rule": "own literal" if all("literal" in w for w in why) else "continuation", "why": "; ".join(why)})
        # junk: tiny rows inside the literal words of the row before, or plain padding
        for prev, r in zip(rows, rows[1:]):
            if r["status"] != "open" or r["name"] in taken or r["size"] > SMALL_JUNK:
                continue
            code = rom[r["vram"] - gba.BASE:r["vram"] - gba.BASE + r["size"]]
            lits = info[prev["name"]][0]
            inside = all(any(a <= r["vram"] + k < a + 4 for a in lits) for k in range(0, r["size"], 2))
            padding = all(code[k:k + 2] == b"\0\0" for k in range(0, len(code), 2))
            has_ret = any(mn == "bx" or (mn == "pop" and "pc" in ops) for _, mn, ops, _ in _thumb(md, code, r["vram"]))
            if (inside or padding) and not info[r["name"]][2] and not has_ret:
                out.append({"function": r["name"], "rule": "junk", "absorb": [], "start": r["vram"], "end": r["vram"] + r["size"],
                            "was": r["size"], "why": f"inside {prev['name']}'s literal pool" if inside else "zero padding"})
        return out

    def apply_doctor(self, slug: str, proposals: list[dict] | None = None) -> list[dict]:
        """Make doctor_bounds' changes (all of them by default); each function changed is judged again with its own
        C (set_bounds). Returns the proposals with what happened to each ("matched", "error")."""
        done = []
        for p in proposals if proposals is not None else self.doctor_bounds(slug):
            q = dict(p)
            try:
                if p["rule"] == "junk":
                    self.mark_assembly(slug, p["function"], f"not code: {p['why']}")
                else:
                    res = self.set_bounds(slug, p["function"], end=p["end"], absorb=p["absorb"], reason=f"{p['rule']}: {p['why']}")
                    q["matched"] = res["matched"]
            except NetworkError as e:
                q["error"] = str(e)
            done.append(q)
        return done

    def close_suggestion(self, slug: str, sid: int, status: str, note: str) -> None:
        """Answer a suggestion: `status` is "applied" or "dismissed", `note` says what was done or why not (it is shown
        on the Suggestions tab)."""
        if status not in ("applied", "dismissed"):
            raise NetworkError("status is applied or dismissed")

        def change(cfg):
            hit = next((s for s in cfg.get("suggestions", []) if s["id"] == sid), None)
            if hit is None:
                raise NetworkError(f"no suggestion {sid}")
            hit["status"], hit["resolution"] = status, " ".join(note.split())[:600]
        self._update_cfg(slug, change)
