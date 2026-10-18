"""Changing where GBA functions start and end, and what is merged into what.

The split is sometimes a halfword off (it keeps the upper half of a literal as the start of the next function, or stops
inside the function's own literal pool) and sometimes cuts one function into pieces (the blocks of a switch or of a
hand-written routine become "functions" with no prologue). Agents found these by their scores and reported them as
suggestions, but a boundary report only worked for MIPS. set_bounds makes the change, from what the ROM says: the bytes
of the new range, the literals the function's own `ldr`s read, and the rows that lie inside it.
"""

from __future__ import annotations

import json
from io import BytesIO

from elftools.elf.elffile import ELFFile

from ...elfobj import _function_symbols
from ...network import NetworkError
from ...rom import gba, gba_candidates, match_arm

MAX_FUNCTION = 0x8000  # bytes: a function larger than this is not a function


class BoundsMixin:
    def set_bounds(self, slug: str, name: str, start: int | None = None, end: int | None = None,
                   absorb: list[str] | None = None, reason: str = "") -> dict:
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
            db.execute("UPDATE functions SET vram=?, rom_offset=?, size=?, n_insns=?, target=?, relocs=?, seed=NULL, "
                       "best_score=NULL WHERE id=?",
                       (new_start, new_start - gba.BASE, size, max(1, size // 2), data,
                        json.dumps([list(x) for x in refs or []]), fn["id"]))
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
