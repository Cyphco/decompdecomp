"""Where a function ends: checked against the C agents wrote for it.

The split decides where each function's bytes end (code, then the literal pool after it, then alignment), and it is
sometimes a halfword or a few words off: it stops inside a pool word, leaves out the pool, or keeps the first bytes of
the next function. Agents found such functions by their scores (a compile that is instruction-exact and scores 100 to
900 only because the original's recorded bytes are too short or too long) and reported them as suggestions, but a
boundary report only worked for MIPS, so the functions stayed stuck. The agents' own C settles it: a function's compiled
size is what it really occupies, and when that C, linked at the function's address, is byte-identical to the ROM
over exactly that many bytes, the recorded extent was wrong.
"""

from __future__ import annotations

import json
import threading
from io import BytesIO

from elftools.elf.elffile import ELFFile

from ...elfobj import _function_symbols
from ...network import NetworkError
from ...rom import gba, gba_candidates, match_arm


class ExtentMixin:
    def repair_extents(self, slug: str, apply: bool = True, limit: int = 0, status: dict | None = None) -> list[dict]:
        """Every open GBA function with a best attempt whose C compiles to a size other than the recorded one: when
        that C is byte-identical to the ROM at that size, the function's extent is set to it and the C is judged
        (a match, credited as usual). `apply=False` only reports. Returns what it found, one entry per function."""
        proj = self._project(slug)
        if self.cfg(proj).get("platform") != "gba":
            raise NetworkError("function extents are checked for GBA games")
        rows = self.store.all(
            "SELECT * FROM functions WHERE project_id=? AND status='open' AND best_source IS NOT NULL AND best_score>0 "
            "AND id NOT IN (SELECT function_id FROM claims) ORDER BY best_score, vram", proj["id"])
        if limit:
            rows = rows[:limit]
        read = self.reader(proj)
        rom, _segments = self._rom(proj)
        starts = sorted(r["vram"] for r in self.store.all("SELECT vram FROM functions WHERE project_id=?", proj["id"]))
        syms = self.symbols(proj["id"])
        agent, _ = self.local_agent("extent-repair")
        literals = None
        found: list[dict] = []
        if status is not None:
            status.update(total=len(rows), done=0, fixed=0)
        for fn in rows:
            if status is not None:
                status["done"] += 1
            if status is not None and status.get("stop"):
                break
            try:
                ctx = self._context(proj["id"], fn["unit"])
                hit = None
                for source in self._extent_candidates(fn):
                    result = self._compile(proj, ctx["header"], source, fn)
                    if not result.ok:
                        continue
                    sym = _function_symbols(ELFFile(BytesIO(result.obj))).get(fn["name"])
                    size = sym[2] if sym else 0
                    if not sym or size <= 0 or size == fn["size"] or size > 0x4000 or size % 2:
                        continue
                    end = fn["vram"] + size
                    if any(fn["vram"] < s < end for s in starts):  # it would take another function's bytes
                        continue
                    data = read(fn["vram"], size)
                    if data is None:
                        continue
                    res = match_arm.link(result.obj, fn["name"], match_arm.ArmTarget(fn["name"], fn["vram"], data), syms, read)
                    if res.candidate is not None and res.exact:
                        hit = (source, size, data)
                        break
                if hit is None:
                    continue
                source, size, data = hit
                entry = {"function": fn["name"], "was": fn["size"], "now": size, "score": fn["best_score"], "matched": False}
                found.append(entry)
                if not apply:
                    continue
                if literals is None:
                    literals = gba_candidates.literal_words(rom, starts)
                refs = gba._refs(data, fn["vram"], literals, fn["vram"] - gba.BASE)
                old = (fn["size"], fn["n_insns"], fn["target"], fn["relocs"])
                self._set_extent(proj, fn, size, data, refs)
                out = self.attempt(agent, fn["name"], source, slug)
                entry["matched"] = bool(out.get("matched"))
                if not entry["matched"]:  # it should: it was byte-identical a moment ago. Put the row back.
                    with self.store.tx() as db:
                        db.execute("UPDATE functions SET size=?, n_insns=?, target=?, relocs=? WHERE id=?", (*old, fn["id"]))
                    self._xrefs.pop(proj["id"], None)
                elif status is not None:
                    status["fixed"] += 1
            except NetworkError:
                continue
            except Exception:  # one function never stops the pass
                import logging

                logging.getLogger("decompdecomp").exception("extent check of %s failed", fn["name"])
        return found

    def _extent_candidates(self, fn, limit: int = 12) -> list[str]:
        """The C worth trying for a function: its best attempt, then the latest different ones that compiled (the one
        that is exact at the right length often scores worse than a variant: the extra bytes count against it)."""
        out = [fn["best_source"]]
        for r in self.store.all("SELECT source FROM attempts WHERE function_id=? AND compiled=1 AND source IS NOT NULL "
                                "ORDER BY id DESC LIMIT 60", fn["id"]):
            if r["source"] not in out:
                out.append(r["source"])
            if len(out) >= limit:
                break
        return out

    def _set_extent(self, proj, fn, size: int, data: bytes, refs: list) -> None:
        with self.store.tx() as db:
            db.execute("UPDATE functions SET size=?, n_insns=?, target=?, relocs=?, seed=NULL WHERE id=?",
                       (size, max(1, size // 2), data, json.dumps([list(r) for r in refs or []]), fn["id"]))
            db.execute("UPDATE symbols SET size=? WHERE project_id=? AND name=?", (size, proj["id"], fn["name"]))
            self._event(db, proj["id"], None, "boundary", f"{fn['name']}: {fn['size']} -> {size} bytes (its C matches there)")
        self._xrefs.pop(proj["id"], None)

    def start_extent_repair(self, slug: str, apply: bool = True) -> dict:
        """repair_extents in the background; the returned dict is its live status."""
        jobs = self.__dict__.setdefault("extent_jobs", {})
        state = jobs.get(slug)
        if state and state["state"] == "running":
            return state
        state = jobs[slug] = {"state": "running", "total": 0, "done": 0, "fixed": 0, "found": [], "error": None}

        def run() -> None:
            try:
                state["found"] = self.repair_extents(slug, apply=apply, status=state)
                state["state"] = "done"
            except Exception as e:
                state["state"], state["error"] = "error", str(e)

        threading.Thread(target=run, daemon=True, name=f"extents-{slug}").start()
        return state
