"""Matching a function from its matched twin: the same code with other constants, data and callees.

Games are full of copies: a factory per scene, a constructor per object, a handler per state, identical but for a
number, the address of a table or the function they call (Harvest Moon GBA: eight 74-instruction scene factories, one
matched, the others left at scores in the thousands). find_similar points agents at the matched one, but they rewrite
it by hand, a turn per spelling. Here it is done by the judge: the matched C is renamed, the operands that differ
between the two functions' instructions (immediates, literal-pool words, call targets) are substituted in it, and the
variants are judged; a byte-identical one is recorded as a match.
"""

from __future__ import annotations

import re
import struct
from io import BytesIO

from elftools.elf.elffile import ELFFile

from ...elfobj import _function_symbols
from ...network import NetworkError
from ...rom import match_arm

_NUM = re.compile(r"(?<![\w.])(0[xX][0-9a-fA-F]+|\d+)(?![\w.])")
_IMM = re.compile(r"#(-?0x[0-9a-fA-F]+|-?\d+)")
MAX_VARIANTS = 24


def _value(tok: str) -> int:
    return int(tok, 16) if tok[:2] in ("0x", "0X") else int(tok)


def _decode(code: bytes, vram: int) -> list[tuple[str, str, int | None, int | None]]:
    """(mnemonic, operands with immediates blanked, the immediate or call/branch target, the literal word it loads)."""
    import capstone

    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
    out = []
    for ins in md.disasm(code, vram):
        lit = None
        imm = None
        if ins.mnemonic == "ldr" and "[pc, #" in ins.op_str:
            at = ((ins.address + 4) & ~3) + int(_IMM.search(ins.op_str).group(1), 0) - vram
            if 0 <= at <= len(code) - 4:
                lit = struct.unpack_from("<I", code, at)[0]
        elif (m := _IMM.search(ins.op_str)):
            imm = int(m.group(1), 0)
        out.append((ins.mnemonic, _IMM.sub("#", ins.op_str), imm, lit))
    return out


def _replace_number(src: str, old: int, new: int, which: int | None = None) -> str | None:
    """`src` with the numeric literal(s) worth `old` written as `new` (the same base): all of them, or only the
    `which`-th. None when there's no such literal."""
    hits = [m for m in _NUM.finditer(src) if _value(m.group(1)) == old]
    if not hits or (which is not None and which >= len(hits)):
        return None
    out, last = [], 0
    for k, m in enumerate(hits):
        if which is not None and k != which:
            continue
        tok = m.group(1)
        out += [src[last:m.start(1)], hex(new) if tok[:2] in ("0x", "0X") else str(new)]
        last = m.end(1)
    return "".join(out) + src[last:]


class AdaptMixin:
    def adapt_from_twin(self, slug: str, name: str, twin: str) -> dict:
        """Try `twin`'s matched C for `name`, with the constants, data and callees that differ substituted. Returns
        {"matched", "score", "variants", "source"}: a byte-identical variant is recorded as the match."""
        proj = self._project(slug)
        fn, tw = self._function(name, slug), self._function(twin, slug)
        if tw["status"] != "matched" or not tw["matched_source"]:
            raise NetworkError(f"{tw['name']} is not matched")
        if fn["status"] != "open":
            raise NetworkError(f"{fn['name']} is {fn['status']}")
        mine, theirs = _decode(bytes(fn["target"]), fn["vram"]), _decode(bytes(tw["target"]), tw["vram"])
        if [m for m, *_ in mine] != [m for m, *_ in theirs]:
            raise NetworkError("the two functions' instructions differ in more than their operands")
        syms = self.symbols(proj["id"])
        src = re.sub(rf"\b{re.escape(tw['name'])}\b", fn["name"], tw["matched_source"])
        names: dict[str, str] = {}
        numbers: list[tuple[int, int]] = []
        for (m, ops, imm, lit), (_, ops2, imm2, lit2) in zip(mine, theirs):
            if ops != ops2 and not (m.startswith("b") or m == "ldr"):
                continue  # other registers: not something a substitution fixes
            if m in ("bl", "blx") and imm is not None and imm2 is not None and imm != imm2:
                names[syms.label(imm2 & ~1)] = syms.label(imm & ~1)
            elif lit is not None and lit2 is not None and lit != lit2:
                old, new = syms.label(lit2 & ~1), syms.label(lit & ~1)
                if lit2 >= 0x02000000 and re.search(rf"\b{re.escape(old)}\b", src):
                    names[old] = new
                else:
                    numbers.append((lit2, lit))
            elif imm is not None and imm2 is not None and imm != imm2 and not m.startswith("b"):
                numbers.append((imm2, imm))
        for old, new in names.items():
            src = re.sub(rf"\b{re.escape(old)}\b", new, src)
        numbers = list(dict.fromkeys(numbers))
        variants = []
        # every literal changed everywhere; then, for a value used more than once, each occurrence alone
        allsub = src
        for old, new in numbers:
            allsub = _replace_number(allsub, old, new) or allsub
        variants.append(allsub)
        for old, new in numbers:
            n = len([m for m in _NUM.finditer(src) if _value(m.group(1)) == old])
            if n > 1:
                for which in range(n):
                    v = src
                    for o2, n2 in numbers:
                        v = (_replace_number(v, o2, n2, which) if o2 == old else _replace_number(v, o2, n2)) or v
                    variants.append(v)
        variants = list(dict.fromkeys(variants))[:MAX_VARIANTS]
        ctx = self._context(proj["id"], fn["unit"])
        read = self.reader(proj)
        target = match_arm.ArmTarget(fn["name"], fn["vram"], fn["target"])
        best = None
        for v in variants:
            result = self._compile(proj, ctx["header"], v, fn)
            if not result.ok or not _function_symbols(ELFFile(BytesIO(result.obj))).get(fn["name"]):
                continue
            res = match_arm.link(result.obj, fn["name"], target, syms, read)
            if res.candidate is not None and res.exact:
                agent, _ = self.local_agent("twin-adapter")
                out = self.attempt(agent, fn["name"], v, slug)
                return {"matched": bool(out.get("matched")), "score": out.get("score"), "variants": len(variants), "source": v}
            best = best or v
        return {"matched": False, "score": None, "variants": len(variants), "source": best}

    def adapt_twins(self, slug: str, min_similarity: float = 0.95, limit: int = 0, status: dict | None = None) -> list[dict]:
        """adapt_from_twin for every open function whose closest matched look-alike has the same instructions."""
        proj = self._project(slug)
        rows = self.store.all("SELECT * FROM functions WHERE project_id=? AND status='open' AND n_insns<=600 "
                              "AND id NOT IN (SELECT function_id FROM claims) ORDER BY n_insns", proj["id"])
        found = []
        if status is not None:
            status.update(total=len(rows), done=0, matched=0)
        for fn in rows[:limit] if limit else rows:
            if status is not None:
                status["done"] += 1
            twins = [(r, s) for r, s in self.similar(proj, fn, top=6) if r["status"] == "matched" and s >= min_similarity
                     and r["n_insns"] == fn["n_insns"]]
            for tw, sim in twins[:3]:
                try:
                    res = self.adapt_from_twin(slug, fn["name"], tw["name"])
                except NetworkError:
                    continue
                except Exception:  # one odd pair never stops the pass
                    continue
                found.append({"function": fn["name"], "twin": tw["name"], "similarity": round(sim, 3), **{k: res[k] for k in ("matched", "variants")}})
                if res["matched"]:
                    if status is not None:
                        status["matched"] += 1
                    break
        return found

    def start_adapt_twins(self, slug: str) -> dict:
        import threading

        jobs = self.__dict__.setdefault("adapt_jobs", {})
        state = jobs.get(slug)
        if state and state["state"] == "running":
            return state
        state = jobs[slug] = {"state": "running", "total": 0, "done": 0, "matched": 0, "found": [], "error": None}

        def run() -> None:
            try:
                state["found"] = self.adapt_twins(slug, status=state)
                state["state"] = "done"
            except Exception as e:
                state["state"], state["error"] = "error", str(e)

        threading.Thread(target=run, daemon=True, name=f"adapt-{slug}").start()
        return state

