"""decomp-permuter on the near misses, in the background.

The permuter in permute.py rewrites lines; the decomp community's decomp-permuter (simonlindholm/decomp-permuter)
rewrites the C's syntax tree in dozens of ways and scores thousands of variants a minute on many cores, and is what
finishes most near misses in decomp projects. Agents here ran it by hand (a checkout at ~/permuter), one function at
a time. This runs it for each near miss in turn: the function's best attempt with the project's shared header is the
base, its original assembly the target, the project's compiler and flags the compile; a variant that scores 0 is
cut back to the function's own code and judged like any attempt (a match is credited to "decomp-permuter").
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from .. import toolchains
from ..network import NetworkError

log = logging.getLogger("decompdecomp")
NEAR = 0.06  # best_score <= 6% of n_insns * 100
MAX_INSNS = 300
ASM_HEADER = """.syntax unified
.macro thumb_func_start name
.global \\name
.type \\name, function
.thumb_func
.align 2
.endm
.macro non_word_aligned_thumb_func_start name
.global \\name
.type \\name, function
.thumb_func
.endm
.text
.thumb
"""
EXTRACT = Path(__file__).with_name("deep_permute_extract.py")


def checkout() -> Path | None:
    """The decomp-permuter checkout (DECOMP_PERMUTER, else ~/permuter), with its libraries in pylibs/."""
    root = Path(os.environ.get("DECOMP_PERMUTER") or Path.home() / "permuter")
    return root if (root / "permuter.py").exists() and (root / "pylibs").is_dir() else None


@dataclass
class Job:
    state: str = "running"
    total: int = 0
    done: int = 0
    matched: int = 0
    improved: int = 0
    current: str = ""
    skipped: list = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    stop: threading.Event = field(default_factory=threading.Event)
    proc: subprocess.Popen | None = None


class DeepPermuter:
    def __init__(self, net):
        self.net = net
        self.jobs: dict[str, Job] = {}

    def status(self, slug: str) -> dict | None:
        j = self.jobs.get(slug)
        return None if j is None else {k: v for k, v in j.__dict__.items() if k not in ("stop", "proc")}

    def stop(self, slug: str) -> None:
        if (j := self.jobs.get(slug)) is not None:
            j.stop.set()
            if j.proc is not None and j.proc.poll() is None:
                j.proc.kill()

    def start(self, slug: str, minutes: float = 4, jobs: int = 0) -> dict:
        if checkout() is None:
            raise NetworkError("decomp-permuter isn't installed: clone simonlindholm/decomp-permuter to ~/permuter "
                               "(with toml and pycparser in its pylibs/), or set DECOMP_PERMUTER")
        proj = self.net._project(slug)
        if self.net.cfg(proj).get("platform") != "gba":
            raise NetworkError("the decomp-permuter job is set up for GBA games (agbcc) for now")
        if (j := self.jobs.get(slug)) is not None and j.state == "running":
            return self.status(slug)
        j = self.jobs[slug] = Job()
        jobs = jobs or max(2, (os.cpu_count() or 4) // 3)
        threading.Thread(target=self._run, args=(slug, j, minutes, jobs), daemon=True, name=f"deep-permuter-{slug}").start()
        return self.status(slug)

    # ------------------------------------------------------------------ the loop

    def candidates(self, proj) -> list:
        return self.net.store.all(
            "SELECT * FROM functions WHERE project_id=? AND status='open' AND best_source IS NOT NULL AND best_score > 0 "
            "AND best_score <= n_insns * 100 * ? AND n_insns <= ? AND id NOT IN (SELECT function_id FROM claims) "
            "ORDER BY CAST(best_score AS REAL) / (n_insns * 100)", proj["id"], NEAR, MAX_INSNS)

    def _run(self, slug: str, j: Job, minutes: float, jobs: int) -> None:
        try:
            proj = self.net._project(slug)
            agent, _ = self.net.local_agent("decomp-permuter")
            todo = self.candidates(proj)
            j.total = len(todo)
            work = toolchains.data_dir() / "deep-permuter" / slug
            for fn in todo:
                if j.stop.is_set():
                    break
                j.current = fn["name"]
                try:
                    self._one(proj, agent, fn, work / fn["name"], minutes, jobs, j)
                except Exception as e:  # one function never stops the rest
                    j.skipped.append(f"{fn['name']}: {e}")
                    log.info("decomp-permuter: %s: %s", fn["name"], e)
                j.done += 1
        finally:
            j.state, j.current = ("stopped" if j.stop.is_set() else "done"), ""

    def _env(self) -> dict:
        tc = toolchains.root()
        shim = toolchains.data_dir() / "deep-permuter" / "bin"
        shim.mkdir(parents=True, exist_ok=True)
        cpp = shim / "cpp"
        if not cpp.exists():
            cpp.symlink_to(tc / "arm-gnu" / "bin" / "arm-none-eabi-cpp")
        root = checkout()
        return dict(os.environ, PATH=f"{shim}{os.pathsep}{tc / 'arm-gnu' / 'bin'}{os.pathsep}{os.environ.get('PATH', '')}",
                    PYTHONPATH=str(root / "pylibs"))

    def _one(self, proj, agent, fn, d: Path, minutes: float, jobs: int, j: Job) -> None:
        if not self._hold(agent, fn, minutes):
            return
        try:
            shutil.rmtree(d, ignore_errors=True)
            d.mkdir(parents=True)
            cfg = self.net.cfg(proj)
            tc = toolchains.root()
            header = self.net._context(proj["id"], fn["unit"])["header"]
            (d / "ctx.h").write_text(header, encoding="utf-8")
            (d / "base.c").write_text(header + "\n" + fn["best_source"] + "\n", encoding="utf-8")
            # the listing ends with the alignment after the function, which isn't part of its bytes
            listing = re.sub(r"(?:\n\s*\.byte 0x00, 0x00\s*)+\s*$", "\n", fn["asm"])
            (d / "target.s").write_text(ASM_HEADER + listing, encoding="utf-8")
            env = self._env()
            asm = subprocess.run([str(tc / "arm-gnu" / "bin" / "arm-none-eabi-as"), "-mcpu=arm7tdmi", "-mthumb-interwork",
                                  str(d / "target.s"), "-o", str(d / "target.o")], capture_output=True, text=True, env=env)
            # (the assembler pads a section to its 4-byte alignment)
            if asm.returncode != 0 or self._text_size(d / "target.o") not in (fn["size"], (fn["size"] + 3) & ~3):
                j.skipped.append(f"{fn['name']}: its listing doesn't assemble to its {fn['size']} bytes")
                return
            flags = " ".join(cfg["compiler"]["flags"])
            agbcc = tc / cfg["compiler"]["toolchain"] / "bin" / "agbcc"
            (d / "compile.sh").write_text(  # agbcc is the compiler proper: the preprocessor runs first, as in the judge
                "#!/bin/bash\nIN=$1; OUT=$3\n"
                f'"{tc / "arm-gnu" / "bin" / "arm-none-eabi-cpp"}" -nostdinc -undef "$IN" -o "${{OUT%.o}}.i" || exit 1\n'
                f'"{agbcc}" {flags} "${{OUT%.o}}.i" -o "${{OUT%.o}}.s" 2>/dev/null || exit 1\n'
                f'"{tc / "arm-gnu" / "bin" / "arm-none-eabi-as"}" -mcpu=arm7tdmi -mthumb-interwork "${{OUT%.o}}.s" -o "$OUT"\n'
                'rm -f "${OUT%.o}.s" "${OUT%.o}.i"\n', encoding="utf-8")
            (d / "compile.sh").chmod(0o755)
            (d / "settings.toml").write_text(f'func_name = "{fn["name"]}"\ncompiler_type = "gcc"\n', encoding="utf-8")
            j.proc = subprocess.Popen([sys.executable if os.environ.get("DECOMP_PERMUTER_PY") is None else os.environ["DECOMP_PERMUTER_PY"],
                                       "permuter.py", str(d), "-j", str(jobs), "--stop-on-zero"],
                                      cwd=checkout(), env=env, stdout=subprocess.DEVNULL, stderr=(d / "permuter.log").open("w"))
            try:
                j.proc.wait(timeout=minutes * 60)
            except subprocess.TimeoutExpired:
                j.proc.kill()
                j.proc.wait()
            j.proc = None
            outputs = sorted((int(m.group(1)), p) for p in d.glob("output-*") if (m := re.match(r"output-(\d+)-", p.name)))
            for score, out in outputs[:3]:  # the best few: a 0 is a match, else maybe a better best attempt
                src = self._extract(d / "ctx.h", out / "source.c", env)
                if not src:
                    continue
                self._let_go(agent, fn)
                res = self.net.attempt(agent, fn["name"], src, proj["slug"])
                if res.get("matched"):
                    j.matched += 1
                    return
                if res.get("score") is not None and res["score"] < fn["best_score"]:
                    j.improved += 1
                if score > 0:
                    break
        finally:
            self._let_go(agent, fn)

    @staticmethod
    def _text_size(obj: Path) -> int | None:
        from elftools.elf.elffile import ELFFile

        try:
            with obj.open("rb") as f:
                sec = ELFFile(f).get_section_by_name(".text")
                return sec.data_size if sec is not None else None
        except Exception:
            return None

    @staticmethod
    def _extract(ctx: Path, source: Path, env: dict) -> str | None:
        """The function's own code from a permuter output (which has the shared header in front), or None."""
        if not source.exists():
            return None
        python = os.environ.get("DECOMP_PERMUTER_PY") or "python3"
        res = subprocess.run([python, str(EXTRACT), str(ctx), str(source)], capture_output=True, text=True, env=env, timeout=120)
        return res.stdout if res.returncode == 0 and res.stdout.strip() else None

    def _hold(self, agent, fn, minutes: float) -> bool:
        now = time.time()
        with self.net.store.tx() as db:
            self.net._expire_claims(db)
            if db.execute("SELECT 1 FROM claims WHERE function_id=?", (fn["id"],)).fetchone():
                return False
            db.execute("INSERT INTO claims VALUES(?,?,?,?)", (fn["id"], agent.id, now, now + minutes * 60 + 600))
        return True

    def _let_go(self, agent, fn) -> None:
        with self.net.store.tx() as db:
            db.execute("DELETE FROM claims WHERE function_id=? AND agent_id=?", (fn["id"], agent.id))
