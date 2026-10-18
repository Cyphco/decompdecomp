"""The permuter, in the background: the decomp community's way through the last few percent.

A function at 95% usually differs in register allocation or instruction order, which comes down to how the C
is written, not what it does: the order of statements and declarations, a temporary, a cast, `x += 1` for
`x++`, `register`. decomp-permuter tries thousands of such rewrites and keeps what scores better; agents doing
it by hand spend turns (and tokens) on it, and stall. Here it runs on its own, on spare CPU, on the near misses
agents left (or autopilot's drafts reached): it holds a function for a minute at a time, so an agent that
wants it gets it next, records every improvement as the function's best attempt (agents start from it), and
a match as a match. Rewrites are candidate spellings, not behavior proofs; what matches is still judged
byte for byte, like everything else. Reviewed behavior candidates are preserved separately.
"""

from __future__ import annotations

import hashlib
import logging
import os
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from .. import scoring
from ..network import NetworkError
from ..permuter import mutate
from ..workstate import identity

log = logging.getLogger("decompdecomp")
NEAR = 0.06  # a near miss: at most this much of the function differs (best_score <= 6% of n_insns * 100)
SECONDS = 60  # per function per turn
MAX_VARIANTS = 256  # bound a turn even when compilation fails immediately
MAX_FAILURES = 16
MAX_TURNS = 4  # turns per function before it's left to agents
# functions permuted at once: each variant is a compile (a process of its own), so threads use the cores; a third of
# them, leaving the rest to the judge and the agents (one at a time left 23 of 24 cores idle with 150 near misses)
WORKERS = max(2, (os.cpu_count() or 4) // 3)


@dataclass
class State:
    state: str = "running"
    tried: int = 0  # functions permuted
    variants: int = 0
    improved: int = 0
    matched: int = 0
    compile_failed: int = 0
    evaluation_failed: int = 0
    scored: int = 0
    duplicates: int = 0
    errors: int = 0
    last_error: str = ""
    current: str = ""
    started_at: float = field(default_factory=time.time)
    stop: threading.Event = field(default_factory=threading.Event)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def add(self, name, amount=1, error=""):
        with self.lock:
            setattr(self, name, getattr(self, name) + amount)
            if error:
                self.last_error = error[:300]


class Permuter:
    def __init__(self, net):
        self.net = net
        self.jobs: dict[str, State] = {}


    def status(self, slug: str) -> dict | None:
        st = self.jobs.get(slug)
        if st is None:
            return None
        with st.lock:
            return {k: v for k, v in st.__dict__.items() if k not in ("stop", "lock")}

    def start(self, slug: str) -> State | None:
        """Run on the project's near misses until there are none (looking again every few minutes while the
        app runs: agents make new ones)."""
        if (st := self.jobs.get(slug)) is not None and st.state == "running":
            return st
        if slug in self.net.links:  # a room member: the host's copy permutes, and its matches come back here
            return None
        st = self.jobs[slug] = State()
        threading.Thread(target=self._loop, args=(slug, st), daemon=True, name=f"permuter-{slug}").start()
        return st

    def stop(self, slug: str) -> None:
        if (st := self.jobs.get(slug)) is not None:
            st.stop.set()

    def candidates(self, proj, limit: int = WORKERS * 3) -> list:
        rows = self.net.store.all(
            "SELECT * FROM functions WHERE project_id=? AND status='open' AND best_source IS NOT NULL "
            "AND best_score > 0 AND best_score <= n_insns * 100 * ? AND n_insns <= 400 "
            "AND id NOT IN (SELECT function_id FROM claims) ORDER BY CAST(best_score AS REAL) / (n_insns * 100)",
            proj["id"], NEAR)
        todo = []
        for row in rows:
            key = self._identity(proj, row)
            tried = self.net.store.one("SELECT turns FROM permuter_runs WHERE function_id=? AND identity=?", row["id"], key)
            rejected = self.net.store.one("SELECT verdict FROM candidate_checks WHERE function_id=? AND source=? "
                                          "ORDER BY id DESC LIMIT 1", row["id"], row["best_source"])
            if (not tried or tried["turns"] < MAX_TURNS) and (not rejected or rejected["verdict"] != "rejected"):
                todo.append(row)
                if len(todo) >= limit:
                    break
        return todo

    def _identity(self, proj, fn):
        return hashlib.sha256((identity(self.net, fn, proj) + fn["best_source"]).encode()).hexdigest()

    def _loop(self, slug: str, st: State) -> None:
        agent, _ = self.net.local_agent("permuter")
        idle = 0
        try:
            while not st.stop.is_set():
                try:
                    proj = self.net.project_row(slug)
                except NetworkError:
                    return  # the project is gone
                todo = self.candidates(proj)
                if not todo:
                    idle += 1
                    if idle > 20:  # nothing for an hour: done until agents start again
                        return
                    st.stop.wait(180)
                    continue
                idle = 0

                def one(fn, proj=proj) -> None:
                    if st.stop.is_set():
                        return
                    try:
                        self._permute(agent, proj, fn, st)
                    except Exception as e:  # one odd function must not stop the rest
                        st.add("errors", error=f"{fn['name']}: {e}")
                        log.exception("permuter: %s", fn["name"])

                with ThreadPoolExecutor(max_workers=WORKERS, thread_name_prefix=f"permute-{slug}") as pool:
                    list(pool.map(one, todo))
        finally:
            with st.lock:
                st.state = "stopped" if st.stop.is_set() else "done"
                st.current = ""

    def _hold(self, agent, fn) -> bool:
        now = time.time()
        with self.net.store.tx() as db:
            self.net._expire_claims(db)
            if db.execute("SELECT 1 FROM claims WHERE function_id=?", (fn["id"],)).fetchone():
                return False
            db.execute("INSERT INTO claims VALUES(?,?,?,?)", (fn["id"], agent.id, now, now + SECONDS + 120))
        return True

    def _let_go(self, agent, fn) -> None:
        with self.net.store.tx() as db:
            db.execute("DELETE FROM claims WHERE function_id=? AND agent_id=?", (fn["id"], agent.id))

    def _permute(self, agent, proj, fn, st: State) -> None:
        if not self._hold(agent, fn):
            return
        try:
            key = self._identity(proj, fn)
            with self.net.store.tx() as db:
                db.execute("INSERT OR IGNORE INTO permuter_runs VALUES(?,?,0)", (fn["id"], key))
                row = db.execute("SELECT turns FROM permuter_runs WHERE function_id=? AND identity=?", (fn["id"], key)).fetchone()
                if row["turns"] >= MAX_TURNS:
                    return
                turn = row["turns"] + 1
                db.execute("UPDATE permuter_runs SET turns=? WHERE function_id=? AND identity=?", (turn, fn["id"], key))
            with st.lock:
                st.current = fn["name"]
            st.add("tried")
            fork = self.net.fork_slug(proj["slug"])
            rng = random.Random(f"{fn['id']}-{key}-{turn}")
            seen = {r["source_hash"] for r in self.net.store.all(
                "SELECT source_hash FROM permuter_trials WHERE function_id=? AND identity=?", fn["id"], key)}
            seen.add(hashlib.sha256(fn["best_source"].encode()).hexdigest())
            best_src = cur_src = fn["best_source"]
            best = cur = fn["best_score"]
            deadline = time.monotonic() + SECONDS
            tried = failures = 0
            for _ in range(MAX_VARIANTS * 8):
                if time.monotonic() >= deadline or best <= 0 or st.stop.is_set() or tried >= MAX_VARIANTS:
                    break
                cand = mutate(cur_src if rng.random() < 0.85 else best_src, rng)
                if cand is None:
                    continue
                st.add("variants")
                digest = hashlib.sha256(cand.encode()).hexdigest()
                if digest in seen:
                    st.add("duplicates")
                    continue
                seen.add(digest)
                tried += 1
                score, outcome, error = self._score(agent, proj, fn, cand, best, fork)
                st.add(outcome, error=error)
                with self.net.store.tx() as db:
                    db.execute("INSERT OR IGNORE INTO permuter_trials VALUES(?,?,?,?)", (fn["id"], key, digest, outcome))
                if score is None:
                    failures += 1
                    if failures >= MAX_FAILURES:
                        break
                    continue
                failures = 0
                if score < best:
                    best, best_src = score, cand
                    st.add("improved")
                    if score == 0:
                        st.add("matched")
                        break
                if score <= cur or rng.random() < 0.02:
                    cur, cur_src = score, cand
        finally:
            self._let_go(agent, fn)

    def _score(self, agent, proj, fn, source: str, best: int, fork: str | None) -> tuple[int | None, str, str]:
        """A variant's score; recorded (as the function's best attempt, or its match) only when it beats `best`."""
        if fork:
            res = self.net.forks.attempt(agent, fork, fn["name"], source, keep=False, quiet=best)
            value = res.get("score")
            return value, "scored" if value is not None else "evaluation_failed", ""
        ctx = self.net._context(proj["id"], fn["unit"])
        result = self.net._compile(proj, ctx["header"], source, fn)
        if not result.ok:
            return None, "compile_failed", result.log.strip()[:300]
        cand, verdict, problems = self.net._evaluate(fn, proj, result.obj)
        if cand is None:
            return None, "evaluation_failed", "; ".join(problems) or "compiled object has no target function"
        d = scoring.diff(self.net._target_obj(fn, proj), cand)
        if verdict is not None:
            d = scoring.DiffResult(0 if verdict else max(1, d.score), d.max_score, d.rows, verdict)
        if d.score < best:
            self.net._record(fn, agent, d.score, source, ctx["version"], matched=d.bytes_match, via="permuter")
        return (0 if d.bytes_match else max(1, d.score)), "scored", ""
