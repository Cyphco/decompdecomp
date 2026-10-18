"""Persistent retry plans and behavior evidence, separate from the byte-for-byte judge."""

from __future__ import annotations

import hashlib
import json
import time

RETRY_ATTEMPTS = 8


def identity(net, fn, proj):
    """Invalidate evidence when the target, compiler, context or symbol addresses change."""
    cfg = json.loads(proj["config"])
    ctx = net._context(proj["id"], fn["unit"])
    symbols = [tuple(r) for r in net.store.all(
        "SELECT name,address,size,kind FROM symbols WHERE project_id=? ORDER BY name", proj["id"])]
    value = [fn["name"], fn["vram"], bytes(fn["target"] or b"").hex(), fn["relocs"], ctx["header"],
             cfg.get("compiler"), cfg.get("compiler_ranges"), symbols]
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def plan_attempt(net, agent, project, function, hypothesis):
    from .network import NetworkError

    fn = net._function(function, project)
    proj = net.store.one("SELECT * FROM projects WHERE id=?", fn["project_id"])
    if json.loads(proj["config"]).get("kind") == "fork" or fn["status"] != "open":
        raise NetworkError("retry plans are for open ROM functions")
    hypothesis = " ".join(hypothesis.split())
    if len(hypothesis) < 40:
        raise NetworkError("describe the new hypothesis, its evidence, and what differs from the prior attempts")
    key = identity(net, fn, proj)
    with net.store.tx() as db:
        previous = db.execute("SELECT text FROM notes WHERE function_id=? AND text LIKE 'Retry hypothesis:%'",
                              (fn["id"],)).fetchall()
        if any(r["text"].casefold() == ("Retry hypothesis: " + hypothesis).casefold() for r in previous):
            raise NetworkError("this hypothesis was already tried; read the notes and provide a different testable hypothesis")
        claim = db.execute("SELECT agent_id FROM claims WHERE function_id=?", (fn["id"],)).fetchone()
        if claim and claim["agent_id"] != agent.id:
            raise NetworkError("another agent holds this function; leave a note instead of resetting its retry budget")
        db.execute("INSERT OR REPLACE INTO retry_plans VALUES(?,?,?,?,?,?)",
                   (fn["id"], hypothesis, key, fn["attempts"], fn["best_score"], time.time()))
        db.execute("INSERT INTO notes(project_id,function_id,agent_id,text,created_at) VALUES(?,?,?,?,?)",
                   (fn["project_id"], fn["id"], agent.id, "Retry hypothesis: " + hypothesis, time.time()))
    return f"Saved hypothesis for {fn['name']}; up to {RETRY_ATTEMPTS} recorded attempts before reassessment."


def check_retry(net, fn, proj):
    from .network import WALL_ABANDONS, NetworkError

    if json.loads(proj["config"]).get("kind") != "rom" or fn["status"] != "open" or fn["abandons"] < WALL_ABANDONS:
        return
    row = net.store.one("SELECT * FROM retry_plans WHERE function_id=?", fn["id"])
    if row is None or row["identity"] != identity(net, fn, proj):
        raise NetworkError(f"{fn['name']} is stalled: read the notes, then call plan_attempt with new evidence before compiling")
    if fn["attempts"] - row["attempts_start"] >= RETRY_ATTEMPTS:
        raise NetworkError(f"{fn['name']} used its retry budget; release it with results or record a new hypothesis with plan_attempt")


def preserve_candidate(net, agent, project, function, source, evidence, verdict):
    from .network import NetworkError

    fn = net._function(function, project)
    proj = net.store.one("SELECT * FROM projects WHERE id=?", fn["project_id"])
    if verdict not in ("reviewed", "tested", "rejected") or not source.strip() or len(evidence.strip()) < 30:
        raise NetworkError("supply complete source, checks and limitations, and verdict reviewed, tested, or rejected")
    if json.loads(proj["config"]).get("kind") == "fork":
        raise NetworkError("candidate preservation is currently for ROM projects")
    key = identity(net, fn, proj)
    with net.store.tx() as db:
        db.execute("INSERT INTO candidate_checks(function_id,source,identity,evidence,verdict,agent_id,created_at) "
                   "VALUES(?,?,?,?,?,?,?)", (fn["id"], source, key, evidence.strip(), verdict, agent.id, time.time()))
    return f"Preserved {verdict} candidate and reported evidence for {fn['name']}; matching state is unchanged."


def candidate_brief(net, fn, proj):
    rows = net.store.all("SELECT * FROM candidate_checks WHERE function_id=? ORDER BY id DESC LIMIT 4", fn["id"])
    if not rows:
        return []
    key = identity(net, fn, proj)
    lines = ["", "### Behavior evidence (reported by agents; separate from binary matching)"]
    for row in rows:
        stale = " — target/compiler/context changed; recheck" if row["identity"] != key else ""
        lines += [f"{row['verdict']}{stale}: {row['evidence']}", "```c", row["source"], "```"]
    return lines


def coverage(rows):
    """Union address ranges so merged fragments and overlaps never inflate code coverage."""
    groups = {k: [] for k in ("matched", "open", "assembly", "excluded")}
    counts = dict.fromkeys(groups, 0)
    raw = 0
    for row in rows:
        reason = json.loads(row["meta"] or "{}").get("asm_code", "").lower()
        group = row["status"] if row["status"] in ("matched", "open") else "assembly"
        if group == "assembly" and (reason.startswith("not code") or "(merged into it)" in reason):
            group = "excluded"
        counts[group] += 1
        size = row["size"] or 0
        if row["vram"] is not None:
            groups[group].append((row["vram"], row["vram"] + size))
        if group != "excluded":
            raw += size

    def length(spans):
        total = 0
        end = -1
        for a, b in sorted(spans):
            total += max(0, b - max(a, end))
            end = max(end, b)
        return total

    code = groups["matched"] + groups["open"] + groups["assembly"]
    return {"counts": counts, "bytes": {k: length(v) for k, v in groups.items()},
            "code_bytes": length(code), "overlap_bytes": raw - length(code),
            "basis": "classified code ranges; excluded data and merged fragments; discovery may be incomplete"}
