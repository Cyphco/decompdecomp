"""Opt-in, finite behavioral checks before a ROM permuter promotes an ELF.

The local project manifest is trusted executable configuration. No manifest
means no change to existing projects; a configured check fails closed.
"""
from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
import subprocess
import tempfile

from ..hostenv import NO_WINDOW

log = logging.getLogger("decompdecomp")
MANIFEST = "behavioral-checks.json"


def permits(project: Path, function: str, obj: bytes) -> bool:
    project = Path(project)
    manifest = project / MANIFEST
    try:
        try:
            config = json.loads(manifest.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return True
        if config.get("version") != 1 or not isinstance(config.get("functions"), dict):
            raise ValueError("invalid behavioral-checks manifest")
        if function not in config["functions"]:
            return True
        expected = config["functions"][function]
        if not isinstance(expected, dict) or not expected:
            raise ValueError("a covered function must declare cases and seeds")
        required = set()
        for case, seeds in expected.items():
            if not isinstance(case, str) or not isinstance(seeds, list) or not seeds:
                raise ValueError("invalid case/seeds")
            for seed in seeds:
                if type(seed) is not int or (case, seed) in required:
                    raise ValueError("invalid or duplicate seed")
                required.add((case, seed))
        python, runner = Path(config["python"]), Path(config["runner"])
        if not python.is_absolute() or not runner.is_absolute():
            raise ValueError("runner and Python must be absolute paths")
        # Each attempt owns its files. No shared latest.json and no source recompile.
        with tempfile.TemporaryDirectory(prefix="decomp-behavior-") as folder:
            folder = Path(folder)
            candidate, report = folder / "candidate.o", folder / "report.json"
            candidate.write_bytes(obj)
            result = subprocess.run(
                [str(python), str(runner), "--project", str(project),
                 "--function", function, "--object", str(candidate),
                 "--seeds", ",".join(str(s) for s in sorted({s for _, s in required})),
                 "--report", str(report)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=90, creationflags=NO_WINDOW,
            )
            if result.returncode != 0:
                raise ValueError("runner failed or found a behavioral difference")
            data = json.loads(report.read_text(encoding="utf-8"))
            rows = data["results"]
            actual = [(r["case"], r["seed"]) for r in rows]
            if len(actual) != len(required) or set(actual) != required:
                raise ValueError("missing, extra or duplicate behavioral comparisons")
            digest = hashlib.sha256(obj).hexdigest()
            for row in rows:
                verdict = row["comparison"]
                if not (row["function"] == function and row["object_sha256"] == digest
                        and row["variant"] == "supplied-object"
                        and row["expected_equal"] is True and row["expectation_met"] is True
                        and verdict["original_valid"] is True and verdict["equal"] is True
                        and row["original"]["completed"] is True
                        and row["candidate"]["completed"] is True
                        and not row.get("load_error")):
                    raise ValueError("candidate did not pass its declared behavioral contract")
        log.info("behavioral gate: %s passed %d finite comparisons", function, len(required))
        return True
    except Exception as exc:
        # A broken runner/manifest/unsupported ELF is never a promotion permit.
        log.warning("behavioral gate: blocked %s: %s", function, exc)
        return False
