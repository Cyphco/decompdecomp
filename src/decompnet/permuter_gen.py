"""Variants of one function's C, made by decomp-permuter's randomizer (MIT, a pinned tool: toolchains.toml).

A program of its own, not a module of decompdecomp: app/permute.py runs it with the Python of decomp-permuter's
environment, `python -I permuter_gen.py <decomp-permuter's folder>`, and it imports nothing of decompdecomp. Our
own judge scores what it writes; this only makes candidates, so a variant that doesn't compile costs one compile.

In, on stdin, one job per line, each a JSON object:
    header    the shared header, as the compiler gets it
    source    the near miss's C
    function  its name
    family    base, ido, gcc or mwcc: the weights decomp-permuter tuned per compiler (default_weights.toml)
    seed      any number: the same job gives the same variants
    count     how many variants to write
Out, on stdout, one JSON object per line: {"variant": C} for each variant, distinct and none the source itself,
each the function alone plus whatever the randomizer added beside it (a helper it inlined code into); or
{"error": why} when the C can't be read; then {"done": true}, and the next job. It runs for as long as its stdin
is open, so a header is parsed once per C a turn starts from: a second for a header of 300 KB.

decomp-permuter reads C through pycparser, which knows neither comments nor the preprocessor: comments go, and so
do the header's preprocessor lines (as for m2c's context, seeds.py). Its macros stay undefined here, which is fine
while the code only names them (GRAVITY): the compiler still gets the header whole. The source's own macros are
expanded (own_macros): agents keep helpers as macros, and m2c's drafts bring their M2C_FIELD block, so 23 of 26
near misses of a GBA game it couldn't read had them. C++ that's only C in `extern "C"` (agbcp's functions) is read
as C, each variant wrapped in `extern "C"` again. What still doesn't parse (a class, `__attribute__`) falls back
to the simple rewrites (permuter.py).

The walk is decomp-permuter's own: a variant is the last one rewritten once more (KEEP of the time) or the source
rewritten afresh, so variants drift a few rewrites away from the source and come back.
"""

import json
import random
import re
import sys

KEEP = 0.6  # decomp-permuter's default chance of building on the last variant instead of starting again
SOURCE_STARTS = "DECOMPDECOMP_SOURCE_STARTS"  # a typedef put between the header and the source, to find the seam
TRIES_PER_VARIANT = 4  # rewrites can repeat or fail: give up on a job that yields nothing new this many times over
MAX_SEED = 10**20
# a comment, or a string or character literal (group 1), which keeps any /* inside it
_COMMENT = re.compile(r'//[^\n]*|/\*.*?\*/|("(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\')', re.S)


def plain_c(text: str, directives: bool = True) -> str:
    """`text` without comments and continued lines, and without preprocessor lines unless `directives`."""
    text = _COMMENT.sub(lambda m: m.group(1) or " ", text.replace("\\\n", ""))
    return text if directives else "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


_DIRECTIVE = re.compile(r"[ \t]*#[ \t]*(\w*)[ \t]*(.*)")
_DEFINE = re.compile(r"(\w+)(\(([^)]*)\))?[ \t]*(.*)")
_WORD = re.compile(r"[A-Za-z_]\w*")
_EXTERN_C = re.compile(r'\bextern\s*"C"\s*(\{)?')
MAX_EXPANSIONS = 10000  # a macro that keeps growing: give up on the C


def own_macros(text: str) -> str:
    """`text` with its own preprocessor lines applied: its #define macros expanded where it uses them (`##` pasted),
    its #ifdef/#ifndef blocks kept or left out by what it defines itself, the lines themselves gone. ValueError for
    what this doesn't do (`#` stringizing, #if expressions, #include): then the C stays unread, as before."""
    macros: dict[str, tuple[list[str] | None, str]] = {}
    active: list[bool] = []
    out = []
    for line in text.splitlines():
        m = _DIRECTIVE.fullmatch(line)
        if m is None:
            if all(active):
                out.append(_expand(line, macros))
            continue
        word, rest = m.group(1), m.group(2).strip()
        if word in ("ifdef", "ifndef"):
            active.append((rest in macros) == (word == "ifdef"))
        elif word == "else" and active:
            active[-1] = not active[-1]
        elif word == "endif" and active:
            active.pop()
        elif not all(active):
            continue
        elif word == "define":
            d = _DEFINE.fullmatch(rest)
            if d is None or re.search(r"(?<!#)#(?!#)", d.group(4)):
                raise ValueError(f"a macro this can't expand: #define {rest}")
            params = [p.strip() for p in d.group(3).split(",") if p.strip()] if d.group(2) else None
            macros[d.group(1)] = (params, d.group(4))
        elif word == "undef":
            macros.pop(rest, None)
        elif word:
            raise ValueError(f"a preprocessor line this can't apply: #{word}")
    return "\n".join(out) + "\n"


def _expand(line: str, macros: dict, depth: int = 0) -> str:
    """One line with the macros expanded, again in what they expand to (not a macro inside its own expansion)."""
    if not macros:
        return line
    out, at, count = [], 0, 0
    for m in _WORD.finditer(line):
        if m.start() < at or m.group() not in macros:
            continue
        params, body = macros[m.group()]
        end = m.end()
        if params is not None:
            args, end = _arguments(line, m.end())
            if args is None:  # the name alone, not a call: left as it is
                continue
            if len(args) != len(params) and not (params == [] and args == [""]):
                raise ValueError(f"{m.group()} takes {len(params)} arguments")
            # (as the preprocessor does: an argument's own macros first, M2C_FIELD(M2C_FIELD(p, ...), ...))
            given = dict(zip(params, (_expand(a, macros, depth + 1).strip() for a in args)))
            body = re.sub(r"\b\w+\b", lambda w, given=given: given.get(w.group(), w.group()), body)
        body = re.sub(r"\s*##\s*", "", body)
        count += 1
        if count > MAX_EXPANSIONS or depth > 50:
            raise ValueError("a macro that doesn't stop expanding")
        inner = {k: v for k, v in macros.items() if k != m.group()}
        out.append(line[at:m.start()] + _expand(body, inner, depth + 1))
        at = end
    return "".join(out) + line[at:]


def _arguments(line: str, at: int) -> tuple[list[str] | None, int]:
    """A function-like macro's arguments after `at` (split at the commas outside parentheses), and where they end."""
    i = at
    while i < len(line) and line[i] in " \t":
        i += 1
    if i >= len(line) or line[i] != "(":
        return None, at
    depth, args, start = 0, [], i + 1
    for j in range(i, len(line)):
        c = line[j]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return args + [line[start:j]], j + 1
        elif c == "," and depth == 1:
            args.append(line[start:j])
            start = j + 1
    raise ValueError("a macro call that doesn't end on its line")


def without_extern_c(text: str) -> tuple[str, bool]:
    """C written as C++'s `extern "C"` (agbcp builds C++: its C functions need it to keep their names) as plain C, and
    whether it was: an `extern "C" { ... }` block's braces go with it."""
    if not _EXTERN_C.search(text):
        return text, False
    out, closes, depth, i = [], [], 0, 0
    while i < len(text):
        m = _EXTERN_C.match(text, i)
        if m:
            if m.group(1):
                closes.append(depth)  # the block's own brace: its closing one goes too
            i = m.end()
            continue
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            if closes and closes[-1] == depth:
                closes.pop()
                i += 1
                continue
            depth -= 1
        out.append(c)
        i += 1
    return "".join(out), True


def main() -> int:
    sys.path.insert(0, sys.argv[1])  # decomp-permuter's folder: its `src` package and its own copy of pycparser
    from perm_pycparser import c_ast
    from src.ast_util import to_c
    from src.candidate import Candidate
    from src.helpers import get_default_randomization_weights
    from src.perm.perm import EvalState

    def variants(job: dict):
        name, count = job["function"], int(job["count"])
        source, wrapped = without_extern_c(plain_c(job["source"]))
        try:
            source = own_macros(source)
        except ValueError as e:
            yield {"error": f"ValueError: {e}"}
            return
        unit = f"{plain_c(job['header'], directives=False)}\ntypedef int {SOURCE_STARTS};\n{source}\n"
        rng = random.Random(job["seed"])
        try:
            weights = get_default_randomization_weights(job.get("family") or "base")
            first = Candidate.from_source(unit, EvalState(), name, weights, rng.randrange(1, MAX_SEED))
        except Exception as e:  # the C or the header isn't C pycparser reads (a macro call, a compiler extension)
            yield {"error": f"{type(e).__name__}: {e}"}
            return
        seam = next(node for node in first.ast.ext if isinstance(node, c_ast.Typedef) and node.name == SOURCE_STARTS)

        def own_part(ast) -> str:
            """The C after the seam: the function and its neighbours from the source, without the header. A header
            declaration the randomizer retyped is left out: the header isn't the permuter's to change, and a
            second, different declaration would only fail to compile."""
            return to_c(c_ast.FileAST(ast.ext[ast.ext.index(seam) + 1:]))

        seen = {own_part(first.ast)}  # the source as decomp-permuter prints it: not a variant
        cand = first
        for _ in range(count * TRIES_PER_VARIANT):
            if len(seen) > count:
                break
            try:
                if cand is None or rng.random() >= KEEP:
                    cand = Candidate.from_source(unit, EvalState(), name, weights, rng.randrange(1, MAX_SEED))
                cand.randomize_ast()
                variant = own_part(cand.ast)
            except Exception:  # a rewrite that trips over this code: start again from the source
                cand = None
                continue
            if variant not in seen:
                seen.add(variant)
                yield {"variant": f'extern "C" {{\n{variant}}}\n' if wrapped else variant}

    for line in sys.stdin:
        if line.strip():
            for answer in variants(json.loads(line)):
                print(json.dumps(answer))
            print(json.dumps({"done": True}), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
