"""Run with decomp-permuter's Python (its pylibs/ on PYTHONPATH): print the part of a permuter output that comes after the
shared header, so it can be judged like any attempt (which puts the header in front itself).

usage: deep_permute_extract.py <the shared header> <the permuter's output source.c>
"""

import sys

import pycparser
from pycparser import c_generator

ARGS = ["-P", "-undef", "-D__attribute__(x)="]  # as decomp-permuter preprocesses


def main() -> int:
    header, source = sys.argv[1], sys.argv[2]
    n = len(pycparser.parse_file(header, use_cpp=True, cpp_path="cpp", cpp_args=ARGS).ext)
    out = pycparser.parse_file(source, use_cpp=True, cpp_path="cpp", cpp_args=ARGS)
    gen = c_generator.CGenerator()
    print("\n".join(gen.visit(node) + (";" if not isinstance(node, pycparser.c_ast.FuncDef) else "") for node in out.ext[n:]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
