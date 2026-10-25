# Matching GBA code built with agbcc

agbcc is pret's rebuild of the GCC 2.95-era compiler most GBA games used (`old_agbcc` for some early
games, `agbcc_arm` for ARM code). Typical flags `-mthumb-interwork -O2`; the project sets them per file.
`try_compiler(function, "old_agbcc")` builds C with the older snapshot, and `suggest(compiler="old_agbcc", ...)`
suggests it for a range; flags go in `flags` as usual (`-mthumb-interwork -O2 -mlong-calls`).

C89, not C99: every local is declared at the top of its block, before any statement (no declarations after code,
no `for (int i = 0; ...)`). Otherwise the compiler only says "syntax error before `x'" and nothing compiles.

What moves the output
- Local declaration order and first use change register allocation. Reorder before rewriting.
- Narrow types: every `u8`/`s16` local or parameter gets truncation shifts after arithmetic; `int`
  locals don't. Match the shifts in the target by choosing types.
- Loop shape: `for`, `while` and `do {} while` produce different block layouts.
- `if (a) { if (b) }` vs `if (a && b)`, early returns vs one exit.
- Temporaries: introduce or remove one; reuse a variable for two values.
- Casts like `(u16)`/`(s32)` placed on subexpressions change when truncation happens.
- `register u32 x asm("r4")` pins a variable to a register; pret projects use it sparingly where nothing
  else works. Prefer natural code first.

Project conventions (pret-style): `gSomething` globals, `sSomething` statics, `Task_*` callbacks,
`FAKEMATCH`/`NONMATCHING` markers for hacks. Look at how matched files in the project write similar code
before inventing a trick.

Calls into BIOS use `swi`; the project wraps them (`CpuSet`, `LZ77UnCompVram`...): use the wrappers.
