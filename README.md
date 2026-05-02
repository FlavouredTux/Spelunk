<p align="center">
  <img src="docs/mascot.png" alt="Ember" width="320">
</p>

<h1 align="center">Ember</h1>

<p align="center">
  A from-scratch reverse-engineering toolkit. No Capstone. No Zydis. No
  Ghidra. No LLVM. No vendored deps. Stdlib only.
</p>

<p align="center">
  <a href="https://github.com/FlavouredTux/Ember/actions/workflows/ci.yml">
    <img src="https://github.com/FlavouredTux/Ember/actions/workflows/ci.yml/badge.svg?branch=main" alt="ci">
  </a>
  <a href="https://github.com/FlavouredTux/Ember/stargazers">
    <img src="https://img.shields.io/github/stars/FlavouredTux/Ember?style=flat&color=yellow" alt="stars">
  </a>
  <img src="https://img.shields.io/badge/C%2B%2B-23-blue.svg" alt="C++23">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT">
  <img src="https://img.shields.io/badge/deps-stdlib--only-success.svg" alt="stdlib only">
</p>

ELF + Mach-O + PE loaders, Microsoft minidump and raw-region memory
images, an x86-64 decoder / lifter / SSA pipeline, structurer, pseudo-C
emitter, a built-in ptrace/Mach debugger that breakpoints against the
pseudo-C view, a declarative `.ember` annotation/scripting format, and
an Electron UI on top.

---

## In one screen

Source — `gotos.c`'s `multi_exit`:

```c
int multi_exit(const char* s, const char* t) {
    if (s == 0) goto fail;
    if (t == 0) goto fail;
    if (strlen(s) != strlen(t)) goto fail;
    return 0;
fail:
    return -1;
}
```

Ember's pseudo-C — `ember -p -s multi_exit gotos`:

```c
u64 multi_exit(u64 a1, u64 a2) {
  if (!a1) {
    return -1;
  }
  if (!a2) {
    return -1;
  }
  u64 r_strlen = strlen(a1);
  u64 r_strlen_2 = strlen(a2);
  if (r_strlen != r_strlen_2) {
    return -1;
  }
  return 0;
}
```

Structurally identical to the source — the `goto fail;` ladder is
recovered as an early-return chain, the spilled `s`/`t` parameters
forward to `a1`/`a2`, the strlen calls bind cleanly, and the `-1`
return renders as signed even though it lives in a `u64`-typed slot.
This is end-to-end pipeline work: SSA cleanup, phi-resolution at
structure time, init-only-slot forwarding, early-return collapse,
sign-aware immediate rendering.

---

## Build

C++23 compiler (gcc 15+ or recent Clang) and CMake 3.28+.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/cli/ember --help
```

UI:

```sh
cd ui && npm install && npm run dev
```

Set `EMBER_BIN` if the CLI isn't at `../build/cli/ember`.

## CLI

```
ember [options] <binary>

  -d, --disasm           linear disassembly of a function
  -c, --cfg              control-flow graph
  -i, --ir               lifted IR
      --ssa              IR in SSA form (implies -i)
  -O, --opt              run cleanup passes (implies --ssa)
      --struct           structured regions (implies -O)
  -p, --pseudo           pseudo-C output (implies --struct)

  -X, --xrefs            full call graph
      --strings          dump printable strings
      --arities          dump inferred arity per function
      --functions [P]    list every discovered function (TSV)
      --fingerprints     content-hash per function (cross-version matching)
      --teef             build a TEEF Max corpus TSV (library identifier)
      --recognize        match query fns against a TEEF corpus (--corpus PATH+)
      --validate NAME    where does NAME live + similar lookalikes
      --collisions       names / fingerprints bound to >1 address

      --ipa              run IPA before pseudo-C (typed sigs across calls)
      --resolve-calls    resolve indirect calls (IAT + constant vtables)
      --eh               parse unwind tables, mark landing pads
      --vm-detect        scan for interpreter-style VM dispatchers
      --list-syscalls VA report each `syscall` site in the function at VA
                         (TSV: file_offset, va, nr, name)
      --debug            launch / attach a debugger; see docs/debugger.md

  -s, --symbol NAME      target a specific symbol (default: main)
      --annotations P    user renames / signatures sidecar file
      --apply PATH       apply a .ember declarative script
      --dry-run          with --apply: don't write; dump the would-be TSV

      --regions PATH     load via raw-region manifest (Scylla-style scrape)
      --apply-patches F  apply (vaddr_hex, bytes_hex) patches to the binary
      --trace PATH        load observed indirect edges (TSV: from_va  to_va)
      --cache-dir DIR    override ~/.cache/ember
      --no-cache         bypass the on-disk cache
```

Heavyweight passes (`--xrefs`, `--strings`, `--arities`,
`--fingerprints`) cache to `~/.cache/ember/`, keyed on
`path | size | mtime | version`. First run is slow, subsequent runs
are instant.

## Debugger

`ember --debug PATH` launches a REPL-driven debugger backed by Linux
ptrace (or Mach on macOS) that uses ember's own pseudo-C as the source
view. Breakpoints take symbols, addresses, or `<symbol>:<line>` against
the decompiled output, so you can `b sub_4000b0:42` to break at the
asm address that maps to line 42 of the pseudo-C — no DWARF required.

```sh
ember --debug ./target -- arg1 arg2     # launch
ember --debug --attach-pid 1234         # attach
```

REPL surface (excerpt):

```
b <addr|sym|sym:line>   software breakpoint (also bin:sym to disambiguate)
c, s                    continue, single-step
regs [all]              GPRs (or full x87/SSE/AVX/AVX-512/DR)
set <reg> <value>       write rax/.../rip/rflags/...; <value> takes hex,
                        decimal, or any address-spec `b` accepts
x <addr> [n]            read + hex-dump
poke <addr> <hex>...    write hex bytes (`poke <a> 90 90 90` to nop out)
bt                      .eh_frame backtrace; RBP-walk fallback
code                    pseudo-C of the function around the current PC
aux <path>[@hex]        load a Binary as a symbol oracle for runtime-mmap'd
                        Mach-O / PE blobs the in-process loader pulled in
ignore <addr>           silently forward known-recovered fault PCs
threads, thread <tid>   multi-thread targets
```

Full surface in [docs/debugger.md](docs/debugger.md).

## Pipeline

```
binary  →  loader (ELF / Mach-O / PE / minidump / regions)
        →  decoder
        →  CFG
        →  IR lift  (x64 / arm64 / ppc64)
        →  SSA
        →  cleanup  (const-fold, copy-prop, GVN, store→load forward, DSE)
        →  local type inference   ─┐
        →  IPA (typed signatures) ─┴─ optional, opt-in
        →  frame layout            (typed stack locals, PDB names if any)
        →  structurer              (if / while / for / switch / goto)
        →  pseudo-C emitter
```

x86-64 has the full pipeline. AArch64 covers most of the
integer/branch/load-store surface with shape-only FP/SIMD lifted as
named intrinsics. PPC64 covers loading, metadata, disasm, and CFG.

## Coverage matrix

| Area | x86-64 ELF | x86-64 Mach-O | x86-64 PE / minidump | AArch64 ELF / Mach-O | PPC64 ELF |
|---|---|---|---|---|---|
| Loader            | ✅          | ✅          | ✅ + dumps  | ✅          | ✅ |
| Decoder + IR lift | ✅          | ✅          | ✅          | partial     | partial |
| SSA + cleanup     | ✅          | ✅          | ✅          | partial     | — |
| Pseudo-C output   | ✅          | ✅          | ✅          | partial     | — |
| ABI modeling      | SysV        | SysV        | Win64       | AAPCS64     | ELFv1/v2 |
| Imports/exports   | PLT/GOT     | LC dyld     | IAT + delay | PLT/LC dyld | — |
| Symbols recovery  | dynsym      | LC_SYMTAB   | export dir + PDATA + PDB | dynsym / LC_SYMTAB | dynsym |
| Unwind info       | eh_frame    | LSDA pads   | UNWIND_INFO | eh_frame    | — |
| RTTI              | Itanium     | Itanium     | MSVC        | Itanium     | — |
| Demangle          | Itanium     | Itanium     | MSVC partial | Itanium    | — |
| Indirect calls    | IAT + vtable\* | IAT + vtable\* | IAT + vtable\* | vtable\*  | — |
| Switch idioms     | 5 patterns  | 5 patterns  | 5 patterns (incl. MSVC two-table) | inherits the analyzer | — |

<sub>* `--resolve-calls` is opt-in; fires on constant vtables today.
Receiver-typed dispatch is gated on the IPA work in progress.</sub>

## Windows runtime images

For packed / protected targets where the on-disk PE is a stub, point
ember at a runtime memory image instead:

```sh
# A Microsoft minidump (.dmp). procdump, taskmgr, WinDbg can produce these.
ember -p ./crash.dmp

# A hand-rolled scrape: manifest of (vaddr, size, flags, file) lines
# pointing at .bin region dumps.
ember --regions ./scrape/regions.txt -p
```

The minidump loader pulls per-module symbols from each module's
in-memory PE headers, so imports and exports get named even when the
on-disk image was junk. Module-name collisions get prefixed:
`kernel32!CreateFileA`.

## Runtime indirect-call traces

For callbacks, JIT glue, VM dispatch, and C++ calls where the static
shape does not bottom out at an IAT slot or constant vtable, feed Ember
observed indirect edges:

```sh
ember --trace edges.tsv --resolve-calls -p -s call_fp ./target
```

`edges.tsv` is tab-separated `from_va  to_va`, where `from_va` is the
indirect call instruction and `to_va` is an observed target. Trace edges
are used by CFG recovery and by pseudo-C emission. A traced
function-pointer wrapper such as:

```c
int call_fp(int (*fn)(int), int x) {
    return fn(x) + 1;
}
```

renders as:

```c
u32 call_fp(u32 (*fn)(u32), u32 x) {
  return plus7(x) /* observed targets: plus7, minus3 */ + 1;
}
```

The first observed target names the expression; additional observed
targets stay attached as a compact comment so the dynamic evidence is
not lost.

## Library function recognition (TEEF Max)

`ember --recognize --corpus libcrypto.tsv --corpus libssl.tsv <binary>`
identifies named library functions in stripped / unknown targets,
even across compiler-version drift, optimization-level changes, and
gcc ↔ clang. Three signals stacked, recognizer picks the first that
crosses confidence threshold:

- **L0 topology hash** — CFG-shape pre-filter. Cheap (~5 µs/fn).
- **L2 cleanup-canonical** — original TEEF: hash of the post-cleanup
  IR token stream + 8-slot MinHash for partial overlap.
- **L4 behavioural** — run K=64 random inputs through an abstract IR
  interpreter, hash the I/O multiset. Loop-shape invariant by
  construction. Catches what L2 can't: pointer-vs-index lowering,
  intrinsic-vs-open-coded (bswap, popcnt, …), induction-variable
  strength reduction, gcc-vs-clang divergence.

```sh
ember --teef libcrypto.so.3 > libcrypto.tsv     # build a corpus
ember --recognize --corpus libcrypto.tsv ./target

# Big libraries: the load is mmap'd and parallel-parsed, the recognize
# scan uses an L2 MinHash inverted index — multi-100MB corpora load in
# ~1 s and scan in seconds, not minutes.
```

Output: TSV rows of `addr  current_name  suggested_name  confidence
via  [alts]`. `via` distinguishes paths: `behav-exact` (L4 collision,
highest precision), `whole-exact`, `whole-jaccard+behav`, `chunk-vote+
behav`, etc.

100% precision, 34.4% recall on the cross-config probe2 matrix
(6 compiler configs × 30 algorithms, 30 directed pairs). Real
cross-binary tests (sha256sum corpus → md5sum) recover all named
gnulib helpers at confidence 1.0; FP rate 0.

Tuning knobs for huge / obfuscated targets:

```sh
ember --recognize --min-fn-size 32 --corpus ... <binary>   # drop tiny stubs
ember --recognize --l0-prefilter --corpus ... <binary>     # skip L4 on
                                                           # off-topology fns
```

Full surface in [docs/teef.md](docs/teef.md).

## Scripting

`.ember` is a declarative section-keyed file consumed by `--apply`.
No expressions, no control flow — every line is a single
`key = value` (or `pattern -> template`) pair. Drives bulk renames,
signature batches, log-format-string-to-rename inference, and pattern
globs over the discovered function set, all into the same
`Annotations` file emit reads back at decompile time.

```sh
ember --apply project.ember <binary>            # writes through to annotations
ember --apply project.ember --dry-run <binary>  # preview as TSV on stdout
```

```ember
[rename]
0x401234 = do_thing
log_handler = handle_log_line

[signature]
0x401234 = int do_thing(char* name, int x)

[from-strings]
"[HttpClient] %s" -> HttpClient_$1
```

Full surface in [docs/scripting.md](docs/scripting.md).

## Agent harness

`agent/` is a TypeScript multi-agent harness that drives LLMs against
the ember CLI to do reverse-engineering work in parallel. Workers run a
single role (namer / mapper / typer / tiebreaker) as an LLM tool-use
loop, write claims into a shared per-binary intel database (append-only
JSONL with retraction + dispute detection), and the orchestrator —
typically you talking through assistant Code or any other agent runtime —
fans them out, resolves disputes, and promotes high-confidence claims
into the same `.ember` annotation file that drives pseudo-C emit.

```sh
# Spawn 20 namer workers backgrounded against a stripped binary:
ember-agent fanout --binary=./target.elf --pick=unnamed --limit=20 \
  --budget=0.04 --model=deepseek/deepseek-v4-flash

# Or run Anchor Cascade — iterative bottom-up naming. Each round
# names fns whose callees are mostly anchored, promotes ≥0.85 conf
# claims, and re-renders pseudo-C so the next round sees richer
# context. Provably better than single-pass: information per prompt
# strictly increases per round.
ember-agent cascade --binary=./target.elf --per-round=30 --max-rounds=5

# Read what the swarm decided:
ember-agent intel ./target.elf disputes
ember-agent intel ./target.elf query --subject=0x4012a0 --predicate=name

# Fold ≥0.85-confidence claims into a .ember script and apply it:
ember-agent promote ./target.elf --apply
# Now `ember -p` shows the agent-supplied names.
```

Provider-neutral over assistant SDK / OpenAI / OpenRouter, with
prompt-cache pricing surfaced for both assistant-direct
(`cache_control: ephemeral`) and DeepSeek-via-OpenRouter (auto-prefix
caching reported in `usage.prompt_tokens_details.cached_tokens`).
Pinned upstream provider routing on OpenRouter for response
determinism. Per-worker USD budget cap. Disputes — top-2 claims within
0.10 confidence from different agents with different values — surface
for unbiased tiebreaker resolution.

End-to-end demo on a stripped fixture: 6 deepseek-v4-pro workers in
parallel produced `u32_mod` (conf 0.98), `call_gmon_start` (conf 0.90),
`u32_array_sum_nonzero` (conf 0.88), correctly declined to name
byte-identical twin functions, hit 89% prompt-cache, total spend $0.04.
Loop closes: those names now appear in `ember -p` output.

Full surface in [docs/agent.md](docs/agent.md).

## Plugin platform

A plugin ecosystem aimed at target-specific reversing — games, engines,
protocols, build-to-build knowledge carryover — is layered onto the
Electron UI, not the C++ core. Plugins are `.cjs` bundles (`plugin.json`
+ `main.cjs`) loaded by the renderer's Node runtime; the core surface
they consume is the same `Annotations` API the `.ember` format drives.
Design in [docs/plugin-platform.md](docs/plugin-platform.md).

## Layout

```
core/             C++23 library — everything except the CLI shim
  include/ember/  public headers
  src/
    binary/       ELF + Mach-O + PE + minidump + raw-regions + PDB v7
    disasm/       x86-64 + AArch64 + PPC64 instruction decoders
    analysis/     CFG, arity, strings, xrefs, sig inference (IPA),
                  type inference, indirect-call resolver, MSVC + Itanium
                  RTTI, eh_frame, PE UNWIND_INFO, ObjC, fingerprints,
                  syscall site walker
    ir/           IR + lifters + SSA + cleanup passes + type lattice
    structure/    region builder (if/while/for/switch/goto)
    decompile/    pseudo-C emitter
    debug/        ptrace (Linux) / Mach (macOS) backends, .eh_frame
                  + RBP-walk unwinders
    script/       declarative .ember parser + applier
    common/       annotations, on-disk cache
cli/              command-line driver
ui/               Electron + React + TypeScript frontend
agent/            TypeScript multi-agent LLM harness — fanout, intel db,
                  promote into .ember, provider-neutral over assistant /
                  OpenAI / OpenRouter (DeepSeek default)
tests/            golden-output CTest suite
docs/             scripting, debugger, vm-detect, raw-input, plugin
                  platform, agent harness, TEEF Max
```

## Tests

```sh
cmake --build build -j
ctest --test-dir build
```

Fixtures are small C programs compiled at build time plus hand-built
ELF / Mach-O / PE / minidump generators in `tests/fixtures/`, so CI
runs on Linux without macOS / Windows toolchains. Output diffs against
checked-in goldens in `tests/golden/`. Accept an intentional change:

```sh
UPDATE_GOLDEN=1 ctest --test-dir build -V
```

CI runs in a `gcc:15` container so goldens are toolchain-stable.

## Status

Active. The pipeline is solid enough to beat hand-reading x86-64 on
real binaries; pseudo-C output is generally readable and improves
visibly with `--ipa --resolve-calls --eh` on. Known rough edges:

- Indirect calls without IAT or constant-vtable shape need either
  `--trace` observations or stronger receiver-type facts. Trace-fed
  callbacks render with named targets, recovered arity, function-pointer
  parameter types, narrowed integer widths, and multi-target comments.
  Static receiver-typed dispatch is gated on the IPA work in progress.
- Sub-register arithmetic corners can still look clunky after the
  cast-simplification pass.
- Switch cases whose default falls outside the bounds check can
  misattribute.
- AArch64 floating-point and Advanced SIMD are decoded shape-only and
  lift as `arm64.<op>(...)` intrinsics. SVE / SME unmapped.

## Star history

<a href="https://star-history.com/#FlavouredTux/Ember&Date">
  <img src="https://api.star-history.com/svg?repos=FlavouredTux/Ember&type=Date" alt="Star history">
</a>

## License

MIT. See [LICENSE](LICENSE).
