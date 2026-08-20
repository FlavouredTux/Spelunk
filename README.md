# Ember

Ember is a small reverse-engineering toolkit for loading binaries, lifting
machine code into its own IR, and rendering a pseudo-C view without relying on
LLVM, Capstone, Zydis, SLEIGH, or debug info.

<table>
<tr>
<td width="50%" valign="top">

**`gotos.c`** - original source

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

</td>
<td width="50%" valign="top">

**`ember -p -s multi_exit gotos`** - recovered from a stripped binary

```c
uint64_t multi_exit(uint64_t a1, uint64_t a2) {
  if (!a1) return -1;
  if (!a2) return -1;
  uint64_t r_strlen   = strlen(a1);
  uint64_t r_strlen_2 = strlen(a2);
  if (r_strlen != r_strlen_2) return -1;
  return 0;
}
```

</td>
</tr>
</table>

<sub>The recovered output comes from the stripped executable. Ember builds SSA,
collapses the shared failure block into early returns, forwards spilled
parameters, and prints the signed constant even though the storage slot is
represented as <code>uint64_t</code>.</sub>

---

## Design

Ember keeps the analysis stack local to the project:

- Custom x86-64 decoder, with AArch64, PPC32, and PPC64 decoders in tree.
- Custom IR, SSA construction, cleanup passes, structurer, and pseudo-C emitter.
- No vendored runtime dependencies; the C++ core builds against the standard library.
- The debugger uses Ember's own pseudo-C line map instead of source or DWARF.
- Unresolved analysis stays explicit, for example
  `(*(uint64_t (**)(...))0x...)(...) /* unresolved indirect: ... */`.

The goal is to keep the pipeline inspectable and easy to change.

---

## Pipeline

```
binary → loader → decoder → CFG → IR lift → SSA → cleanup → structure → pseudo-C
```

The loader handles ELF, DOL, Wii REL, Mach-O, PE, Microsoft minidump, and raw-region
scrapes from packed targets. Cleanup includes constant folding, copy
propagation, GVN, store-to-load forwarding, dead-store elimination, and a small
type lattice that propagates through phis. The structurer recovers `if`,
`while`, `for`, and `switch`, falling back to `goto` when the control flow is
not clean enough to structure.

DTK projects can select either the main DOL or one of their configured RELs:

```sh
ember --dtk ./spm --version EU0 --dtk-module relF -d -s func_80c458fc
```

Selecting a REL also loads the configured main DOL as its symbol oracle and
maps peer REL modules into a shared link context. Module IDs and
section-relative relocation targets are resolved automatically, so cross-REL
calls and globals use names from the peer symbol maps instead of raw
`rel<ID>_s<section>_<offset>` coordinates.

For source-oriented Wii recovery, Ember can overlay project headers through
libclang. Imported prototypes feed PPC ABI argument recovery, record layouts
name direct parameter fields, and typed data/event commands reuse the same
symbols and loader relocations:

```sh
# Header-aware pseudo-C (repeat --headers or --header-arg as needed).
ember --headers ./spm-headers/include \
  --header-arg=-I./spm-headers/decomp \
  --dtk ./spm --version EU0 -p -s seq_mapChangeMain

# Batch a symbol manifest while loading the DOL, symbols, and headers once.
ember --headers ./spm-headers/include --dtk ./spm --version EU0 \
  -p --symbols benchmarks/spm_eu0_ppc.txt

# Relocation-aware C initializers and SPM event macros.
ember --headers ./spm-headers/include --dtk ./spm --version EU0 \
  --decompile-data mapData --type 'MapData *[468]' --verify-roundtrip
ember --dtk ./spm --version EU0 --evt-script lbl_80415e04 \
  --verify-roundtrip
```

`--decompile-data` understands primitive/pointer/record/array types. It uses
applied DOL/REL relocation evidence before raw pointer words, resolves named
objects and callbacks, renders printable character pointers as strings, and
recurses through nested records. Arrays of record pointers are followed
automatically and emitted as typed compound initializers. `--evt-script`
validates each encoded opcode
and argument count, reconstructs IF/SWITCH/DO/inline nesting, decodes SPM
variable encodings such as `LW(0)`, and resolves user-function/script pointers.
`--verify-roundtrip` re-encodes scalar literals, record layouts, pointer slots,
event opcodes, arguments, and relocation-backed symbols, then fails if they do
not reproduce the loaded representation.

PowerPC pseudo-C recovery models the integer and floating-point argument
registers as independent ABI lanes. Mixed calls are interleaved from callee-use
evidence or an explicit signature instead of treating every argument as a GPR.
Known scalar floating-point returns are recovered from `f1`, including common
Wii SDK `PSVEC*`, MTX, GX, OS, DVD, controller, and CX routines; unknown calls
stay conservative rather than treating every post-call FPR clobber as a result.
Untyped `func_*`/`sub_*` calls carry an address and inferred PPC signature hint
so unresolved names remain explicit without hiding recovered call information.

Ember's pseudo-C is reverse-engineering guidance, not a promise of the original
CodeWarrior source. Exact byte matching still requires objdiff-led iteration on
source structure, declaration order, stack placement, expression spelling, and
other compiler-sensitive details.
`scripts/ppc_match_loop.py` automates that final iteration for controlled source
alternatives. It reuses the unit's exact Ninja/CodeWarrior command, compiles
every candidate outside the decompilation checkout, ranks the requested
function through objdiff's one-shot JSON diff, and preserves `best.c`, `best.o`,
`best.objdiff.json`, and a reproducible result manifest without editing the
original source.
Its `--auto` mode scopes discovery to the requested function, generates only
conservative side-effect-free comparison, declaration, increment, boolean and
compound-assignment spellings, then uses a bounded objdiff-guided beam to keep
the closest CodeWarrior candidates.
`scripts/ppc_decompile_unit.py` recovers every function owned by an objdiff
unit in retail-object order, preserves the existing source preamble and
includes, isolates inferred PPC record names between functions, and writes a
separate translation-unit candidate without modifying the project source.
With `--verify`, it compiles that candidate through the unit's exact
Ninja/CodeWarrior command and emits whole-object function/data evidence plus an
`ember-match` queue for anything still nonmatching.
See [PowerPC decompilation](docs/powerpc.md) for the supported ABIs, recovery
rules, annotation workflow, binary-only limits, the `--ppc-coverage`
decoder/semantic-gap report, project-scale exact-matching expectations, and the
repeatable SPM pseudo-C quality benchmark.

---

## Features

### Pseudo-C debugger

```sh
ember --debug ./target
(ember-dbg) b sub_4000b0:42
```

The breakpoint resolves through Ember's generated pseudo-C line map. The line
does not need to exist in a source file. Linux uses ptrace; macOS uses Mach.
`code` shows the pseudo-C around the current PC, `bt` walks `.eh_frame` with an
RBP fallback, and `aux` side-loads another binary as a symbol source for
runtime-mapped Mach-O or PE blobs.

### Cross-binary function recognition

```sh
ember --teef libcrypto.so.3 > corpus.tsv
ember --recognize --corpus corpus.tsv ./stripped-target
```

Function matching combines a CFG-shape pre-filter, a post-cleanup IR canonical
with MinHash for partial overlap, and a behavioural signature. The behavioural
pass runs 64 random inputs through an abstract IR interpreter and hashes the
input/output multiset, which helps with compiler differences such as
pointer-vs-index lowering, open-coded intrinsics, and induction-variable
strength reduction.

> **100% precision, 34.4% recall** on the cross-config probe2 matrix
> (6 compiler configurations × 30 algorithms, 30 directed pairs).
> Real cross-binary: `sha256sum` corpus → `md5sum` recovers every named
> gnulib helper at confidence 1.0, zero false positives.

### Runtime evidence

When static analysis cannot resolve an indirect call, pass Ember a TSV of
observed edges. The same wrapper without and with `--trace`:

```c
// ember -p -s call_fp ./target
uint32_t call_fp(uint32_t (*fn)(uint32_t), uint32_t x) {
  return (*(uint64_t (**)(uint32_t))0x602010)(x) /* unresolved indirect: fnptr slot @ 0x602010 */ + 1;
}

// ember -p -s call_fp --trace edges.tsv ./target
uint32_t call_fp(uint32_t (*fn)(uint32_t), uint32_t x) {
  return plus7(x) /* observed targets: plus7, minus3 */ + 1;
}
```

The first observed target names the expression; the other observed targets stay
attached as a comment.

---

## Support matrix

|                       | x86-64                | AArch64           | PPC32 / PPC64 |
|---                    |---                    |---                |---            |
| Loader                | ELF / Mach-O / PE / minidump / regions | ELF / Mach-O | ELF32 / ELF64 / PPC32 `.o` / DOL / Wii REL |
| Decoder + IR lift     | full                  | partial           | partial       |
| SSA + cleanup         | full                  | partial           | partial       |
| Pseudo-C              | full                  | partial           | partial       |
| ABI                   | SysV / Win64          | AAPCS64           | SysV / ELFv1 / v2 |
| RTTI                  | Itanium + MSVC        | Itanium           | -           |
| Switch idioms         | 5 patterns (incl. MSVC two-table) | inherited | - |
| Indirect calls        | IAT + const vtable + trace + IPA receiver-type | inherited | CTR constants + trace |

---

## Limitations

Known limits:

- Indirect calls without IAT, constant vtable, trace observation, or
  receiver-type evidence still render as typed unresolved function-pointer-slot
  calls with an evidence comment.
- Switch cases whose default falls outside the bounds check can misattribute.
- AArch64 floating-point and Advanced SIMD are decoded shape-only and lift as `arm64.<op>(...)` intrinsics. SVE / SME unmapped.
- PPC32/PPC64 lifting is intentionally small: scalar GPR/control-flow basics,
  DOL, Wii REL, and relocatable PPC32 ELF function discovery, core PPC32
  relocations, and code-pointer xrefs. DTK project mode resolves configured
  REL-to-REL and `main.dol` references; a standalone REL keeps unavailable
  peer-module references explicit. Scalar mixed GPR/FPR and ordinary aligned
  stack-passed arguments are recovered. Signature-backed Wii aggregates model
  consecutive GPR words and hidden structure-return pointers, while unknown
  binary-only aggregate sizes remain conservative. See
  [docs/powerpc.md](docs/powerpc.md).
- Itanium demangle is comprehensive; MSVC demangle is partial.
- C++ stdlib name simplification (`std::__cxx11::basic_string<…>` → `std::string`, `std::vector<T, std::allocator<T>>` → `std::vector<T>`) is balanced-template aware while preserving custom allocators.

---

<details>
<summary><b>Build &amp; run</b></summary>

C++23 (gcc 16+ or recent Clang) and CMake 3.28+:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/cli/ember --help
```

Python wrapper:

```sh
python -m pip install -e .
```

```python
from emberpy import Ember

e = Ember("tests/fixtures/gotos")
fn = e.function("multi_exit")
print(fn.pseudo())
print(e.functions())
```

The wrapper shells out to the ember CLI. Pass `ember_bin="path/to/ember"`
or set `EMBER_BIN` when the executable is not on `PATH` or under
`./build/cli/ember`. Full surface in [docs/python.md](docs/python.md).

</details>

<details>
<summary><b>CLI surface</b></summary>

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
      --identify         YARA-like crypto/protocol fingerprint scan
      --validate NAME    where does NAME live + similar lookalikes
      --collisions       names / fingerprints bound to >1 address
      --vtables          runtime pointer-dense vtables from data/RELRO
      --vtable-at VA     narrow vtable view around a vptr/typeinfo/slot VA

      --ipa              run IPA before pseudo-C (typed sigs across calls)
      --resolve-calls    resolve indirect calls (IAT + constant vtables)
      --eh               parse unwind tables, mark landing pads
      --list-syscalls VA report each `syscall` site in the function at VA
      --debug            launch / attach a debugger; see docs/debugger.md

  -s, --symbol NAME      target a specific symbol (default: main)
      --symbols FILE     batch one-symbol-per-line views with one project load
      --annotations P    user renames / signatures sidecar file
      --apply PATH       apply a .ember declarative script
      --annotate ADDR    one-shot: append a single rename / note / signature
                         to the resolved annotations file. Pair with
                         --set-name / --set-note / --set-signature, plus
                         optional --confidence / --evidence / --source.
      --show-provenance  -p only: emit `// confidence: …` lines under
                         function headers when annotations carry metadata
      --dry-run          with --apply / --annotate: don't write; dump TSV
      --regions PATH     load via raw-region manifest (Scylla-style scrape)
      --raw-bytes PATH   load one raw memory range at --base-va
      --base-va 0xVA     base address for --raw-bytes
      --apply-patches F  apply (vaddr_hex, bytes_hex) patches to the binary
      --trace PATH       runtime facts: edges, qwords, objects, vptrs
      --refs-to-loose VA find direct refs plus pointer slots to VA
      --explain-vcall OBJ:OFF  resolve *( *(OBJ) + OFF )
      --dump-object ADDR --size N  classify object qwords
      --cache-dir DIR    override ~/.cache/ember
      --no-cache         bypass the on-disk cache
```

Heavyweight passes (`--xrefs`, `--strings`, `--arities`, `--fingerprints`) cache to `~/.cache/ember/` keyed on `path | size | mtime | version`. First run is slow; subsequent runs are instant.

</details>

<details>
<summary><b>Runtime Memory Images</b></summary>

For packed / protected targets where the on-disk file is a stub or an
unrelocated view, point ember at runtime memory instead:

```sh
# Microsoft minidump (procdump, taskmgr, WinDbg can produce these)
ember -p ./crash.dmp

# Hand-rolled scrape: manifest of (vaddr, size, flags, file) lines
ember --regions ./scrape/regions.txt -p

# Loaded Android / PIE dump: find RELRO vtables and explain one dispatch slot
ember --regions ./scrape/regions.txt --vtables
ember --regions ./scrape/regions.txt --vtable-at 0xVTABLE_OR_SLOT --limit 24
ember --regions ./scrape/regions.txt --explain-vcall 0xOBJECT:0x40

# Snapshot an object as pointer-sized fields
ember --regions ./scrape/regions.txt --dump-object 0xOBJECT --size 0x100
```

The minidump loader pulls per-module symbols from each module's in-memory PE headers, so imports and exports are named even when the on-disk image was junk. Module-name collisions get prefixed: `kernel32!CreateFileA`.

Raw-region loaded dumps are treated as runtime memory: `--data-xrefs`
indexes relocated pointer slots, `--refs-to-loose` accepts module-relative
offsets by trying `lowest_region_base + offset`, and `--trace` can overlay
runtime facts such as `qword ADDR VALUE`, `object ADDR VTABLE`, and
`indirect CALLSITE TARGET`.

</details>

<details>
<summary><b>Scripting (<code>.ember</code>)</b></summary>

```ember
[rename]
0x401234     = do_thing
log_handler  = handle_log_line

[signature]
0x401234 = int do_thing(char* name, int x)

[field]
do_thing:name+0x10 = length        # name struct fields scoped to a parameter
do_thing:a1+0x18   = flags         # by ABI slot when no signature param exists

[from-strings]
"[HttpClient] %s" -> HttpClient_$1

[pattern-rename]
sub_4* -> sample_sub_*

[delete]
log_handler = all                  # drop rename + note + signature
```

Section-keyed, one directive per line, no expressions or control flow. Anything that needs decisions (walk callees, drive renames from CFG shape) consumes the public `Annotations` API from a one-off C++ tool linked against `ember::core`. Full surface in [docs/scripting.md](docs/scripting.md).

</details>

<details>
<summary><b>Layout</b></summary>

```
core/             C++23 library - everything except the CLI shim
  binary/         ELF + DOL + Mach-O + PE + minidump + raw-regions + PDB v7
  disasm/         x86-64 + AArch64 + PPC32/PPC64 instruction decoders
  analysis/       CFG, arity, strings, xrefs, sig inference, type inference,
                  indirect-call resolver, MSVC + Itanium RTTI, eh_frame,
                  PE UNWIND_INFO, ObjC, fingerprints, name resolver,
                  syscall sites, YARA-like identification
  ir/             IR + lifters + SSA + cleanup passes + type lattice
  structure/      region builder
  decompile/      pseudo-C emitter
  debug/          ptrace + perf + Mach backends, .eh_frame + RBP-walk unwinders
  script/         declarative .ember parser + applier
  common/         annotations, on-disk cache
cli/              command-line driver
tests/            golden-output CTest suite
docs/             Python wrapper, scripting, debugger, raw-input,
                  TEEF Max
```

</details>

<details>
<summary><b>Tests</b></summary>

```sh
ctest --test-dir build
```

Goldens live in `tests/golden/`. Accept an intentional shift in the same commit as the behaviour change:

```sh
UPDATE_GOLDEN=1 ctest --test-dir build -V
```

CI runs in a `gcc:16` container so layout / signature output stays toolchain-stable. A separate Apple Clang + libc++ job builds `core/` (the CLI is gcc-only because it leans on `<print>`).

</details>

---

<p align="center">
  <img src="docs/mascot.png" alt="Ember" width="160">
</p>

<p align="center">
  <a href="https://github.com/FlavouredTux/Ember/actions/workflows/ci.yml">
    <img src="https://github.com/FlavouredTux/Ember/actions/workflows/ci.yml/badge.svg?branch=main" alt="ci">
  </a>
  <a href="https://github.com/FlavouredTux/Ember/stargazers">
    <img src="https://img.shields.io/github/stars/FlavouredTux/Ember?style=flat&color=yellow" alt="stars">
  </a>
  <img src="https://img.shields.io/badge/C%2B%2B-23-blue.svg" alt="C++23">
  <img src="https://img.shields.io/badge/deps-stdlib--only-success.svg" alt="stdlib only">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT">
</p>

<p align="center"><sub>MIT - see <a href="LICENSE">LICENSE</a>. Star history at <a href="https://star-history.com/#FlavouredTux/Ember&Date">star-history.com</a>.</sub></p>
