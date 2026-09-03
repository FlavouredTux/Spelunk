# Ember agent operating manual

This is the project-level reference for agents and people using Ember. It was
checked against the CLI and repository documentation on 2026-08-20. When this
file and the executable disagree, `ember --help <topic>` is authoritative.

Ember is a local, from-scratch reverse-engineering toolkit. It loads binaries,
discovers functions, builds a CFG, lifts instructions into its IR, constructs
SSA, runs cleanup and type recovery, structures control flow, and emits
pseudo-C:

```text
binary -> loader -> decoder -> CFG -> IR -> SSA -> cleanup -> structure -> pseudo-C
```

It does not depend on LLVM, Capstone, Zydis, SLEIGH, or debug information. The
core supports ELF, DOL, Wii REL, Mach-O, PE, Microsoft minidumps, relocatable
PowerPC ELF objects, and raw memory regions. Instruction support includes
x86-64 plus partial AArch64, PPC32, and PPC64 pipelines.

## Operating rules

- Start with the cheapest targeted query that answers the question.
- Prefer a symbol, address, string, xref, or DTK unit over a whole-binary pass.
- Batch symbols with `--symbols FILE`; do not launch Ember once per function.
- Reuse cached evidence unless the binary, project, headers, or question changed.
- Keep uncertainty explicit. A plausible name or type is not a verified fact.
- Treat pseudo-C as reverse-engineering guidance, not recovered original source.
- Never call a CodeWarrior result matching unless objdiff reports exact equality.
- Do not modify a target binary or decompilation checkout during diagnosis.
- Use `--apply-patches` only when binary patching was explicitly requested.
- Use isolated output directories for generated candidates and matching evidence.
- Preserve project-local annotations, headers, source WIP, and compiler settings.

Approximate cost model:

| Cheap and broad | Targeted | Deliberately expensive |
|---|---|---|
| `--functions`, `--strings`, `--containing-fn`, `--validate`, `--explain-address` | `-p -s`, `-d -s`, `--refs-to`, `--callees`, `--disasm-window` | `--full-analysis`, `--ipa`, `--resolve-calls`, `--eh`, whole-binary sweeps |

## First-contact workflow

Use this sequence for an unfamiliar binary:

1. Inventory the container and functions.
2. Anchor on a symbol, string, import, known address, or runtime observation.
3. Read the smallest relevant function in pseudo-C and disassembly.
4. Expand through callers, callees, data xrefs, or state use.
5. Persist only evidence-backed names, signatures, fields, constants, and notes.

```sh
ember ./target
ember --functions ./target
ember --strings ./target
ember --identify ./target

ember --refs-to 0x401000 ./target
ember --containing-fn 0x402034 ./target
ember -p -s sub_402000 ./target
ember -d -s sub_402000 ./target
ember --callees 0x402000 ./target
```

Add `--json` when a command supports it and another tool will consume the
result. Use `--row-limit N` to bound broad inventory output.

## Current CLI map

The view pipeline is cumulative. `-p` runs all earlier analysis stages:

```sh
ember -d -s NAME ./target       # disassembly
ember -c -s NAME ./target       # assembly CFG
ember --cfg-pseudo -s NAME ./target
ember -i -s NAME ./target       # lifted IR
ember --ssa -s NAME ./target
ember -O -s NAME ./target       # cleaned SSA
ember --struct -s NAME ./target
ember -p -s NAME ./target       # pseudo-C
```

For complete option descriptions, use:

```sh
ember --help view
ember --help syms
ember --help xrefs
ember --help ana
ember --help teef
ember --help ann
ember --help dbg
ember --help load
ember --help data
ember --help patch
ember --help cache
```

### Symbols and local orientation

```sh
ember --functions ./target
ember --functions=filter ./target
ember --strings ./target
ember --collisions ./target
ember --validate NAME ./target
ember --containing-fn 0xVA ./target
ember --explain-address 0xVA ./target
```

Useful relationship queries:

```sh
ember --xrefs ./target
ember --data-xrefs ./target
ember --refs-to 0xVA ./target
ember --refs-to FN ./target
ember --refs-to-loose 0xVA ./target
ember --callees 0xVA ./target
ember --state-map 0xVA ./target
ember --branch-on 0xVA ./target
ember --guard-map 0xFN ./target
ember --state-lifetime 0xVA ./target
ember --side-effects 0xFN ./target
ember --object-roles 0xFN ./target
```

`--refs-to` reports direct calls and ordinary code/data references. It accepts
a symbol name or a VA, matching the `--side-effects FN` / `--guard-map FN`
form.
`--refs-to-loose` additionally scans literal pointer slots and relocation
evidence; use it for callback tables and address-taken functions. Add
`--access read|write|lea|code-ptr|all` where supported and `--verbose` when the
site disassembly matters.

### Bounded instruction inspection

Use bounded windows instead of decompiling an entire large function when the
question concerns one site:

```sh
ember --disasm-at 0xVA --count 24 ./target
ember --disasm-at 0xVA --count 24 --json ./target
ember --disasm-window 0xVA1,0xVA2 --count 16 ./target
ember --disasm-window @addresses.txt --count 16 --json ./target
```

The JSON form includes instruction bytes, operands, branch targets,
RIP-relative targets, and trampoline hazards. `--patch-plan 0xVA` summarizes
safe steal length and relocation requirements; it is evidence, not permission
to patch.

### C++, Objective-C, and runtime objects

```sh
ember --rtti ./target
ember --vtables ./target
ember --vtable-at 0xVA --limit 24 ./target
ember --callees-class ClassName ./target
ember --explain-vcall 0xOBJECT:0xSLOT ./target
ember --dump-object 0xOBJECT --size 0x100 ./target

ember --objc-names ./target
ember --objc-protocols ./target
ember --objc-surfaces ./target
```

Runtime evidence can augment static analysis:

```text
from_va to_va
indirect callsite_va target_va
qword address value
object address vtable
```

```sh
ember -p -s NAME --trace runtime-facts.tsv ./target
```

Observed facts constrain unresolved indirect calls and loaded objects; they do
not prove that an unobserved target is impossible.

### Recognition and cross-binary comparison

```sh
ember --fingerprints ./library > fingerprints.tsv
ember --teef ./library > corpus.tsv
ember --recognize --corpus corpus.tsv ./stripped-target
ember --identify ./target
ember --diff ./old-target ./new-target
```

TEEF combines CFG shape, cleaned IR similarity, and an optional behavioral
signature. Filter corpus work with `--min-fn-size`, `--max-fn-size`, CFG/IR
caps, or `--teef-no-l4` when scale requires it. A high fuzzy score is useful
evidence, but only a unique exact identity should be described as exact.

See [docs/teef.md](docs/teef.md) for corpus fields, confidence, size caps, and
recognition behavior.

### Raw captures and minidumps

```sh
ember --raw-bytes code.bin --base-va 0x180000000 -p -s 0x180001000
ember --regions regions.txt --functions
ember --regions regions.txt --vtables
ember --regions regions.txt --recover-imports \
  --dll-dir /path/to/System32 --image-base 0x140000000 --json
```

Raw inputs do not provide container symbols, imports, unwind ranges, or
relocations unless they are reconstructed or supplied separately. A region
manifest is documented in [docs/raw-input.md](docs/raw-input.md).

### Debugger

```sh
ember --debug ./target -- arg1 arg2
ember --debug --attach-pid PID ./target
ember --debug --debug-backend auto ./target
ember --debug --aux-binary helper.bin@0xBASE ./target
```

The debugger maps breakpoints to Ember's generated pseudo-C rather than DWARF
source. Linux uses ptrace or hardware perf breakpoints; macOS uses Mach. See
[docs/debugger.md](docs/debugger.md) before relying on attach, unwind, fault
forwarding, or auxiliary-binary behavior.

## PowerPC and Wii workflow

The Wii uses a 32-bit PowerPC CPU. For Wii work, prefer a DTK project over a
standalone DOL or REL because the project supplies exact symbols, function
sizes, module selection, peer-module relocations, and objdiff metadata.

```sh
ember --dtk /path/to/spm --dtk-version EU0 -p -s marioMain
ember --dtk /path/to/spm --dtk-version EU0 --dtk-module relF \
  -p -s func_80c458fc
```

Selecting a REL also loads the configured main DOL as a symbol oracle and maps
peer REL modules into a shared link context. Module IDs, section-relative
relocations, cross-REL calls, and cross-module globals can therefore resolve to
project names. A standalone REL cannot invent peer-module contents that were
not supplied and must leave those references explicit.

### PPC ABI recovery

PPC integer and floating-point arguments occupy independent lanes:

| ABI | Integer and pointer arguments | Floating-point arguments |
|---|---|---|
| PPC32 SysV / Wii | `r3` through `r10` | `f1` through `f8` |
| PPC64 ELFv1/v2 | `r3` through `r10` | `f1` through `f13` |

Ember merges the lanes from a known prototype or callee-use evidence. It also
recovers ordinary aligned stack arguments, signature-backed small aggregates,
known hidden structure-return pointers, and evidence-backed `r3`/`f1` return
values. Built-in prototypes cover common Wii SDK OS, DVD, GX, MTX, vector,
controller, and compression routines. Unknown aggregates and ambiguous
`float` versus `double` transport remain conservative.

Header import is the preferred way to replace ABI guesses with project facts:

```sh
ember --headers /path/to/spm/spm-headers/include \
  --header-arg=-I/path/to/spm/spm-headers/decomp \
  --dtk /path/to/spm --dtk-version EU0 -p -s seq_mapChangeMain
```

Repeat `--headers` and `--header-arg` as needed. Libclang imports prototypes,
records, fields, globals, arrays, and enums using PPC32 layouts. Public headers
take priority; sibling source prototypes and scoped interprocedural inference
can fill private gaps. Manual annotations remain authoritative.

Header-aware output emits compact declarations for the imported records and
array aliases it actually uses. With a conventional DTK/SPM header tree, the
matching linker list also supplies address-checked global aliases. Expect
`pausewin_wp->entries`, nested `Vec3` components, named aggregate locals,
`Mtx34` matrices, element-scaled pointer arithmetic, and `memcpy` for long
contiguous field-copy runs instead of raw labels and byte strides.

### PPC control flow and semantics

The PPC32 CFG recognizes bounded CodeWarrior `lwzx -> mtctr -> bctr` dispatch
and adds the table targets to recover a structured `switch`. Counted CTR loops
retain the decrement side effect. Common scalar and paired-single arithmetic,
`fctiwz` conversion, rotate/mask/merge, leading-zero count, multiword
load/store, and conventional unquantized paired-single memory operations are
lifted into readable dataflow. Quantized or ambiguous vector forms stay as
explicit `ppc.*` helpers rather than being guessed.

Pseudo-C merge recovery discards Phi webs that never reach an observable sink
and ignores packed call lanes outside the callee's recovered PPC ABI. Loop
induction values feeding Phis render as `++`/`--` updates, including updates
shared with the loop comparison. The common CodeWarrior
`xoris`/stack/`lfd`/bias-subtract idiom folds back into a signed integer-to-float
cast. Menu navigation tables with four neighbor bytes plus a callback slot are
emitted as typed `PpcNavigationEntry` arrays rather than raw scaled pointer
arithmetic.

Imported eight-byte fields let Ember rejoin big-endian high/low loads and
collapse `subfc`/`subfe` carry chains. The verified Wii clock/divide idiom is
rendered through `OSTicksToMilliseconds`, while masked-rotate byte scales feed
typed `object->array[index]` and `records[index].field` recovery. Wider
fixed-address strides receive compact `PpcDataEntry` declarations.

Measure a binary instead of assuming decoder/lifter coverage:

```sh
ember --dtk /path/to/spm --dtk-version EU0 \
  --ppc-coverage --coverage-limit 20
ember --dtk /path/to/spm --dtk-version EU0 \
  --ppc-coverage --coverage-limit 0 --json
```

The report separates hard decoder failures from decoded instructions that
still lift to opaque `ppc.*` operations. Executable sections may contain
embedded data, so inspect sample addresses before filing a decoder gap.

### Typed Wii data and SPM event scripts

```sh
ember --headers /path/to/spm/spm-headers/include \
  --dtk /path/to/spm --dtk-version EU0 \
  --decompile-data mapData --type 'MapData *[468]' \
  --verify-roundtrip

ember --dtk /path/to/spm --dtk-version EU0 \
  --evt-script lbl_80415e04 --verify-roundtrip
```

`--decompile-data` uses imported layouts and loader relocations to distinguish
named objects, callbacks, strings, nested records, and null pointers. Pointer
tables are followed with bounded recursion. `--evt-script` decodes SPM event
opcodes, argument counts, variable encodings, structured control regions, and
callback/script pointers.

Always use `--verify-roundtrip` when the result will become source. It checks
that decoded scalar values, layout, opcodes, pointer slots, and relocation-backed
symbols reproduce the loaded representation. Successful roundtrip verification
proves representation fidelity, not original identifier names or source layout.

### Batch pseudo-C and quality measurement

```sh
ember --headers /path/to/spm/spm-headers/include \
  --dtk /path/to/spm --dtk-version EU0 \
  -p --symbols benchmarks/spm_eu0_ppc.txt

python3 scripts/ppc_quality_benchmark.py \
  --ember ./build/cli/ember \
  --dtk /path/to/spm --dtk-version EU0 \
  --headers /path/to/spm/spm-headers/include \
  --syntax-check \
  --roundtrip-manifest benchmarks/spm_eu0_roundtrip.txt
```

The benchmark tracks unresolved registers/SSA values, temporaries, opaque PPC
operations, generic parameters/fields, unresolved calls, structurer failures,
constant conditions, event pointers, syntax failures, and optional timings.
Use the checked-in baseline with `--fail-on-regression` when changing PPC
analysis. Timing data is diagnostic and intentionally excluded from quality
pass/fail comparisons.

### Whole translation-unit recovery

`ember-unit` recovers the retail object's functions in object order, retains
the source preamble/includes, and writes a separate candidate file:

```sh
ember-unit \
  --project /path/to/spm \
  --unit main/mario_motion \
  --dtk-version EU0 \
  --headers /path/to/spm/spm-headers/include \
  --output /tmp/mario_motion.recovered.c \
  --strict
```

Add `--verify` to compile with the unit's exact Ninja/CodeWarrior command and
compare the candidate object through objdiff:

```sh
ember-unit \
  --project /path/to/spm \
  --unit main/mario_motion \
  --headers /path/to/spm/spm-headers/include \
  --output /tmp/mario_motion.recovered.c \
  --verify --verify-dir /tmp/mario_motion.evidence \
  --fail-unmatched
```

Verification retains the compile log, object, objdiff JSON, text/JSON summary,
and a matcher queue for nonmatching functions. The output path must remain
separate from the project's real source. `--strict` means recovery must cover
every object function; `--fail-unmatched` means every function and data object
must be exact.

### CodeWarrior matching loop

`ember-match` searches controlled source-equivalent spellings in isolation and
ranks the requested function through objdiff:

```sh
ember-match \
  --project /path/to/spm \
  --unit main/mario_motion \
  --symbol mot_22 \
  --auto \
  --output-dir /tmp/mot22-match \
  --jobs 4 --beam-width 8 --max-candidates 256 \
  --fail-unmatched
```

Automatic mode is deliberately conservative: it explores bounded forms such
as pure comparison direction, uninitialized declaration order, increments,
compound assignments, and boolean zero tests. For casts, initialized-local
order, control-flow layouts, or project-specific expression alternatives, use
a version-1 JSON spec:

```sh
ember-match --project /path/to/spm --unit main/mario_motion \
  --symbol mot_22 --spec variants.json \
  --output-dir /tmp/mot22-spec --jobs 4 --fail-unmatched
```

The source checkout is not rewritten. Results include `best.c`, `best.o`,
`best.objdiff.json`, `results.json`, and `summary.txt`. A high fuzzy score is
never a match. Only an exact objdiff result is 100%.

### Exact-matching boundary

Ember removes mechanical work, but optimized machine code cannot uniquely
identify the programmer's original source. Byte-for-byte CodeWarrior matching
still depends on control-flow spelling, expression shape, declaration order,
stack placement, temporary lifetime, casts, translation-unit layout, static
data, and compiler version/flags. Work one unit at a time and preserve exact
compiler and objdiff evidence.

The dated SPM project-scale measurements and their interpretation live in
[docs/powerpc.md](docs/powerpc.md). Objdiff auto-split units are bookkeeping
boundaries and must not be presented as an equal number of hand-written C
files.

## Annotations and source knowledge

Use a declarative `.ember` file for reusable facts:

```ember
[rename]
0x401234 = update_player ; conf=0.95 ; src=hand ; ev=unique log and callers

[signature]
0x401234 = int update_player(Player* player, float dt)

[field]
update_player:player+0x44 = currentMap

[constant]
0x40000 = PLAYER_FLAG_FLIPPED

[note]
0x401234 = state transition owner; verify case 9
```

Preview before writing:

```sh
ember --apply project.ember --dry-run --annotations project.annotations ./target
ember --apply project.ember --annotations project.annotations ./target
ember --list-annotations --annotations project.annotations ./target
ember -p --show-provenance --annotations project.annotations \
  -s update_player ./target
```

For a single fact:

```sh
ember --annotate 0x401234 --set-name update_player \
  --confidence 0.95 --source hand \
  --evidence 'unique log and callers' --dry-run ./target
```

Annotations can express renames, notes, signatures, parameter-scoped fields,
constants, pattern renames, string-derived renames, and deletions. Direct user
facts take priority over inference. See [docs/scripting.md](docs/scripting.md)
for exact syntax, escaping, provenance, storage, and conflict rules.

## Reading output correctly

- `sub_<address>` or `func_<address>` means no semantic name was proven.
- An unresolved indirect call is intentionally printed as a typed function
  pointer expression with its available evidence.
- `ppc.<op>(...)` means decoding succeeded but exact high-level semantics remain
  opaque or deliberately conservative.
- Generic `a1`, `field_XX`, `void*`, and synthetic record names are hypotheses
  shaped by ABI/dataflow evidence, not debug types.
- `STRUCTURER_FAIL`, explicit gotos, unresolved SSA merges, constant conditions,
  and uninitialized synthetic values require inspection before compiling output.
- `unresolved expression materialization` marks a depth-capped value whose
  dependency chain could not be rendered safely; its zero initializer prevents
  undefined C use but is not a recovered source value.
- A named call can come from a binary symbol, DTK symbol, relocation, import,
  header, annotation, recognition corpus, or runtime trace. Keep the provenance
  when that distinction affects confidence.
- Roundtrip data/event success is different from source compilation success.
- Compilation success is different from objdiff exactness.
- Function exactness is different from complete translation-unit code and data.

Confidence language:

| Level | Meaning |
|---|---|
| Verified | Direct binary/project evidence and the relevant mechanical check passed |
| High confidence | Multiple independent static facts agree; no contradiction found |
| Likely | Best interpretation of incomplete evidence |
| Unknown | Insufficient evidence; retain the address or generic type/name |

## Platform notes

- **x86-64 ELF:** SysV ABI, ELF relocations/imports, Itanium RTTI, and Linux
  syscall inspection are supported. XMM0–7 are tracked as floating/vector
  argument lanes and XMM0–15 as caller-clobbered state.
- **PE32+ x86-64:** Win64 ABI, regular/delay imports, exports, TLS callbacks,
  `.pdata`/UNWIND_INFO, PDB sidecars, MSVC RTTI/vtables, and DIR64 relocations
  feed discovery and pseudo-C. Its four positional XMM argument slots and
  XMM0–5 caller-clobber set are modeled separately from SysV.
- **Modern x86 vectors:** two- and three-byte VEX plus four-byte EVEX preserve
  non-destructive sources, XMM/YMM/ZMM widths, AVX-512 masks, zeroing, and
  broadcast metadata. Common map-`0F` AVX/AVX2 operations, map-`0F38`
  BMI/BMI2, FMA3, and `vzeroupper` lift to typed IR. Rare `0F3A`,
  gather/scatter, and full EVEX tuple/compressed-displacement semantics remain
  explicit coverage boundaries.
- **Mach-O:** thin/universal 64-bit slices, entry metadata, function starts,
  dyld bind/export/chained fixups, dSYM overlays, ObjC metadata/blocks, and basic
  Swift nominal descriptors are supported.
- **AArch64:** loading, decoding, IR, and pseudo-C are partial. Floating-point,
  Advanced SIMD, SVE, and SME coverage is not equivalent to x86-64.
- **PPC32/PPC64:** DOL, Wii REL, PPC ELF objects, DTK projects, core
  relocations, scalar/control-flow/FP, selected paired-single semantics, and
  source-oriented Wii workflows are supported but still partial. Measure with
  `--ppc-coverage` and validate against objdiff.

## When Ember cannot prove the answer

Stop and state the missing evidence when:

- the binary omits the peer REL, runtime module, or memory region containing a
  target;
- stripped code does not encode source-level GPR/FPR ordering or aggregate
  types uniquely;
- an indirect call has no relocation, table, signature, or runtime witness;
- an optimized expression has several source-equivalent CodeWarrior spellings;
- data has no type/layout/relocation evidence;
- a packed disk binary does not contain the runtime code being investigated;
- output still contains unresolved SSA/control-flow diagnostics.

The right next step is usually one of: import headers, add a narrow annotation,
load the correct DTK module, capture runtime facts, inspect the disassembly,
measure PPC coverage, syntax-check pseudo-C, or iterate with objdiff. Do not
paper over missing evidence with invented names, arguments, fields, or source.

## Build, test, and local installation

The project requires CMake 3.28+ and C++23. The CLI is built with GCC 16 or a
recent compatible compiler:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target ember_cli -j
./build/cli/ember --help
ctest --test-dir build --output-on-failure
```

This workstation's global tools normally resolve to:

```text
~/.local/bin/ember       -> build/release-local/cli/ember
~/.local/bin/ember-match -> scripts/ppc_match_loop.py
~/.local/bin/ember-unit  -> scripts/ppc_decompile_unit.py
```

Rebuild and update the CLI symlink only when installation was requested:

```sh
cmake -S . -B build/release-local -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build/release-local --target ember_cli -j 6
ln -sfn "$PWD/build/release-local/cli/ember" "$HOME/.local/bin/ember"
```

The Python wrapper is installed with `python -m pip install -e .`; its API is
documented in [docs/python.md](docs/python.md).

## Documentation index

- [README.md](README.md): design, features, support matrix, build, and layout
- [docs/powerpc.md](docs/powerpc.md): PPC/Wii ABI, DTK/REL, typed data/events,
  coverage, benchmarks, unit recovery, and CodeWarrior matching
- [docs/x86.md](docs/x86.md): x86-64 discovery, ABI/type recovery, COFF/DWARF,
  strings, imports, and current limitations
- [docs/scripting.md](docs/scripting.md): `.ember` annotations
- [docs/debugger.md](docs/debugger.md): pseudo-C debugger
- [docs/raw-input.md](docs/raw-input.md): raw bytes and region manifests
- [docs/teef.md](docs/teef.md): cross-binary recognition
- [docs/forge-spec.md](docs/forge-spec.md): minimum reachability shapes
- [docs/python.md](docs/python.md): Python wrapper

Keep this manual practical. Add a workflow when an agent needs it repeatedly;
put detailed implementation semantics and benchmark evidence in the focused
document linked above.
