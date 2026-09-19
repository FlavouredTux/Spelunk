# PowerPC decompilation

## Wii U RPX/RPL input

With optional system zlib support, Spelunk loads Cafe OS ELF32 big-endian
PowerPC files directly, including compressed code, symbol, string, and
relocation sections. Decompression happens in the owned in-memory image;
the input file is unchanged. `image()` and section file offsets describe
that normalized image, not the original compressed layout.

Streams must pass zlib checksum validation and exactly match their declared
uncompressed size, without trailing bytes. Expansion is limited to 256 MiB
per section and 512 MiB total. Builds without zlib report an unsupported
compression error. Configure with `-DSPELUNK_WITH_ZLIB=OFF` to disable support.

Cafe import tables and ELF symbols identify function and data imports as
`module!symbol`, for example `coreinit!OSBlockMove`. Function-pointer references
retain the file's symbolic import-slot addresses. Calls whose destinations
are outside the PowerPC branch range use named, analysis-only veneers;
disassembly and pseudo-C can therefore identify the imported function without
guessing its address in a running Wii U. Data-import slots have no readable
runtime bytes: their on-disk module names are not treated as global values.

The loader applies supported absolute 32-bit and 16-bit relocations, relative
branches, REL32, and Green Hills relative halfword relocations. RELA records
use their absolute patch addresses and explicit signed addends. Local TLS
offsets are applied, while runtime TLS module IDs, unresolved symbols, and
unsupported relocations remain visible through `Binary::relocations()` with
`applied == false`. This flag describes the static analysis image, not a
running process. The default CLI inventory reports applied/unapplied counts
and lists unapplied records, bounded by `--row-limit`. Export tables are read
after relocation. BSS relocation
targets are materialized with zero-filled owned storage (64 MiB total limit).

Generated veneers and materialized BSS have no file-backed bytes;
their `file_offset` is `image().size()`. They are present in `sections()` and
`bytes_at()`, but not serialized into `image()`. Import/export metadata is not
scanned as executable code. The loader limits relocation records to 4 million
and generated veneers to 65,536. Cafe SHT_REL records with implicit addends
are rejected; this path expects SHT_RELA.

System-library implementations, runtime module addresses, TLS module IDs,
and SDA relocations are not supplied by this static linker. Check unapplied
records before treating an address as resolved. The format constants and
relocation expressions can be cross-checked against
[Decaf's Cafe loader](https://github.com/decaf-emu/decaf-emu/blob/master/src/libdecaf/src/cafe/loader/cafe_loader_reloc.cpp).

Spelunk supports PPC32 and PPC64 binary loading, instruction decoding, partial IR
lifting, and pseudo-C emission. Wii-oriented work can load a DOL, a standalone
REL, a relocatable PPC32 ELF object, or a complete DTK project. The decompiler
also recovers scalar function arguments passed through both the general-purpose
and floating-point register files.

## Calling conventions

### Virtual dispatch

PowerPC virtual-style calls use four-byte slots on PPC32 and eight-byte slots
on PPC64. When the loaded vtable belongs to the object passed in `r3`, output
uses `object->vfn_N(...)`, with the receiver implicit and the vptr displacement
shown in a comment. `vfn_N` is a slot label, not a recovered method name.

For unresolved signatures, a bounded 128-byte preparation window supplies
register-write evidence. Dispatch scratch registers and stale snapshot values
are omitted; explicit argument copies (including copies of the vtable itself)
are retained. Register comments such as `/* r4 */` and `/* f1 */` preserve lane
identity without claiming a known mixed-parameter order. Established incoming
parameters are retained even when prepared before the current block.

The `inferred ABI args` comment means the displayed argument list is heuristic:
extra arguments prepared earlier, stack arguments, and the full prototype may
still be unknown. Resolved call signatures take precedence, including floating
return lanes. If memory analysis requires a captured vptr or function pointer,
the emitter preserves the explicit target instead of reloading a virtual slot.

The currently modelled PowerPC ABIs use independent integer and floating-point
argument sequences:

| ABI | Integer / pointer arguments | Floating-point arguments |
|---|---|---|
| PPC32 SysV, including DOL and Wii REL | `r3` ... `r10` | `f1` ... `f8` |
| PPC64 ELFv1 big-endian | `r3` ... `r10` | `f1` ... `f13` |
| PPC64 ELFv2 little-endian | `r3` ... `r10` | `f1` ... `f13` |

An integer argument does not consume an FPR position, and a floating-point
argument does not consume a GPR position. For example, a source signature such
as:

```c
void update(double scale, Object* object, double limit, Vec3* position);
```

is passed through `f1`, `r3`, `f2`, and `r4`, respectively. Spelunk records both
register banks at each call and treats `f0` through `f13` as caller-clobbered.
The clobber model prevents a result or temporary left in an FPR by an earlier
call from becoming a phantom argument to a later call.

The ABI references used by the implementation are the
[32-bit PowerPC System V ABI](https://www.uclibc.org/docs/psABI-ppc.pdf) and the
[64-bit PowerPC ELF ABI](https://refspecs.linuxbase.org/ELF/ppc64/PPC-elf64abi.html).

## Binary-only argument recovery

Without type information, Spelunk lifts the callee and finds argument-register
values that are read before being overwritten. It then:

1. builds the live-in GPR and FPR lanes independently;
2. preserves ABI order inside each lane;
3. performs a stable merge using each value's first meaningful use in the
   callee; and
4. follows bounded direct-callee wrapper chains when a parameter is used only
   as an argument to another function (four call levels, at most 64 lifted
   functions per inference query). Explicit moves between integer argument
   lanes also provide evidence for forwarding through an indirect call.

Inference reuses a function-entry index within each query. Call-return
folding preserves calls before branches and memory operations; a unique use
alone does not justify moving a call to a conditional return. Computed
pointer values used by guarded call-argument merges are materialized before
the guard, so both the existing-pointer and allocation paths initialize the
value passed to the callee.

The resulting layout drives both the recovered function header and its call
sites. Direct calls and resolved or signature-known indirect calls use the
callee layout to select and interleave the saved GPR/FPR values.

Scalar overflow parameters are recovered from the ABI parameter area as well.
On PPC32 the first integer overflow word is at entry `r1 + 0x28`, after the
linkage area and eight GPR home slots. Spelunk follows a versioned `r1` through a
Metrowerks `stwu` frame allocation, so the same incoming slot is recognized in
leaf and framed callees. At call sites, layout-gated stores to the outgoing
parameter area are folded into the following call instead of leaking as
synthetic `arg_28` assignments. Exact annotations determine mixed scalar slot
width and alignment; stripped binary-only recovery remains conservative.

## Aggregate values and structure returns

Signature-backed small aggregates consume their complete consecutive GPR word
span. Spelunk rebuilds those words as a C compound literal at a call site, so an
eight-byte `CXParsedHeader` is emitted as one source argument and the following
scalar is taken from `r5`, not mistaken for the second half in `r4`.

Known large aggregate returns use the PPC hidden-result convention. The caller's
`r3` result-buffer pointer is removed from the source argument list and the
first declared integer parameter begins in `r4`. The call result keeps its
declared aggregate type in pseudo-C. Current Wii aggregate size knowledge covers
`GXColor`, `GXColorS10`, `CXParsedHeader`, `Vec`/`Vec3`, and
`Quaternion`/`Quat`; pointers, references, and array typedef parameters retain
their pointer-style ABI treatment.

Integer parameters used as load/store bases are marked pointer-like. The
evidence follows register copies, constant-offset address arithmetic, one level
of direct argument forwarding, and Wii `psq_l`/`psq_st` addresses. When no
stronger pointee type is known, the header uses `void*` rather than pretending
the ABI word is an integer or guessing a structure name.

## PPC return values

`blr` does not distinguish a source-level `return;` from returning the value
currently left in `r3` or `f1`. Integer and pointer results use `r3`; scalar
floating-point results use `f1`. Spelunk selects `f1` only when an explicit
annotation or a known routine prototype says the return is `float`/`double`.
Unknown calls remain on the established `r3` path, so merely clobbering `f1`
does not invent a floating result.

Known Wii SDK vector routines include the `PSVEC*` arithmetic family. For
example, a consumed result is rendered as a source-level binding:

```c
float magnitude = PSVecMag(&delta);
```

instead of a discarded `PSVecMag(&delta);` followed by an undefined FPR SSA
name. The same prototype data marks routines such as `PSVECSubtract` as
`void`, preserves their pointer arguments, and places the scalar argument of
`PSVECScale` in the independent FPR argument lane.

The built-in Wii table also covers common `PSMTX*`/`C_MTX*`, GX state and
texture setup, OS arena/context/thread/cache helpers, synchronous and
asynchronous DVD reads, KPAD/WPAD controller routines, and CX decompression
entry points. These prototypes provide exact void/integer/pointer/float return
lanes, mixed scalar ordering, callback-as-pointer positions, and known
`GXColor`/`CXParsedHeader` aggregate sizes. User annotations still take
precedence over every built-in entry.

For `r3`, Spelunk keeps direct definitions, call results with real consumers,
and ordinary conditional return expressions. It suppresses an incidental
merge when the evidence instead consists of unconsumed call clobbers or
live-in state mixed with values already used for side effects. This also
removes the synthetic `result` variable such merges would otherwise produce
in a `void` function.

For example, this PPC32 setup:

```asm
lfs   f1, constant(r2)
mr    r3, r31
addi  r4, r31, 0xbc
bl    update
```

can render as:

```c
update(*(float*)(r2 + constant), object, object + 0xbc);
```

## Measuring decoder and lift coverage

### Semantic execution tests

Run `ctest --test-dir build -R '^ppc_pipeline_semantics$' --output-on-failure`.
The default corpus contains 406 seeded cases across eight synthetic assembly
functions in `tests/support/ppc_pipeline.S`. Every case checks five executions
against a small mathematical reference: original PPC instructions in Unicorn,
SSA before cleanup, SSA after cleanup, and emitted C compiled to PPC at both
`-O0` and `-O2` and executed in Unicorn. Function signatures are supplied by
the fixtures; this test does not measure unknown-signature inference.

The comparison includes the 32-bit return, every byte of a 256-byte data
region (including untouched guard bytes), and the order, arguments, and
observed memory values of two explicitly modeled helper calls. Private stack
frames are not compared because recompilation changes their layout. Writes
outside the data and stack regions fail. CPU/interpreter instruction limits,
unmodeled calls, and unsupported intrinsics fail rather than count as matches.

The test adapter preserves raw IR dumps and separately projects the fixture's
integer ABI: `r3` is the return lane, unused ABI snapshots are discarded, and
big-endian loads/stores are adapted to the shared little-endian interpreter
with explicit byte swaps. Helper-call effects are modeled at the call site.
The emitted function bodies are compiled unchanged; a small preamble supplies
integer types and the documented `carry_add` operation.

Required test-only dependencies are Python Unicorn 2+ with PowerPC support,
Clang's PPC backend, and `ld.lld`. They are not core library dependencies.
Missing tools produce a CTest skip, not a pass. To replay or vary a seed:

```sh
python3 tests/ppc_pipeline_test.py \
  --probe build/tests/spelunk_ppc_pipeline_probe \
  --clang clang --lld ld.lld --support tests/support --seed 0x505043
```

Failures retain a temporary directory containing the seed, input transcript,
ELFs, emitted C, original and adapted IR, command logs, and mismatch details.
This first corpus covers integer arithmetic, branches, CTR loops, overlapping
word/halfword accesses, carry, and direct calls. It does not establish general
PPC equivalence or cover floating point, paired-single/GQR operations, indirect
calls, exceptions, or concurrency.

`--ppc-coverage` scans every four-byte word in executable sections. It reports
hard decoder failures first, then ranks decoded instructions that still lift to
an opaque `ppc.*` intrinsic:

```sh
spelunk --dtk ./spm --dtk-version EU0 --ppc-coverage --coverage-limit 20
```

Use `--json` for tooling and `--coverage-limit 0` for the complete ranking. The
scan is deliberately conservative and includes embedded data in executable
sections, so inspect the sample addresses before treating an unsupported word
as a missing instruction.

For the local SPM EU0 DOL used during development, the scan decoded
785,390/787,040 words. The 14 nonzero unsupported words were embedded data, not
real instructions. Semantic ranking identified scalar fused floating-point
operations and `frsp` as the highest-value safe gaps: together they accounted
for 4,860 opaque lift fallbacks. They now produce typed multiply/add/subtract/
negate dataflow and an explicit `float` rounding cast, which lets pseudo-C show
ordinary arithmetic instead of `ppc.fmadds(...)` or `ppc.frsp(...)`.
The common Metrowerks `fctiwz; stfd; lwz` sequence is also folded into a signed
integer cast, removing the temporary stack spill used only to move the
converted payload from an FPR into a GPR.
Header aliases `f32` and `f64` participate in the same ABI classification as
`float` and `double`. This is important for mixed-lane Wii calls: an `f32`
return binds the post-call `f1` value, and `f32` parameters consume FPR slots
without displacing independently numbered GPR arguments. PPC `bdnz`/CTR loops
retain their predecrement side effect as `--i != 0` (or `--i == 0` for a break)
instead of the incorrect non-mutating `i - 1` condition.
Unquantized `psq_l`/`psq_st` operations using the conventional Wii GQR0 pair
mode lift as ordinary `float2` loads and stores. Single-lane and quantized GQR
forms keep explicit PPC helpers until their lane and scale semantics can be
represented without guessing.
`rlwimi` is expanded into rotate/mask/merge dataflow, while `cntlzw` becomes
the architecture-neutral `count_leading_zeros(...)` operation. This keeps
compiler-generated bit idioms readable and available to cleanup passes.
`lmw` and `stmw` expand into ordinary 32-bit loads and stores. This exposes
their dataflow to SSA and lets the emitter suppress matched callee-saved
register save/restore traffic as ABI boilerplate.

The paired-single fused arithmetic family (`ps_madd`, `ps_msub`, `ps_nmadd`,
and `ps_nmsub`) is likewise expanded into typed two-lane multiply/add/subtract
dataflow. Lane-shuffle, reciprocal-estimate, and quantized GQR operations stay
explicit until their exact vector semantics can be represented safely.

Pseudo-C pointer declarations also follow visible memory-address flow through
register copies and constant field offsets. This preserves pointer-shaped Wii
locals even when an earlier ABI-width integer hint conflicts with later body
evidence; mixed-width field bases remain deliberately opaque `void*` values.

### CodeWarrior jump tables

PPC32 CFG recovery recognizes the bounded CodeWarrior dispatch shape built
from `lwzx`, `mtctr`, and `bctr`. Spelunk resolves the absolute big-endian target
table, adds every in-range target plus the bounds-check default edge to the
CFG, preserves duplicate targets as grouped cases, and emits a structured
`switch`. The selector is traced back through the scaled table index and its
bounds-check predecessor, so source output uses the recovered state field or
local instead of `ctr` or a temporary register.

This is important for large Wii state machines such as `seq_mapChangeMain`,
where an unresolved `bctr` otherwise hides nearly the entire function.

### Header-aware Wii source recovery

Pass one or more header files/directories with `--headers`. Spelunk asks
libclang for 32-bit PowerPC layouts and overlays matching function prototypes,
parameter names, direct record fields, arrays, globals, and enums. Imported
pointer-valued globals also retain their record layouts, so SDA accesses can
render as `gp->mapName` instead of `gp + 0x44`. Decomp-header
`UNKNOWN_FUNCTION(name)` declarations are treated as incomplete prototypes,
not as false zero-argument functions. Existing
manual annotations retain priority. Extra include paths or project defines can
be passed with repeatable `--header-arg` values:

```sh
spelunk --headers /path/to/spm/spm-headers/include \
  --header-arg=-I/path/to/spm/spm-headers/decomp \
  --dtk /path/to/spm --dtk-version EU0 -p -s seq_mapChangeMain
```

For multi-function work, `--symbols FILE` accepts the same comment-friendly,
one-symbol-per-line format as the quality corpus. Spelunk loads the DOL/REL,
DTK symbols, annotations, and headers once, prefixes each result with
`// spelunk-symbol: NAME`, and reuses that project context across the batch.

The importer is an optional CLI dependency. Builds made without libclang keep
all ordinary decompilation features and report a focused error only when
`--headers` is requested.
For conventional `spm-headers/include` trees, sibling `decomp` and `mod`
directories are added to Clang's include search automatically. Both ordinary
Clang declarations and object-like `DECOMP_STATIC(...)` declarations populate
the global type database, including arrays and aggregate objects hidden from
Clang by decompilation macros.

Header and body evidence are combined rather than applied as unrelated
cosmetic hints. Mixed GPR/FPR prototypes shape stack locals (`f32*` produces a
scalar `float`, not an accidental integer array), inferred record layouts flow
back to live-in parameters and allocator returns, and direct aggregate globals
use imported field names. When a byte offset has no known field, fallback
pointer arithmetic is explicitly cast through `uint8_t*` so it remains valid C.

When headers accompany a DTK project, Spelunk also imports simple prototypes
from sibling source units and runs signature inference over only the requested
functions and their transitive direct callees. Public headers retain priority;
source declarations fill private gaps, while scoped IPA supplies return lanes
and parameter evidence for still-unnamed leaves. Built-in SDK signatures beat
absence-based inference, and caller-visible return use prevents a helper from
being mislabeled `void`. A sized DTK function symbol also owns all interior
labels, so shared epilogues cannot be rediscovered as fake tail-call targets.

### Typed data and SPM event scripts

Use `--decompile-data SYMBOL --type TYPE` to turn fixed data into a C
initializer. Records and arrays come from imported headers; pointers consult
loader relocation records first and are classified as functions, event/data
objects, strings, nested records, or nulls. Record pointers inside tables are
followed automatically and rendered as typed compound initializers; recursion
is bounded so corrupt or cyclic data cannot make the command run forever.

```sh
spelunk --headers /path/to/spm/spm-headers/include \
  --dtk /path/to/spm --dtk-version EU0 \
  --decompile-data mapData --type 'MapData *[468]' --verify-roundtrip
```

`--evt-script SYMBOL` is the SPM-specific companion. It decodes the packed
argument-count/opcode word, validates instruction boundaries, names callbacks
through DOL/REL symbols, renders encoded values (`LW`, `GSW`, `FLOAT`, and the
other event variable classes), and indents structured IF, SWITCH, DO, inline,
and brother-event regions until `EVT_END()`.

Add `--verify-roundtrip` to either command to validate output mechanically.
Typed-data verification reparses emitted scalar/enum literals, checks record
padding and recursively followed objects, and preserves pointer/relocation
slots. Event verification reverses every variable macro, opcode, argument
count, raw argument, callback, and relocation-backed symbol. A mismatch is a
hard error; successful runs report the verified byte/object/relocation totals.

Calls whose DTK name is still only `func_*` or `sub_*` retain that honest
placeholder, but pseudo-C now appends the concrete target address and inferred
PPC argument types. This makes unresolved callbacks actionable without
inventing a semantic name that the binary cannot prove.

### CodeWarrior matching boundary

Pseudo-C removes mechanical reverse-engineering work, but it cannot uniquely
recover the programmer's original source from optimized instructions. Treat it
as a typed starting point. Byte-for-byte CodeWarrior matching still needs
manual objdiff iteration over control-flow spelling, local declaration order,
stack layout, temporary lifetimes, casts, and compiler-sensitive expressions.

### Automated CodeWarrior matching loop

`scripts/ppc_match_loop.py` exhaustively evaluates a bounded set of controlled
source alternatives. It reads the selected unit from `objdiff.json`, asks Ninja
for that unit's real compiler invocation, substitutes only the candidate source
and isolated output directory, then scores the requested function with
objdiff's one-shot JSON diff:

```sh
python3 scripts/ppc_match_loop.py \
  --project /path/to/spm \
  --unit main/mario_motion \
  --symbol mot_22 \
  --spec mot22-variants.json \
  --output-dir /tmp/mot22-match \
  --jobs 4 \
  --fail-unmatched
```

The version-1 JSON spec contains exact, non-overlapping source choices. The
current source spelling is always included automatically, so alternatives only
describe the variants worth testing. A single spec can combine equivalent
comparison direction, casts, condition layouts, expression spelling, and local
declaration order:

```json
{
  "version": 1,
  "choices": [
    {
      "name": "delay-condition",
      "category": "condition",
      "find": "timer > 0.0f",
      "alternatives": [
        { "name": "swapped", "text": "0.0f < timer" },
        { "name": "negated", "text": "!(timer <= 0.0f)" }
      ]
    },
    {
      "name": "locals",
      "category": "declarations",
      "find": "    Vec3 position;\n    Vec3 offset;",
      "alternatives": [
        { "name": "offset-first", "text": "    Vec3 offset;\n    Vec3 position;" }
      ]
    }
  ]
}
```

See `docs/ppc_match_spec.example.json` for a larger template. If `find` occurs
more than once, set a 1-based `occurrence`; overlapping choices are rejected.
The Cartesian product is complete and deterministic, and the tool refuses to
silently truncate it beyond `--max-candidates` (256 by default).

For a useful first pass without writing a spec, use automatic discovery:

```sh
spelunk-match \
  --project /path/to/spm \
  --unit main/mario_motion \
  --symbol mot_22 \
  --auto \
  --output-dir /tmp/mot22-auto \
  --jobs 4 \
  --beam-width 8 \
  --max-candidates 256
```

Automatic mode scopes itself to the requested source function. It ignores
comments, strings and preprocessor lines, and generates only conservative
side-effect-free forms: swapped pure comparison operands, adjacent uninitialized
declaration order, identifier increments, simple compound assignments, and
explicit boolean zero tests. Each step compiles the beam, ranks it with the
requested function's objdiff score, and retains `--beam-width` survivors.
`--max-candidates` is a hard total compile budget and `results.json` records
whether that budget truncated the search. Use `--auto-whole-unit` only when the
symbol has no source definition or a unit-wide search is intentional.

Candidates are compiled in parallel under the marked output directory. The
input source and project are never rewritten. Identical reruns reuse cached
candidate results. `best.c` contains clean source without the synthetic
`#line` used for compilation, `best.o` is the corresponding CodeWarrior object,
and `best.objdiff.json` is the full diff evidence. `results.json` records every
choice, command, timing, object path, exact percentage, function sizes, and diff
count; `summary.txt` is the compact result. `--fail-unmatched` returns 1 unless
objdiff reports an exact 100% function match.

objdiff 3.8 or newer provides the direct per-function JSON path. Older versions
fall back to a temporary one-unit progress report, but updating is recommended
for speed and exact function-focused scoring. Automatic mode deliberately does
not invent casts, reorder initialized declarations, transform expressions
containing calls/indexing, or claim that a high fuzzy score is a match. A JSON
spec remains the right path for project-specific cast and control-flow
alternatives. In both modes only an exact objdiff result is reported as 100%
matching.

### Whole translation-unit recovery

`scripts/ppc_decompile_unit.py` bridges function-oriented pseudo-C and an
objdiff source unit. It asks objdiff for the retail object's function symbols,
keeps their object order, decompiles them through Spelunk's shared DTK batch
context, and combines them with the original source preamble and includes:

```sh
python3 scripts/ppc_decompile_unit.py \
  --project /path/to/spm \
  --unit main/mario_motion \
  --headers /path/to/spm/spm-headers/include \
  --header-arg=-I/path/to/spm/spm-headers/decomp \
  --output /tmp/mario_motion.recovered.c \
  --strict
```

The output is always separate from `metadata.source_path`. Synthetic
`PpcState`/`PpcObject` families are scoped by function name so independently
inferred layouts do not collide when assembled into one file. `--strict`
rejects partial batches, and the footer records the exact recovery command.
The result is a compile-oriented starting translation unit; exact source still
requires resolving any explicitly reported SSA/type gaps and validating it
with the unit's real CodeWarrior command and objdiff.

Add `--verify` to perform that validation immediately:

```sh
spelunk-unit \
  --project /path/to/spm \
  --unit main/main \
  --headers /path/to/spm/spm-headers/include \
  --output /tmp/main.recovered.c \
  --verify \
  --verify-dir /tmp/main.evidence \
  --fail-unmatched
```

Verification copies the recovered source under the original basename, reuses
the exact compiler command exposed by Ninja, and writes `compile.log`, the
candidate object, the full `objdiff.json`, `verification.json`, and a compact
`verification.txt`. Function and data matches follow objdiff's target-symbol
mapping, so CodeWarrior local-label renumbering does not create false data
failures. Nonmatching functions are written to `matcher-symbols.txt` and
`matcher-queue.json` with ready-to-run bounded `spelunk-match --auto` commands;
compiler diagnostics and likely missing header/annotation names are retained
when compilation fails. `--compile-command` provides the same placeholder
override as `spelunk-match` for projects that do not expose Ninja commands.

### Project-scale expectations

"100% exact" means that the rebuilt object code and data agree byte-for-byte
with the configured reference according to objdiff. It does not include the
disc's textures, audio, movies, or other unlinked assets, and it does not imply
that the recovered C is textually identical to the lost original source.

As a concrete scale reference, a whole-project objdiff report for SPM EU0 on
2026-08-18 measured:

| Metric | Whole target | Matched in the snapshot | Remaining |
|---|---:|---:|---:|
| Functions | 10,216 | 584 (5.72%) | 9,632 |
| Code | 3,550,036 bytes | 136,908 bytes (3.86%) | 3,413,128 bytes |
| Data | 4,636,761 bytes | 125,009 bytes (2.70%) | 4,511,752 bytes |
| Code and data | 8,186,797 bytes (7.81 MiB) | 261,917 bytes | 7,924,880 bytes (7.56 MiB) |

The code size corresponds to roughly 887,509 four-byte PPC instructions. The
report contained 4,776 objdiff units, but only 27 had a configured source file;
the remaining auto-split units are bookkeeping boundaries, not 4,749 separate
C files that must each be written by hand. Thirteen units were completely
matched in this snapshot.

These figures are a dated project snapshot, not a Spelunk benchmark or a
completion forecast. `spelunk-unit` can create and verify a starting point for a
unit, and its matcher queue can drive `spelunk-match` across the remaining
functions. Exact completion still requires human decisions for compiler-
sensitive control flow and expressions, translation-unit layout, static data,
relocations, and types that the binary cannot uniquely prove. The tools reduce
that iteration; they do not make a multi-thousand-function project an
unattended one-command decompilation.

### Repeatable SPM pseudo-C benchmark

The checked-in `benchmarks/spm_eu0_ppc.txt` manifest keeps a stable twelve-function
mix of ABI, control-flow, scalar-float, nested object, pointer-return, and GX
call sites. It includes `pluswinMain` and `pluswinBgDispSub` as semantic
regressions for navigation tables, Phi liveness, loop induction, and
CodeWarrior integer-to-float conversion. Run it with:

```sh
python3 scripts/ppc_quality_benchmark.py \
  --spelunk ./build/cli/spelunk \
  --dtk /path/to/spm \
  --dtk-version EU0 \
  --headers /path/to/spm/spm-headers/include \
  --roundtrip-manifest benchmarks/spm_eu0_roundtrip.txt
```

Add `--timings` to collect wall-clock cost plus Spelunk's CFG, lift, SSA,
cleanup, type-inference, structurer, and emitter phase timings. Timing values
are reported for diagnosis but deliberately excluded from pass/fail baseline
comparisons because machine load is noisy.

The benchmark uses Spelunk's batch mode by default, so project loading happens
once. `--no-batch` retains the older one-process-per-function behavior for
diagnosis. Repeatable `--headers` and `--header-arg` options exercise the same
type overlay used during real decompilation. `--syntax-check` runs Clang over
each generated function, while `--roundtrip-manifest` executes typed-data and
event cases such as `benchmarks/spm_eu0_roundtrip.txt`.

The report counts raw architectural registers and versioned SSA names,
temporary identifiers, opaque `ppc.*` calls, generic parameters and fields,
unresolved `func_`/`sub_` calls, and `STRUCTURER_FAIL` diagnostics. It also
checks constant conditions, unresolved SSA merges, raw event pointers, and
optional syntax failures, then normalizes every lower-is-better metric per
1,000 lines. The checked-in
`benchmarks/spm_eu0_quality_baseline.json` captures the current corpus and can
be enforced later:

```sh
python3 scripts/ppc_quality_benchmark.py --dtk /path/to/spm \
  --headers /path/to/spm/spm-headers/include \
  --baseline benchmarks/spm_eu0_quality_baseline.json --fail-on-regression
```

PPC merge recovery performs a CFG must-assignment pass after call binding and
edge materialization. Stable stack/global pointer initializers are recovered
from Phi webs, two-arm diamonds render as conditional expressions, and locals
whose first top-level statement assigns them remain intentionally
uninitialized until that statement. The baseline therefore rejects any return
of synthetic `{0} /* unresolved SSA merge */` declarations.

Phi pruning is sink-aware: a merge web survives only when it reaches an
observable non-Phi use. Call arguments count as sinks only when the resolved
callee ABI actually consumes that lane, so stale caller-clobbered register
lanes no longer leak into pseudo-C as raw `r8`, `r9`, or `r10` values. Add/sub
values feeding loop Phis are mapped back to their recovered locals and emitted
as `i++`/`i--`, even when the same value also feeds a loop comparison.

Pseudo-C also preserves the time at which a PPC memory value was read. A load
kept across a later call or a proven aliasing store is materialized before that
barrier, and one-write stack save slots whose source is itself a load remain
real locals. This prevents reset functions from collapsing a genuine
save/`memset`/restore sequence into false output such as
`work->flags = work->flags`. Pointer-to-const call parameters refine the stack
object's base type without incorrectly declaring the caller's local `const`.

CodeWarrior switch recovery prefers the bounds comparison's non-immediate
operand when cleanup has propagated the architectural selector out of the
dispatch block. A caller-clobbered `r3` in the same predecessor is not accepted
as selector evidence. The quality baseline counts exact self-assignment lines
and rejects their reintroduction. Depth-capped expressions that still cannot
be materialized are initialized explicitly and marked
`unresolved expression materialization` instead of becoming silently
uninitialized C variables.

CodeWarrior's signed-integer-to-double sequence (`xoris`, paired stack stores,
`lfd`, then subtraction of the `0x43300000` bias) is recognized as one typed
conversion. The emitter uses the closest reaching low-word store and renders
the source expression directly, such as `(float)(int32_t)(i - 2)`, instead of
exposing the stack scratch and magic bias. Eight-byte menu-navigation tables
with four neighbor bytes and a callback slot are rendered as typed
`PpcNavigationEntry` arrays, including `neighbor_N` field accesses and a typed
callback invocation with the selected entry address.

Big-endian high/low load pairs are also rejoined when an imported eight-byte
field proves their shared identity. CodeWarrior `subfc`/`subfe` chains then
recover signed 64-bit differences, and the `mulhwu` magic-number division used
for `/ 1000` is checked against the Wii timer-clock shape. A guarded elapsed
time comparison can consequently render as
`OSTicksToMilliseconds(gp->time - work->openingTime) <= 500` instead of an
`__div2i` call, two raw word fields, carry expressions, and `0x10624dd3`.

Header-aware pseudo-C is self-contained for the types it uses. Spelunk emits
compact union overlays containing the imported fields referenced by the
function, opaque storage for otherwise incomplete records, required forward
declarations, and array aliases such as `Mtx34`. Nested aggregate accesses use
the imported layout and access width, so scalar traffic at the start of a
`Vec3` renders as `.x`, `.y`, or `.z` rather than assigning a float to the
whole vector. Four- and eight-byte aggregate transfers use `_raw` compound
literals for valid C while retaining the named aggregate type.

When a DTK version accompanies conventional `spm-headers`, Spelunk reads the
matching `linker/spm.<version>.lst` and overlays header globals by address.
This turns anonymous map names such as `lbl_805ae930` into the project spelling
`pausewin_wp`, allowing subsequent accesses to become
`pausewin_wp->entries`. The binary symbol remains the address authority; an
alias is accepted only when its linker-list address names an existing object
and the header declares the same global.

Typed pointer arithmetic now removes byte scaling already implied by C. For
example, `entries + id * 0x78` becomes `entries + id` when the imported entry
size is `0x78`, while a synthetic record iterator with a proven stride renders
as `ptr++`. Masked rotate scales such as
`rotl32(index, 2) & 0xfffffffc` normalize to a four-byte index before C pointer
scaling. Header layouts then recover both `object->array[index]` and
`records[index].field`; fixed-address tables with a wider proven stride get a
self-contained `PpcDataEntry` declaration. Contiguous runs of four or more PPC
field copies are folded into a
single offset-preserving `memcpy`, and stack matrices passed to MTX routines
recover `Mtx34` declarations instead of `uint64_t[6]` storage.

Expression expansion remains bounded, but its budget covers the longer
rotate/index/load chains seen in the SPM corpus. A dominating cross-block load
is materialized at its definition, and a final fallback is expanded only when
that snapshot is dependency-safe. The checked-in corpus currently contains no
unresolved expression materializations and passes standalone C11 syntax
checking with imported headers enabled.

The tool returns 2 when a corpus function cannot be decompiled and 1 when a
requested baseline check regresses. It has no third-party Python dependencies,
and its metric parser is covered by the normal CTest suite.

## Supplying an exact signature

An annotation takes precedence over inferred arity, types, and interleaving.
This is the preferred way to pin a known SDK or decompilation-project
prototype:

```sh
spelunk --annotate 0x8011f45c \
  --set-signature "void update(double scale, Object* object, Vec3* position)" \
  --annotations project.annotations <binary>
```

Known import and platform SDK signatures receive the same mapping.
Parameter-scoped field names can be stored in the annotation file; see
[annotations.md](annotations.md).

## Current limits

- Source order across independent GPR/FPR lanes is not encoded in stripped
  machine code. First-use merging is deterministic and usually useful, but it
  remains a heuristic when no signature is available.
- PPC32 FPR transport alone does not reliably distinguish a source `float`
  from `double`. Binary-only scalar FPR parameters are therefore rendered
  conservatively as `double`; an annotation can select `float` precisely.
- Floating return recovery is deliberately evidence-driven. Unknown routines
  are not assumed to return through `f1`; add a signature when a routine is not
  in the built-in prototype table.
- Scalar stack-passed arguments are reconstructed for ordinary aligned PPC
  parameter slots. Signature-backed aggregates with known sizes and large
  hidden-result returns are classified. Dynamically addressed outgoing areas,
  unknown named aggregate sizes, and binary-only aggregate classification are
  not reconstructed yet.
- Return types, pointer target types, and structure names can remain generic
  when the ABI state is ambiguous. Pointer-shaped parameters deliberately use
  `void*` until stronger evidence is available, and PPC `void` recovery remains
  conservative. Use a signature and field annotations when exact types are
  known.
- Vector/paired-single coverage and the PPC instruction lift remain partial.
