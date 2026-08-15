# PowerPC decompilation

Ember supports PPC32 and PPC64 binary loading, instruction decoding, partial IR
lifting, and pseudo-C emission. Wii-oriented work can load a DOL, a standalone
REL, a relocatable PPC32 ELF object, or a complete DTK project. The decompiler
also recovers scalar function arguments passed through both the general-purpose
and floating-point register files.

## Calling conventions

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

is passed through `f1`, `r3`, `f2`, and `r4`, respectively. Ember records both
register banks at each call and treats `f0` through `f13` as caller-clobbered.
The clobber model prevents a result or temporary left in an FPR by an earlier
call from becoming a phantom argument to a later call.

The ABI references used by the implementation are the
[32-bit PowerPC System V ABI](https://www.uclibc.org/docs/psABI-ppc.pdf) and the
[64-bit PowerPC ELF ABI](https://refspecs.linuxbase.org/ELF/ppc64/PPC-elf64abi.html).

## Binary-only argument recovery

Without type information, Ember lifts the callee and finds argument-register
values that are read before being overwritten. It then:

1. builds the live-in GPR and FPR lanes independently;
2. preserves ABI order inside each lane;
3. performs a stable merge using each value's first meaningful use in the
   callee; and
4. follows one level of direct callee forwarding when a parameter is used only
   as an argument to another function.

The resulting layout drives both the recovered function header and its call
sites. Direct calls and resolved or signature-known indirect calls use the
callee layout to select and interleave the saved GPR/FPR values.

Scalar overflow parameters are recovered from the ABI parameter area as well.
On PPC32 the first integer overflow word is at entry `r1 + 0x28`, after the
linkage area and eight GPR home slots. Ember follows a versioned `r1` through a
Metrowerks `stwu` frame allocation, so the same incoming slot is recognized in
leaf and framed callees. At call sites, layout-gated stores to the outgoing
parameter area are folded into the following call instead of leaking as
synthetic `arg_28` assignments. Exact annotations determine mixed scalar slot
width and alignment; stripped binary-only recovery remains conservative.

## Aggregate values and structure returns

Signature-backed small aggregates consume their complete consecutive GPR word
span. Ember rebuilds those words as a C compound literal at a call site, so an
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
floating-point results use `f1`. Ember selects `f1` only when an explicit
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

For `r3`, Ember keeps direct definitions, call results with real consumers,
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

`--ppc-coverage` scans every four-byte word in executable sections. It reports
hard decoder failures first, then ranks decoded instructions that still lift to
an opaque `ppc.*` intrinsic:

```sh
ember --dtk ./spm --version EU0 --ppc-coverage --coverage-limit 20
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
from `lwzx`, `mtctr`, and `bctr`. Ember resolves the absolute big-endian target
table, adds every in-range target plus the bounds-check default edge to the
CFG, preserves duplicate targets as grouped cases, and emits a structured
`switch`. The selector is traced back through the scaled table index and its
bounds-check predecessor, so source output uses the recovered state field or
local instead of `ctr` or a temporary register.

This is important for large Wii state machines such as `seq_mapChangeMain`,
where an unresolved `bctr` otherwise hides nearly the entire function.

### Header-aware Wii source recovery

Pass one or more header files/directories with `--headers`. Ember asks
libclang for 32-bit PowerPC layouts and overlays matching function prototypes,
parameter names, direct record fields, arrays, globals, and enums. Imported
pointer-valued globals also retain their record layouts, so SDA accesses can
render as `gp->mapName` instead of `gp + 0x44`. Decomp-header
`UNKNOWN_FUNCTION(name)` declarations are treated as incomplete prototypes,
not as false zero-argument functions. Existing
manual annotations retain priority. Extra include paths or project defines can
be passed with repeatable `--header-arg` values:

```sh
ember --headers /path/to/spm/spm-headers/include \
  --header-arg=-I/path/to/spm/spm-headers/decomp \
  --dtk /path/to/spm --version EU0 -p -s seq_mapChangeMain
```

For multi-function work, `--symbols FILE` accepts the same comment-friendly,
one-symbol-per-line format as the quality corpus. Ember loads the DOL/REL,
DTK symbols, annotations, and headers once, prefixes each result with
`// ember-symbol: NAME`, and reuses that project context across the batch.

The importer is an optional CLI dependency. Builds made without libclang keep
all ordinary decompilation features and report a focused error only when
`--headers` is requested.

### Typed data and SPM event scripts

Use `--decompile-data SYMBOL --type TYPE` to turn fixed data into a C
initializer. Records and arrays come from imported headers; pointers consult
loader relocation records first and are classified as functions, event/data
objects, strings, nested records, or nulls. Record pointers inside tables are
followed automatically and rendered as typed compound initializers; recursion
is bounded so corrupt or cyclic data cannot make the command run forever.

```sh
ember --headers /path/to/spm/spm-headers/include \
  --dtk /path/to/spm --version EU0 \
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

### Repeatable SPM pseudo-C benchmark

The checked-in `benchmarks/spm_eu0_ppc.txt` manifest keeps a stable ten-function
mix of ABI, control-flow, scalar-float, nested object, pointer-return, and GX
call sites. Run it with:

```sh
python3 scripts/ppc_quality_benchmark.py \
  --ember ./build/cli/ember \
  --dtk /path/to/spm \
  --version EU0 \
  --headers /path/to/spm/spm-headers/include \
  --roundtrip-manifest benchmarks/spm_eu0_roundtrip.txt
```

Add `--timings` to collect wall-clock cost plus Ember's CFG, lift, SSA,
cleanup, type-inference, structurer, and emitter phase timings. Timing values
are reported for diagnosis but deliberately excluded from pass/fail baseline
comparisons because machine load is noisy.

The benchmark uses Ember's batch mode by default, so project loading happens
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
  --baseline benchmarks/spm_eu0_quality_baseline.json --fail-on-regression
```

The tool returns 2 when a corpus function cannot be decompiled and 1 when a
requested baseline check regresses. It has no third-party Python dependencies,
and its metric parser is covered by the normal CTest suite.

## Supplying an exact signature

An annotation takes precedence over inferred arity, types, and interleaving.
This is the preferred way to pin a known SDK or decompilation-project
prototype:

```ember
[signature]
0x8011f45c = void update(double scale, Object* object, Vec3* position)
```

Apply it with the normal annotation workflow:

```sh
ember --apply ppc-signatures.ember --annotations project.annotations <binary>
```

Known import and platform SDK signatures receive the same mapping. Parameter
names may also be used by `[field]` directives; the complete annotation syntax
is documented in [scripting.md](scripting.md).

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
