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
