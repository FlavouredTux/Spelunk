# Spelunk

Spelunk is a reverse-engineering toolkit written from scratch in C++23. It
loads a binary, decodes the machine code, lifts it into its own IR, builds
SSA, runs cleanup passes, recovers control flow and prints pseudo-C. It
requires only the C++ standard library for its core analysis: no LLVM,
Capstone, Zydis, SLEIGH, and no debug info required.

```
binary -> loader -> decoder -> CFG -> IR -> SSA -> cleanup -> structure -> pseudo-C
```

## Example

`tests/fixtures/gotos.c`, compiled with gcc and stripped:

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

```
$ spelunk -p -s sub_401156 gotos
// sub_401156
uint64_t sub_401156(char* a1, char* a2) {
  if (!a1) {
    return -1;
  }
  if (!a2) {
    return -1;
  }
  uint64_t r_strlen = strlen(a1);
  uint64_t r_strlen_2 = strlen(a2);
  if (r_strlen != r_strlen_2) {
    return -1;
  }
  return 0;
}
```

The shared `fail` block became early returns, the spilled parameters were
forwarded, and `char*` came from the `strlen` calls.

## Support

|                 | x86-64                          | AArch64      | PPC32 / PPC64                     |
|-----------------|---------------------------------|--------------|-----------------------------------|
| Loaders         | ELF, Mach-O, PE, minidump, raw regions | ELF, Mach-O | ELF, PPC32 `.o`, DOL, Wii REL, DTK projects |
| Decoder + lift  | legacy, VEX, common EVEX/BMI/FMA | partial      | partial                           |
| SSA, cleanup, pseudo-C | full                     | partial      | partial                           |
| ABI             | SysV, Win64                     | AAPCS64      | SysV, ELFv1, ELFv2                |
| RTTI            | Itanium, MSVC                   | Itanium      | -                                 |

Unresolved things stay visible in the output rather than being guessed: an
indirect call without evidence renders as a typed function-pointer slot with
a comment, and PPC calls to unnamed functions carry their inferred signature.

## Build

C++23 (gcc 16+ or a recent clang) and CMake 3.28+:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/cli/spelunk --help
```

Wii U RPX/RPL compressed sections are expanded automatically when system zlib
development files are available at configure time. Use `-DSPELUNK_WITH_ZLIB=OFF`
to disable this optional dependency. Cafe imports are named by module, and
supported relocations are applied to the analysis image. External addresses
remain symbolic; this does not load Wii U system libraries or execute the game.

The Qt 6 desktop front end is optional:

```sh
cmake --preset gui && cmake --build --preset gui
./build/gui/gui/spelunk-gui path/to/binary
```

## Usage

Each view flag runs the pipeline up to that stage:

```sh
spelunk -d -s NAME ./target        # disassembly
spelunk -c -s NAME ./target        # CFG
spelunk -i -s NAME ./target        # lifted IR
spelunk --ssa -s NAME ./target     # SSA form
spelunk -O -s NAME ./target        # after cleanup passes
spelunk --struct -s NAME ./target  # structured regions
spelunk -p -s NAME ./target        # pseudo-C
spelunk --emit-c -s NAME ./target  # C export with declarations and explicit memory accesses
```

Without `-s` the default symbol is `main`. `--symbols FILE` batches many
functions through one load; `--json` is available where a machine-readable
form makes sense.

`--emit-c` fails when the function has undecoded control-flow targets or the
output still contains unresolved values, types, or operations. Use `-p` to
inspect partial pseudo-C; it is not a compilable or verified replacement for
the original function.

Whole-binary queries include `--functions`, `--strings`, `--xrefs`,
`--refs-to`, `--callees`, `--vtables` and `--identify`.
`spelunk --help <topic>` lists the rest by area (`view`, `syms`, `xrefs`,
`ana`, `fingerprints`, `ann`, `load`, `data`, `patch`, `cache`).

Other pieces, each documented under `docs/`:

- **Annotations**: renames, signatures, notes and field names in a sidecar
  file. See [docs/annotations.md](docs/annotations.md).
- **Runtime memory**: minidumps and raw region scrapes for packed targets,
  plus `--trace` to feed observed indirect-call edges back in. See
  [docs/raw-input.md](docs/raw-input.md).
- **PowerPC and Wii**: DTK projects, header-aware typing through libclang,
  data and event-script decompilation. See [docs/powerpc.md](docs/powerpc.md).
- **x86-64 details** in [docs/x86.md](docs/x86.md).

Expensive passes cache under `~/.cache/spelunk/`, keyed on the file's path,
size, mtime and the Spelunk version. `--no-cache` bypasses it.

## Layout

```
core/       the library
  binary/     loaders: ELF, DOL, REL, Mach-O, PE, minidump, raw regions, PDB
  disasm/     x86-64, AArch64 and PowerPC decoders
  analysis/   CFG, discovery, xrefs, strings, arity and type inference,
              RTTI, ObjC, unwind tables, fingerprints, recognition
  ir/         IR, lifters, SSA, cleanup passes
  structure/  region builder
  decompile/  pseudo-C emitter
cli/        the spelunk command
gui/        Qt 6 front end
tests/      unit tests and golden-output tests
docs/
```

## Tests

```sh
ctest --test-dir build
```

`ir_semantics_unit` and `ir_control_flow_unit` interpret integer SSA before and
after cleanup and compare return values and final memory bytes. They cover
arithmetic boundaries, cast chains, overlapping memory accesses, diamonds,
early returns, and counted loops, with deterministic generated cases.

The test-only interpreter supports 1–64-bit integers, bounded little-endian
memory, direct/conditional branches, and predecessor-selected phi nodes. Phis
update simultaneously, including on loop backedges. CFG and SSA validation
rejects malformed edges and non-dominating definitions; execution stops with
an error after 10,000 instructions by default. Unsupported operations and
step-limit exhaustion fail comparisons even when both versions fail. These
tests do not validate the decoders, lifters, or emitted pseudo-C.

`x64_pipeline_semantics` separately compares locally compiled x86-64 fixtures
against decoded/lifted SSA before and after cleanup and against emitted C
compiled at `-O0` and `-O2`. It covers register exchanges, multiply halves,
ANDN flags, shift signedness, parity, and zero/masked shift and rotate counts.
Narrow signed comparisons include negative values, sign-bit immediates, and
conditional moves. A loop with an internal diamond and early exits checks
that its shared latch is emitted only once.
Branch diamonds, early returns, counted loops, simultaneous loop phis, and
overlapping memory operations also run through every stage. Each execution
starts with the same memory bytes; comparisons check the return value and the
entire final memory image, including untouched guard bytes. Known pointer
slots are normalized explicitly between native addresses and IR offsets.
The adapter supplies explicit multiply/rotate
intrinsic semantics, and unsupported intrinsics still fail by default.
BMI cases execute only when the host CPU supports them. A separate UBSan run
exercises emitted shifts, loop exits, and memory accesses. Failures retain the
generated C and complete IR input transcript in the reported temporary directory.
This is targeted integer coverage, not general machine-code equivalence.

The x64 corpus also covers loop-carried call results, early exits after calls,
callee-saved values across deliberately clobbering helpers, and calls that
mutate aliased memory. It compares call counts as well as return values and
buffer bytes. Declared integer call arguments are projected into an explicit
test oracle; unknown calls and reads of unmodeled clobbers fail. Private frame
storage is excluded from the observable buffer comparison. Known scalar call
signatures allow the emitter to keep loop arguments and results in explicit
SSA locals, including when optimized code uses RBP as an ordinary counter.

`macho_pipeline_semantics` compares Clang-generated Intel Mach-O functions
against native C and recompiled pseudo-C, including mixed float/integer calls,
stack arguments, mutable function pointers, and memory writes. It also checks
stripped copies. See [the x86 testing notes](docs/x86.md#executable-checks-and-real-binary-audits)
for dependencies and the reusable corpus audit and C output checker.

`ppc_pipeline_semantics` checks synthetic PPC32 big-endian programs against
an independent Unicorn CPU reference, interpreted SSA before/after cleanup,
and emitted C compiled back to PPC at `-O0` and `-O2`. It compares integer
returns, all 256 data-memory bytes, and ordered helper-call traces that include
the memory value observed at each call. It covers arithmetic boundaries,
branches, CTR loops, overlapping stores, carry, and calls around branches and
memory writes. It requires Python `unicorn` with PPC support, `clang`, and
`ld.lld`; CTest reports a skip when these test-only dependencies are absent.
See [the PPC semantic test notes](docs/powerpc.md#semantic-execution-tests)
for scope, adapters, and seed replay.

Semantic mismatches print both IR versions and the initial machine state.
Generated cases also print a seed that can be replayed directly:

```sh
./build/tests/spelunk_ir_semantics_test --seed 42
./build/tests/spelunk_ir_control_flow_test --seed 42
```

Golden outputs live in `tests/golden/`. After an intentional output change,
regenerate them in the same commit:

```sh
UPDATE_GOLDEN=1 ctest --test-dir build -V
```

The compiled test fixtures are committed as `tests/fixtures/*.prebuilt`
so the goldens don't depend on the installed compiler; edit a fixture
source and run `scripts/refresh_fixtures.sh` to rebuild them.

## License

MIT, see [LICENSE](LICENSE).
