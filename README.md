# Ember

Ember is a reverse-engineering toolkit written from scratch in C++23. It
loads a binary, decodes the machine code, lifts it into its own IR, builds
SSA, runs cleanup passes, recovers control flow and prints pseudo-C. It
depends only on the C++ standard library: no LLVM, Capstone, Zydis, SLEIGH,
and no debug info required.

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
$ ember -p -s sub_401156 gotos
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
./build/cli/ember --help
```

The Qt 6 desktop front end is optional:

```sh
cmake --preset gui && cmake --build --preset gui
./build/gui/gui/ember-gui path/to/binary
```

## Usage

Each view flag runs the pipeline up to that stage:

```sh
ember -d -s NAME ./target        # disassembly
ember -c -s NAME ./target        # CFG
ember -i -s NAME ./target        # lifted IR
ember --ssa -s NAME ./target     # SSA form
ember -O -s NAME ./target        # after cleanup passes
ember --struct -s NAME ./target  # structured regions
ember -p -s NAME ./target        # pseudo-C
```

Without `-s` the default symbol is `main`. `--symbols FILE` batches many
functions through one load; `--json` is available where a machine-readable
form makes sense.

Whole-binary queries include `--functions`, `--strings`, `--xrefs`,
`--refs-to`, `--callees`, `--vtables`, `--identify` and `--recognize`.
`ember --help <topic>` lists the rest by area (`view`, `syms`, `xrefs`,
`ana`, `teef`, `ann`, `dbg`, `load`, `data`, `patch`, `cache`).

Other pieces, each documented under `docs/`:

- **Debugger** (`--debug`): breakpoints on pseudo-C lines, backtraces
  through `.eh_frame`, ptrace on Linux and Mach on macOS. See
  [docs/debugger.md](docs/debugger.md).
- **Function recognition** (`--teef`, `--recognize`): fingerprint a
  library, then name functions in a stripped binary from the corpus. See
  [docs/teef.md](docs/teef.md).
- **Annotations and `.ember` scripts**: renames, signatures and field
  names in a sidecar file or a small declarative script. See
  [docs/scripting.md](docs/scripting.md).
- **Runtime memory**: minidumps and raw region scrapes for packed targets,
  plus `--trace` to feed observed indirect-call edges back in. See
  [docs/raw-input.md](docs/raw-input.md).
- **PowerPC and Wii**: DTK projects, header-aware typing through libclang,
  data and event-script decompilation. See [docs/powerpc.md](docs/powerpc.md).
- **x86-64 details** in [docs/x86.md](docs/x86.md).

Expensive passes cache under `~/.cache/ember/`, keyed on the file's path,
size, mtime and the Ember version. `--no-cache` bypasses it.

Python wrapper (shells out to the CLI):

```sh
python -m pip install -e .
```

```python
from emberpy import Ember

e = Ember("tests/fixtures/gotos")
print(e.function("multi_exit").pseudo())
```

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
  debug/      ptrace, perf and Mach targets, unwinders
  script/     .ember scripts
cli/        the ember command
gui/        Qt 6 front end
python/     emberpy
tests/      unit tests and golden-output tests
docs/
```

## Tests

```sh
ctest --test-dir build
```

`ir_semantics_unit` interprets integer SSA before and after cleanup and
compares return values and final memory bytes. It covers arithmetic boundaries,
cast chains, overlapping memory accesses, and deterministic generated programs.
The test-only interpreter rejects unsupported operations; it currently handles
one straight-line block, 1–64-bit integers, and bounded little-endian memory.
It does not validate the decoders, lifters, or emitted pseudo-C.

Semantic mismatches print both IR versions and the initial machine state. Generated cases
also print a seed that can be replayed directly:

```sh
./build/tests/ember_ir_semantics_test --seed 42
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
