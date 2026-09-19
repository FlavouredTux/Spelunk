# Spelunk

Spelunk is a C++23 binary analysis and decompilation toolkit. It loads native
binaries, decodes machine code, lifts it into an internal IR, builds SSA,
recovers control flow, and emits pseudo-C.

```text
binary -> loader -> decoder -> CFG -> IR -> SSA -> cleanup -> pseudo-C
```

The core is implemented without LLVM, Capstone, Zydis, SLEIGH, or required
debug information.

## Support

| Architecture | Status | ABIs |
|---|---|---|
| x86-64 | Main target | SysV, Win64 |
| AArch64 / ARM32 | Partial | AAPCS64, AAPCS32 |
| PPC32 / PPC64 | Partial | SysV, ELFv1, ELFv2 |

Supported inputs include ELF, Mach-O, PE, PDB, minidumps, raw memory regions,
PPC object files, DOL, Wii REL, and DTK projects.

Incomplete analysis remains visible in the output. Pseudo-C is intended for
reverse engineering; it is not a reconstruction of the original source.

## Build

Spelunk requires CMake 3.28+ and a C++23 compiler. GCC 16 or a recent Clang is
recommended.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/cli/spelunk --help
```

The Qt 6 GUI is optional:

```sh
cmake --preset gui
cmake --build --preset gui
./build/gui/gui/spelunk-gui path/to/binary
```

Zlib is used for compressed Wii U sections when available. Disable it with
`-DSPELUNK_WITH_ZLIB=OFF`. Header import uses libclang when installed.

## CLI

List functions and inspect one in pseudo-C:

```sh
spelunk --functions ./target
spelunk -p -s main ./target
```

The available pipeline views are:

```sh
spelunk -d       -s NAME ./target  # disassembly
spelunk -c       -s NAME ./target  # control-flow graph
spelunk -i       -s NAME ./target  # lifted IR
spelunk --ssa    -s NAME ./target  # SSA form
spelunk -O       -s NAME ./target  # cleaned SSA
spelunk --struct -s NAME ./target  # structured regions
spelunk -p       -s NAME ./target  # pseudo-C
spelunk --emit-c -s NAME ./target  # strict C export
```

Without `-s`, the selected function defaults to `main`. Use `--symbols FILE`
to process a list of functions in one run. Commands that support structured
output accept `--json`. Function views emit one JSON result per function,
including failures, and batches continue after individual errors. Use
`--timeout 30s` to bound the whole command; expiry exits with status `124`.
See [CLI results and timeouts](docs/cli-output.md) for the record format.

With `--json`, stderr contains one JSON diagnostic per line, including argument
and loading errors. Records have `type` (`error` or `diagnostic`), `kind`, and
`message` fields. Check the exit status for command success; informational
diagnostics do not mean failure. stdout keeps the selected command's output
format and may contain partial results on failure.

```json
{"type":"error","kind":"io","message":"cannot open file"}
```

Error kinds include `invalid-format`, `io`, `unsupported`, `out-of-bounds`,
`truncated`, `not-implemented`, and `command-failed` for command-specific
failures. Other diagnostics use kind `cli`. Without `--json`, diagnostics
remain plain text.

Common whole-binary queries include:

```sh
spelunk --strings ./target
spelunk --xrefs ./target
spelunk --refs-to SYMBOL ./target
spelunk --callees ADDRESS ./target
spelunk --vtables ./target
spelunk --identify ./target
```

`--emit-c` rejects functions with unresolved control flow, values, types, or
operations. Use `-p` when partial output is useful.

Run `spelunk --help <topic>` for detailed options. Available topics include
`view`, `syms`, `xrefs`, `ana`, `fingerprints`, `ann`, `load`, `data`,
`patch`, and `cache`.

## Documentation

- [x86-64](docs/x86.md)
- [PowerPC and Wii](docs/powerpc.md)
- [Annotations](docs/annotations.md)
- [Raw memory input](docs/raw-input.md)
- [Forge specifications](docs/forge-spec.md)

## Development

```sh
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Tests include unit tests, golden output checks, semantic IR comparisons, and
native-versus-emitted-C checks. Golden files live in `tests/golden/`. Compiled
fixtures are committed under `tests/fixtures/` so their addresses do not vary
with the host compiler.

To update goldens after an intentional output change:

```sh
UPDATE_GOLDEN=1 ctest --test-dir build -V
```

## License

MIT, see [LICENSE](LICENSE).
