<p align="center">
  <img src="docs/mascot.png" alt="Ember" width="360">
</p>

# Ember

A from-scratch reverse-engineering toolkit: ELF + Mach-O loader, x86-64
disassembler, IR lifter, SSA, cleanup passes, control-flow structuring,
pseudo-C emitter, a QuickJS scripting surface, and an Electron UI.

No Capstone. No Zydis. No Ghidra decompiler. Stdlib only (QuickJS-NG is
vendored for scripting).

![welcome screen](docs/welcome.png)

![decompiler view](docs/main.png)

## Build

Requires a C++23 compiler (GCC 15+ or recent Clang) and CMake 3.28+.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/cli/ember --help
```

### UI

The Electron UI lives in `ui/`. It shells out to the `ember` CLI binary.

```sh
cd ui
npm install
npm run dev
```

Set `EMBER_BIN` if the CLI isn't at `../build/cli/ember`.

## CLI

```
ember [options] <binary>

  -d, --disasm         linear disassembly of a function
  -c, --cfg            control-flow graph of a function
  -i, --ir             lifted IR of a function
      --ssa            IR in SSA form (implies -i)
  -O, --opt            run cleanup passes (implies --ssa)
      --struct         structured regions (implies -O)
  -p, --pseudo         pseudo-C output (implies --struct)
  -X, --xrefs          emit full call graph (all fn -> call targets)
      --strings        dump printable strings (addr|text|xrefs)
      --arities        dump inferred SysV arity per function
  -s, --symbol NAME    target a specific symbol (default: main)
      --annotations P  read user renames / signatures from a project file
      --project PATH   project file scripts may read/write via project.*
      --script PATH    run a JS file against the loaded binary
      -- ARG...        pass remaining args to the script as argv
      --cache-dir DIR  override ~/.cache/ember
      --no-cache       bypass the on-disk cache
```

`--xrefs`, `--strings`, and `--arities` are cached to `~/.cache/ember/`
(keyed on path + size + mtime). First run is slow; subsequent runs on the
same binary skip the analysis entirely.

## Pipeline

```
ELF   →  decoder  →  CFG       →  IR lift   →  SSA      →
cleanup passes  →  structurer (if/while/switch)  →  pseudo-C
```

x86-64 only. ELF and Mach-O.

## Scripting

`--script PATH` runs a JavaScript file with the loaded binary exposed
through `binary`, `xrefs`, `strings`, and (with `--project`) `project`.

```sh
ember --script scripts/query.js <binary> -- <command> [args...]
```

`scripts/query.js` is a generic dispatcher covering `info`, `imports`,
`sections`, `bytes`, `disasm`, `func`, `pseudo-c`, `xrefs-to`, `callers`,
`callees`, `strings`, `string-xrefs`, `find-func`, `find-bytes`, and more.

Mutations (`project.rename`, `setSignature`, `note`) stage into a pending
buffer; `project.commit()` writes them back to the project file. Every
mutator also accepts `{ dryRun: true }` so agents can preview changes
before committing.

## Layout

```
core/           C++23 library (everything except the CLI shim)
  include/ember/   public headers
  src/
    binary/     ELF + Mach-O loaders
    disasm/     x86-64 instruction decoder
    analysis/   CFG builder, SysV arity inference, strings scanner
    ir/         IR + x64 lifter + SSA builder + cleanup passes
    structure/  region builder (if / while / switch)
    decompile/  pseudo-C emitter
    script/     QuickJS runtime + bindings
    common/     annotations (project file), on-disk cache
cli/            command-line driver
scripts/        JS scripts that run against the CLI (query.js, etc.)
ui/             Electron + React + TypeScript frontend
tests/          golden-output CTest suite
third_party/    vendored deps (QuickJS-NG)
```

## Tests

```sh
cmake --build build -j
ctest --test-dir build
```

Fixtures are small C programs compiled at build time; output is diffed
against checked-in goldens in `tests/golden/`. To accept an intentional
output change:

```sh
UPDATE_GOLDEN=1 ctest --test-dir build -V
```

## Status

Under active development. Output is readable enough to beat hand-reading
x64, but edges are rough — particularly around indirect calls, sub-register
arithmetic corner cases, and switch cases whose default target happens to
lie outside the table's bounds check.

## License

MIT. See [LICENSE](LICENSE). QuickJS-NG (vendored under `third_party/quickjs/`)
is also MIT.
