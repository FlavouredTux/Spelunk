<p align="center">
  <img src="docs/mascot.png" alt="Ember" width="360">
</p>

<h1 align="center">Ember</h1>

<p align="center">
  <a href="https://github.com/FlavouredTux/Ember/actions/workflows/ci.yml">
    <img src="https://github.com/FlavouredTux/Ember/actions/workflows/ci.yml/badge.svg?branch=main" alt="ci">
  </a>
  <img src="https://img.shields.io/badge/C%2B%2B-23-blue.svg" alt="C++23">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT">
  <img src="https://img.shields.io/badge/deps-stdlib--only-success.svg" alt="stdlib only">
</p>

A from-scratch reverse-engineering toolkit. ELF + Mach-O + PE loaders,
Microsoft minidump + raw-region memory image loaders, an x86-64
decoder/lifter/SSA pipeline, structurer, pseudo-C emitter, a QuickJS
scripting surface, and an Electron UI.

**No Capstone. No Zydis. No Ghidra. No LLVM.** Stdlib only — QuickJS-NG
(MIT) is the one vendored dep, for scripting.

![welcome screen](docs/welcome.png)
![decompiler view](docs/main.png)

---

## What's in the box

| Area | x86-64 ELF | x86-64 Mach-O | x86-64 PE / minidump | PPC64 ELF |
|---|---|---|---|---|
| Loader            | ✅          | ✅          | ✅ + dumps  | ✅ |
| Decoder + IR lift | ✅          | ✅          | ✅          | partial |
| SSA + cleanup     | ✅          | ✅          | ✅          | — |
| Pseudo-C output   | ✅          | ✅          | ✅          | — |
| ABI modeling      | SysV        | SysV        | Win64       | ELFv1/v2 |
| Imports/exports   | PLT/GOT     | LC dyld     | IAT + delay | — |
| Symbols recovery  | dynsym      | LC_SYMTAB   | export dir + PDATA | dynsym |
| Unwind info       | eh_frame    | LSDA pads   | UNWIND_INFO | — |
| RTTI              | Itanium     | Itanium     | MSVC        | — |
| Demangle          | Itanium     | Itanium     | MSVC partial | — |
| Indirect calls    | IAT + vtable* | IAT + vtable* | IAT + vtable* | — |
| Switch idioms     | 5 patterns  | 5 patterns  | 5 patterns (incl. MSVC two-table) | — |

<sub>* `--resolve-calls` is opt-in; fires on constant vtables today.
Receiver-typed dispatch is gated on the IPA work in progress.</sub>

## Build

C++23 compiler (gcc 15+ or recent Clang) and CMake 3.28+.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/cli/ember --help
```

### UI

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
      --validate NAME    where does NAME live + similar lookalikes
      --collisions       names / fingerprints bound to >1 address

      --ipa              run IPA before pseudo-C (typed sigs across calls)
      --resolve-calls    resolve indirect calls (IAT + constant vtables)
      --eh               parse unwind tables, mark landing pads

  -s, --symbol NAME      target a specific symbol (default: main)
      --annotations P    user renames / signatures sidecar file
      --project PATH     project file scripts may read/write via project.*
      --script PATH      run a JS file against the loaded binary
      -- ARG...          pass remaining args to the script as argv

      --regions PATH     load via raw-region manifest (Scylla-style scrape)
      --apply-patches F  apply (vaddr_hex, bytes_hex) patches to the binary
      --cache-dir DIR    override ~/.cache/ember
      --no-cache         bypass the on-disk cache
```

Heavyweight passes (`--xrefs`, `--strings`, `--arities`, `--fingerprints`)
cache to `~/.cache/ember/`, keyed on `path | size | mtime | version`.
First run is slow, subsequent runs are instant.

## Pipeline

```
binary  →  loader (ELF / Mach-O / PE / minidump / regions)
        →  decoder
        →  CFG
        →  IR lift (x64 / PPC64)
        →  SSA
        →  cleanup (const-fold, copy-prop, GVN, store→load forwarding, DSE)
        →  local type inference   ─┐
        →  IPA (typed signatures) ─┴─ optional, opt-in
        →  structurer (if / while / for / switch / goto fallback)
        →  pseudo-C emitter
```

x86-64 has the full pipeline. PPC64 currently supports loading,
metadata, disassembly, and CFG-oriented browsing.

## Windows runtime images

For packed / protected targets where the on-disk PE is a stub, point
Ember at a runtime memory image instead:

```sh
# A Microsoft minidump (.dmp). procdump, taskmgr, WinDbg can produce these.
ember -p ./crash.dmp

# Or a hand-rolled scrape: a manifest of (vaddr, size, flags, file) lines
# pointing at .bin region dumps.
ember --regions ./scrape/regions.txt -p
```

The minidump loader pulls per-module symbols from each module's
in-memory PE headers, so imports and exports get named even when the
on-disk image was junk. Module-name collisions get prefixed:
`kernel32!CreateFileA`.

## Scripting

`--script PATH` runs a JS file with the loaded binary exposed through
`binary`, `xrefs`, `strings`, and (with `--project`) `project`.

```sh
ember --script scripts/query.js <binary> -- find-bytes "b8 ?? ?? ?? c3"
ember --script scripts/query.js <binary> -- pseudo-c main
ember --script scripts/query.js <binary> -- xrefs-to 0x401050
```

`scripts/query.js` is a generic dispatcher covering `info`, `imports`,
`sections`, `bytes`, `disasm`, `func`, `pseudo-c`, `xrefs-to`,
`callers`, `callees`, `strings`, `string-xrefs`, `find-func`,
`find-bytes`, and more.

Mutations (`project.rename`, `setSignature`, `note`, `defineStruct`,
`refineType`) stage into a pending buffer; `project.commit()` writes
them back. Every mutator accepts `{dryRun: true}` for previews.

Full surface in [docs/scripting.md](docs/scripting.md).

## Plugin platform

The scripting surface is the foundation for a plugin ecosystem aimed at
target-specific reversing — games, engines, protocols, build-to-build
knowledge carryover. Plugins are `.cjs` bundles
(`plugin.json` + `main.cjs`) loaded by the Electron UI through the same
script API. Design in [docs/plugin-platform.md](docs/plugin-platform.md).

## Layout

```
core/             C++23 library — everything except the CLI shim
  include/ember/  public headers
  src/
    binary/       ELF + Mach-O + PE + minidump + raw-regions loaders
    disasm/       x86-64 + PPC64 instruction decoders
    analysis/     CFG, arity, strings, xrefs, sig inference (IPA),
                  type inference, indirect-call resolver, MSVC + Itanium
                  RTTI, eh_frame, PE UNWIND_INFO, ObjC, fingerprints
    ir/           IR + lifters + SSA + cleanup passes + type lattice
    structure/    region builder (if/while/for/switch/goto)
    decompile/    pseudo-C emitter
    script/       QuickJS runtime + bindings
    common/       annotations, on-disk cache
cli/              command-line driver
scripts/          JS scripts consumed by --script (query.js, names.js, …)
ui/               Electron + React + TypeScript frontend
tests/            golden-output CTest suite
docs/             scripting, plugin platform, mascot, screenshots
third_party/      vendored deps (QuickJS-NG)
```

## Tests

```sh
cmake --build build -j
ctest --test-dir build
```

Fixtures are small C programs compiled at build time, plus hand-built
ELF/Mach-O/PE/minidump generators in `tests/fixtures/` so CI runs on
Linux without needing macOS / Windows toolchains. Output is diffed
against checked-in goldens in `tests/golden/`. To accept an
intentional change:

```sh
UPDATE_GOLDEN=1 ctest --test-dir build -V
```

CI runs in a `gcc:15` container so goldens are toolchain-stable.

## Status

Active. The pipeline is solid enough to beat hand-reading x86-64 on
real binaries; pseudo-C output is generally readable and improves
visibly with `--ipa --resolve-calls --eh` on. Known rough edges
(intentionally documented):

- Indirect calls without IAT or constant-vtable shape still render as
  `(*(u64*)0x...)(...)`. Receiver-typed dispatch needs the in-progress
  IPA work to flow class types into call sites.
- Sub-register arithmetic corners can look clunky.
- Switch cases whose default falls outside the bounds check can
  misattribute.
- PDB ingestion is not implemented yet — Microsoft binaries with
  symbols still render with synthesised names.

## License

MIT. See [LICENSE](LICENSE). QuickJS-NG (vendored under
`third_party/quickjs/`) is also MIT.
