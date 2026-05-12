# Ember

> *Take a binary. Hand back the program.*

<table>
<tr>
<td width="50%" valign="top">

**`gotos.c`** — the source

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

**`ember -p -s multi_exit gotos`** — the recovery

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

<sub>The right column was reconstructed from a stripped binary. Ember has never seen the source — it walked SSA, collapsed the <code>goto&nbsp;fail</code> ladder into early returns, forwarded the spilled parameters, and rendered <code>-1</code> as signed even though it lives in a <code>uint64_t</code>-typed slot.</sub>

---

## By omission

What ember refuses to link, vendor, or import:

- **No Capstone.** Own x86-64 decoder. AArch64, PPC32, and PPC64 have decoders too.
- **No Zydis. No Ghidra SLEIGH.** Same reason.
- **No LLVM.** Own IR, own SSA, own cleanup, own structurer.
- **No vendored dependencies.** A C++23 compiler and the standard library. That's it.
- **No DWARF — even when it's right there.** The debugger sets breakpoints against ember's own pseudo-C output. There is no source on disk; ember invents one.
- **No pretending.** When the analyzer can't bottom something out, the output says so out loud — `(*(uint64_t (**)(...))0x...)(...) /* unresolved indirect: ... */`, not a fabricated symbol.

The whole pipeline fits in your head.

---

## The pipeline, in nine arrows

```
binary → loader → decoder → CFG → IR lift → SSA → cleanup → structure → pseudo-C
```

Loader handles ELF, DOL, Mach-O, PE, Microsoft minidump, and raw-region scrapes from packed targets. Cleanup is const-fold, copy-prop, GVN, store→load forward, dead-store elimination, plus a type lattice that propagates through phis. Structurer recovers `if`, `while`, `for`, `switch`, and as a last resort `goto`. Per-function latency is a few milliseconds.

---

## Three things you don't expect

### The debugger speaks pseudo-C

```sh
ember --debug ./target
(ember-dbg) b sub_4000b0:42
```

That breakpoint resolves through ember's own emitter. Line 42 does not exist in any file on disk — it exists in the decompiled view ember just generated, and the asm address it maps to is exactly where execution stops. ptrace on Linux, Mach on macOS. `code` shows the pseudo-C around the current PC; `bt` walks `.eh_frame` with an RBP fallback; `aux` lets you side-load a Binary as a symbol oracle for runtime-mmap'd Mach-O / PE blobs.

### It recognizes library functions across compilers

```sh
ember --teef libcrypto.so.3 > corpus.tsv
ember --recognize --corpus corpus.tsv ./stripped-target
```

Three signals stacked: a CFG-shape pre-filter, a post-cleanup IR canonical with MinHash for partial overlap, and a behavioural signature that runs K=64 random inputs through an abstract IR interpreter and hashes the I/O multiset. The behavioural pass catches what canonicalization can't — pointer-vs-index lowering, intrinsic-vs-open-coded (bswap, popcnt, …), induction-variable strength reduction, gcc ↔ clang divergence.

> **100% precision, 34.4% recall** on the cross-config probe2 matrix
> (6 compiler configurations × 30 algorithms, 30 directed pairs).
> Real cross-binary: `sha256sum` corpus → `md5sum` recovers every named
> gnulib helper at confidence 1.0, zero false positives.

### It listens to runtime evidence

When static analysis can't bottom out an indirect call, hand ember a TSV of observed edges. Compare the same wrapper without and with `--trace`:

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

The first observed target names the expression; the rest stay attached as a comment so dynamic evidence is never silently lost.

---

## Receipts

|                       | x86-64                | AArch64           | PPC32 / PPC64 |
|---                    |---                    |---                |---            |
| Loader                | ELF / Mach-O / PE / minidump / regions | ELF / Mach-O | ELF32 / ELF64 / DOL |
| Decoder + IR lift     | full                  | partial           | partial       |
| SSA + cleanup         | full                  | partial           | partial       |
| Pseudo-C              | full                  | partial           | partial       |
| ABI                   | SysV / Win64          | AAPCS64           | SysV / ELFv1 / v2 |
| RTTI                  | Itanium + MSVC        | Itanium           | —           |
| Switch idioms         | 5 patterns (incl. MSVC two-table) | inherited | — |
| Indirect calls        | IAT + const vtable + trace + IPA receiver-type | inherited | CTR constants + trace |

---

## Honest cracks

Limits, not bug reports:

- Indirect calls without IAT, constant vtable, trace observation, or receiver-type fact still render as typed unresolved function-pointer-slot calls with an evidence comment. By design — see *By omission*.
- Switch cases whose default falls outside the bounds check can misattribute.
- AArch64 floating-point and Advanced SIMD are decoded shape-only and lift as `arm64.<op>(...)` intrinsics. SVE / SME unmapped.
- PPC32/PPC64 lifting is intentionally small: scalar GPR/control-flow basics, DOL function discovery, and code-pointer xrefs.
- Itanium demangle is comprehensive; MSVC demangle is partial.
- C++ stdlib name simplification (`std::__cxx11::basic_string<…>` → `std::string`) uses a fixed alias table; uncommon container/allocator instantiations stay long.

---

<details>
<summary><b>Build &amp; run</b></summary>

C++23 (gcc 16+ or recent Clang) and CMake 3.28+:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/cli/ember --help
```

UI:

```sh
cd ui && npm install && npm run dev
```

Set `EMBER_BIN` if the CLI isn't at `../build/cli/ember`.

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

      --ipa              run IPA before pseudo-C (typed sigs across calls)
      --resolve-calls    resolve indirect calls (IAT + constant vtables)
      --eh               parse unwind tables, mark landing pads
      --list-syscalls VA report each `syscall` site in the function at VA
      --debug            launch / attach a debugger; see docs/debugger.md

  -s, --symbol NAME      target a specific symbol (default: main)
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
      --apply-patches F  apply (vaddr_hex, bytes_hex) patches to the binary
      --trace PATH       observed indirect edges (TSV: from_va  to_va)
      --cache-dir DIR    override ~/.cache/ember
      --no-cache         bypass the on-disk cache
```

Heavyweight passes (`--xrefs`, `--strings`, `--arities`, `--fingerprints`) cache to `~/.cache/ember/` keyed on `path | size | mtime | version`. First run is slow; subsequent runs are instant.

</details>

<details>
<summary><b>Windows runtime images</b></summary>

For packed / protected targets where the on-disk PE is a stub, point ember at a runtime memory image instead:

```sh
# Microsoft minidump (procdump, taskmgr, WinDbg can produce these)
ember -p ./crash.dmp

# Hand-rolled scrape: manifest of (vaddr, size, flags, file) lines
ember --regions ./scrape/regions.txt -p
```

The minidump loader pulls per-module symbols from each module's in-memory PE headers, so imports and exports are named even when the on-disk image was junk. Module-name collisions get prefixed: `kernel32!CreateFileA`.

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
sub_4* -> roblox_sub_*

[delete]
log_handler = all                  # drop rename + note + signature
```

Section-keyed, one directive per line, no expressions or control flow. Anything that needs decisions (walk callees, drive renames from CFG shape) consumes the public `Annotations` API from a one-off C++ tool linked against `ember::core`. Full surface in [docs/scripting.md](docs/scripting.md).

</details>

<details>
<summary><b>Agent harness</b></summary>

`agent/` is a TypeScript multi-agent driver. Workers run a single role — namer / mapper / typer / tiebreaker — as an LLM tool-use loop, write claims into a shared per-binary intel database (append-only JSONL with retraction + dispute detection), and the orchestrator promotes high-confidence claims into the same `.ember` file `--apply` consumes. Provider-neutral over assistant / OpenAI / OpenRouter, prompt-cache-aware on both assistant-direct (`cache_control: ephemeral`) and DeepSeek-via-OpenRouter (auto-prefix caching reported in `usage.prompt_tokens_details.cached_tokens`), per-worker USD budget cap.

```sh
# 20 namer workers in parallel against a stripped binary
ember-agent fanout --binary=./target.elf --pick=unnamed --limit=20 \
  --budget=0.04 --model=deepseek/deepseek-v4-flash

# Anchor Cascade — bottom-up rounds, each one names fns whose callees
# are mostly anchored, promotes ≥0.85 conf claims, re-renders pseudo-C
# so the next round sees richer context.
ember-agent cascade --binary=./target.elf --per-round=30 --max-rounds=5

ember-agent intel ./target.elf disputes
ember-agent promote ./target.elf --apply
```

Disputes — top-2 claims within 0.10 confidence from different agents with different values — surface for unbiased tiebreaker resolution. Full surface in [docs/agent.md](docs/agent.md).

</details>

<details>
<summary><b>Plugin platform</b></summary>

Target-specific reversing — games, engines, protocols, build-to-build knowledge carryover — is layered onto the Electron UI, not the C++ core. Plugins are `.cjs` bundles (`plugin.json` + `main.cjs`) loaded by the renderer's Node runtime; the surface they consume is the same `Annotations` API the `.ember` format drives. Design in [docs/plugin-platform.md](docs/plugin-platform.md).

</details>

<details>
<summary><b>Layout</b></summary>

```
core/             C++23 library — everything except the CLI shim
  binary/         ELF + DOL + Mach-O + PE + minidump + raw-regions + PDB v7
  disasm/         x86-64 + AArch64 + PPC32/PPC64 instruction decoders
  analysis/       CFG, arity, strings, xrefs, sig inference, type inference,
                  indirect-call resolver, MSVC + Itanium RTTI, eh_frame,
                  PE UNWIND_INFO, ObjC, fingerprints, name resolver,
                  syscall sites, YARA-like identification
  ir/             IR + lifters + SSA + cleanup passes + type lattice
  structure/      region builder
  decompile/      pseudo-C emitter
  debug/          ptrace + Mach backends, .eh_frame + RBP-walk unwinders
  script/         declarative .ember parser + applier
  common/         annotations, on-disk cache
cli/              command-line driver
ui/               Electron + React + TypeScript frontend
agent/            TypeScript multi-agent LLM harness
tests/            golden-output CTest suite
docs/             scripting, debugger, raw-input, plugin platform,
                  agent harness, TEEF Max
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

<p align="center"><sub>MIT — see <a href="LICENSE">LICENSE</a>. Star history at <a href="https://star-history.com/#FlavouredTux/Ember&Date">star-history.com</a>.</sub></p>
