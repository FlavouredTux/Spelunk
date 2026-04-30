# TEEF — Tree-Edit Equivalence Fingerprint

Library-function recognition that survives compiler version drift,
optimization-level changes, and (within reasonable limits) end-to-end
function refactors. Designed to do for ember what FLIRT does for IDA,
without inheriting FLIRT's brittleness to byte-level perturbation.

## Why not FLIRT-style byte sigs

FLIRT identifies a function by hashing its bytes and matching against
pre-computed signatures of library functions. It works great when the
binary you're looking at was compiled with the same compiler+version
and same optimization flags as the sigs were built from. As soon as
those drift — gcc 13 → 14, `-O2` → `-O3`, LTO turning on, PGO
reordering blocks — the bytes change and the sig misses entirely.

We measured this empirically. Full fingerprint of glibc-2.35 vs
glibc-2.39 (one year apart, same gcc family) shows 27.8% exact-byte
match across all functions. The remaining 72% are FLIRT-class misses
even though the *source code* of nearly every function is unchanged.
By size:

| Size       | Byte-match recall |
|------------|-------------------|
| ≤5 inst    | 96.5% |
| 6-20       | 78.0% |
| 21-80      | 12.8% |
| 81-300     |  0.3% |
| >300       |  0.0% |

Tiny functions (return-stubs, single-call thunks) match by accident —
their bytes can't really change. Anything substantial fails. The
medium / large / huge buckets — exactly where users actually want
help — get nothing.

## TEEF: hash the structured IR

Bytes are downstream of every compiler decision. The actual *source*
is upstream of compiler choices but isn't recoverable from a stripped
binary. The closest thing to source we can recover is the structured
IR after ember's lift → SSA → cleanup → structurer pipeline. That's
the layer TEEF hashes.

Per-function we produce two things:

- **64-bit exact hash** of the canonicalized token stream
- **8-slot MinHash sketch** over canonical bigrams, for Jaccard
  similarity matching when the exact hash misses

### Canonicalization

Walk the structured Region tree (the same one the emitter would walk)
and emit one canonical token per node:

- **Region kind** for IfThen / IfElse / While / DoWhile / For / Loop /
  Switch / Block / etc., plus open/close delimiters.
- **IR opcode** (Add, Load, Call, Phi, ...) for each instruction.
- **Operand shape** for each value:
  - `Reg` / `Temp` → alpha-renamed in first-appearance order.
    Tells `mov rax, rbx` and `mov rdi, rsi` apart from each other but
    not from `mov v_0, v_1`, which is exactly what we want.
  - `Imm` ≤ 0x10000 → kept literal (bit masks, struct offsets,
    syscall numbers, TLS slot offsets — actual identifying signal).
  - `Imm` > 0x10000 → resolved via PLT / GOT / defined-object lookup
    to a stable name token, falling back to `ADDR` class. So a
    `call 0x401234` to `__lll_lock_wait_private` hashes the same
    in every binary that imports that symbol.
  - `Flag` → flag name (zf vs cf vs of).
- **Type tag** (`i32`, `i64`, ...) on every value — distinguishes
  `Add i32` (likely an int) from `Add i64` (likely a pointer offset).
- **Segment register** when present (`fs:` for TLS, `gs:` for PEB).

Anchor names (callee names, intrinsic names, defined symbol names)
are kept verbatim — they're what makes `printf` recognizable across
versions even when its body was rewritten.

### Sub-function chunks

Big functions get refactored end-to-end between library versions —
single-thread fast paths get added, error handling gets extracted,
the format-string switch gets reorganized — and whole-function TEEF
can't see through that. But within those functions, individual loops,
switches, and large branches stay structurally identical.

So we *also* hash every chunkable subregion (IfThen, IfElse, While,
DoWhile, For, Loop, Switch) whose subtree contains ≥10 IR instructions.
Each chunk gets its own canonicalizer pass with a fresh alpha-rename
map, so it hashes the same regardless of where it sits in its parent.

A function fingerprint is the pair `(whole_TEEF, set_of_chunk_TEEFs)`.
Matching uses both layers:

1. Exact whole-function match (highest precision)
2. Jaccard on whole-function MinHash ≥ 0.70
3. **Chunk-vote recognition**: each chunk in the unknown function
   votes for the corpus function it appeared in, weighted by chunk
   size. Top-voted name wins; the margin (top1 / (top1+top2)) is the
   confidence score.

## Validation: glibc 2.35 → 2.39

Test setup: take libc6 from Ubuntu 22.04 (glibc 2.35) and Ubuntu 24.04
(glibc 2.39), one year apart. For each named function present in
both, ask whether the algorithm correctly recognizes the 2.39 build
when the 2.35 corpus is the only thing it has to match against.

Recall by IR-instruction-count bucket:

| Bucket            | Byte-fp | Whole TEEF | + Chunk vote (top-1) | + top-3 |
|-------------------|---------|------------|----------------------|---------|
| tiny (≤5)         | 96.5%   | 51.3%      | 51.3%                | 51.3%   |
| small (6-20)      | 78.0%   | 80.1%      | 80.3%                | 80.3%   |
| medium (21-80)    | 12.8%   | 26.1%      | 39.4%                | 40.9%   |
| large (81-300)    |  0.3%   |  6.2%      | 28.8%                | 35.7%   |
| **huge (>300)**   |  0.0%   |  1.3%      | **19.4%**            | **28.6%** |

Tiny shows a regression because the corpus lookup now picks one
arbitrary same-hash hit when many trivial wrappers collide; in real
deployment this surfaces as ambiguous-low-confidence rather than a
real miss. The interesting story is medium/large/huge — TEEF moves
the recall floor from "byte-fp can't do anything" to substantive
recognition, with the vote-fallback specifically rescuing huge
functions where whole-TEEF was useless.

Confidence-thresholded precision/recall on the vote-based recognizer
(margin = top1_score / (top1_score + top2_score)):

| Margin threshold | Precision | Recall (of vote-recoverable) |
|------------------|-----------|------------------------------|
| ≥ 0.50 (any)     | 65.7%     | 100% |
| ≥ 0.70           | 85.3%     | 83.0% |
| ≥ 0.95           | 86.9%     | 78.2% |

A 0.70 threshold gives 85% precision on the surfaced names, which
means the user can mostly trust the auto-renames and easily flag
the rest as "still sub_\*."

## Stride-1 dedup

`enumerate_functions()` on stripped binaries can emit overlapping
shadow entries when the prologue-sweep heuristic fires at consecutive
bytes inside one real function's body. Without a dedup pass,
`--recognize` re-fingerprints each shadow entry and produces dozens of
identical-name hits at a stride of 1 byte (e.g. 126× rows for the
same canonical `_ZSt7getlineIw...` template instantiation).

Fix: walk the discovered set sorted by entry address, keep an entry
only if it's not contained in a previously-kept entry's
`[entry, entry + size)` window. Reported in stderr as
`recognize: dropped N shadow entries (stride-1 dedup)`.

## Anchor-weighted canonicalization

A function calling `malloc` + `free` + `memcpy` has a more
discriminating identity than two unrelated functions sharing some
random reg-arith patterns. Calls to NAMED imports/symbols and
named `Intrinsic` ops are far stronger fingerprint signal than the
surrounding alpha-renamed register arithmetic that dominates the
canonical token stream by volume.

The canonicalizer now repeats anchor-class tokens 3× in the stream:

- `Call` whose target resolves to a PLT/GOT/defined-object name
- `Intrinsic` with a non-empty name (`cpuid`, `rdtsc`, `syscall`, …)

The repetition folds into both the exact 64-bit hash (sequential
FNV over tokens) and the bigram-derived MinHash (more bigrams
involving the anchor → higher chance of dominating the slot
minimums). Unresolved calls (`kClassAddr` fallback when no symbol
lookup hit) get a single token as before — no boost when we can't
tell what's being called.

Schema bumped v4 → v5 to invalidate stale caches; the corpus
build script (`scripts/build_corpus_linux_x86.sh`) regenerates
TSVs with the new fingerprints.

## String anchors

Two functions with identical TEEF structure but disjoint reachable
strings are almost certainly not the same function — different error
messages, different format strings, different path constants. The
recognizer now uses string overlap as a precision filter against
structural false positives.

`ember --teef` collects per-fn reachable strings during the build:
walks `scan_strings(b)`, attributes each xref site to the function
whose `[entry, entry+size)` window covers it (size-0 shadow entries
from the prologue sweep are skipped — their xrefs route to the
containing real fn). Up to 8 strings per fn, length-biased toward
unique ones; each hashed to u64 via `fnv1a_64`.

Stored in the corpus TSV as a new row:

```
S<TAB>addr<TAB>hash1,hash2,...
```

Schema bumped to `v4` so old caches don't silently miss the S rows.
Loader attaches the hashes to `WholeEntry.string_hashes`. At
recognize time, when both query and candidate have ≥2 string hashes
and share zero of them, the candidate is filtered. Conservative: any
side with <2 strings (small fns, EH cleanup, anonymous helpers)
bypasses the filter and structural match remains the sole signal,
preserving recall on cases where strings can't help.

## Cross-language ABI tags

A pure-Rust binary should never hit confidence-1.0 against a libstdc++
template instantiation — the structural similarity that scores high
is just shared compiler-generated EH/cleanup boilerplate, not real
identity. The recognizer now carries an optional runtime/ABI tag per
corpus entry so cross-language matches get filtered.

Corpus TSV format gained one row type:

```
T<TAB>runtime<TAB><tag>
```

Applies to all subsequent F/C rows in the file. Multiple T rows mean
mixed-runtime corpora (rare but supported). Tags in current use:

- `rust` — Rust std (`_R`-mangled, `__rust_alloc`, `__rust_panic`, …)
- `libstdcxx` — GNU libstdc++ (`_ZSt…`, `_ZNSt…`)
- `cxx` — Itanium C++ generally (any `_Z`-mangled but not std::)
- `libc` — glibc / musl
- `openssl` — libssl / libcrypto
- `c` — plain C library (libgcc_s, libm, libz, …)

`scripts/build_corpus_linux_x86.sh` emits the right tag per library
automatically. Old corpus TSVs without any T row remain valid — empty
tag is treated as wildcard (matches every query), preserving the
1.0 release's behavior on existing corpora.

Recognize-side: the query binary's runtime is detected via symbol/
import shape (≥4 `_R` or `__rust_*` → rust; ≥4 `_ZSt` → libstdcxx;
≥8 `_Z` → cxx; otherwise unknown). Mismatched lanes are filtered
across all three match paths (whole-exact, whole-jaccard, chunk-vote).
The Rust↔libstdcxx exclusion is conservative and bidirectional;
Rust↔libc/openssl is allowed because Rust binaries do legitimately
link those.

## Daemon corpus cache

`ember --recognize --corpus PATH+` parses the corpus on every
invocation — typically 50-150 MB of TSV across glibc / libstdc++ /
Rust std / openssl, ~5-15s to load. With `--serve` mode (the agent
daemon path), the corpus is now cached across requests in a static
inside `run_recognize`: identical `--corpus PATH` lists reuse the
in-memory indices, so the second and subsequent recognize calls in
one daemon session pay only the matching cost. The agent's
`ember_recognize` tool benefits directly when cascade is configured
with a corpus.

## What's still hard

Functions over 300 IR instructions whose chunks ALSO got refactored
between versions remain stubborn. Chunk-vote at top-1 hits 19.4% on
the huge bucket; the other 80% really did get rewritten end to end
between 2.35 and 2.39. Sub-chunk fingerprinting (single-BB algorithmic
shapes — AES round, CRC inner loop, strchr-scan) is the natural next
step but requires a different anchor model — single blocks are too
small to be identifying without much stronger anchor gating.

The other open question is corpus build. The current results use a
single (binary, version) per library; for production we'd need a
corpus that spans `{compiler} × {version} × {opt level}` for each
runtime, automatically built in CI. That's operational work rather
than a research question.

## Recognition

`ember --recognize <binary> --corpus PATH+ [--recognize-threshold T]`
fingerprints every function in the target binary and matches it against
one or more pre-built TEEF TSVs (the corpus). For each function with
confidence ≥ T, emits a TSV row:

```
<addr>  <current_name>  <suggested_name>  <confidence>  <via>  [alt=conf, alt=conf]
```

Three matching paths in priority order, all gated by precision:

1. **Whole-function exact hash.** Confidence 1.0. `via=whole-exact`.
   When multiple corpus functions share the hash (a wrapper family),
   emits each at confidence `1/N` with `via=whole-exact-tied`.
2. **Whole-function jaccard ≥ 0.875 AND margin ≥ 0.25 over the
   second-best.** `via=whole-jaccard`. The margin requirement is
   the FP guard — without it, tiny stub functions surface false
   positives by ties at 7/8.
3. **Chunk-vote.** Each query chunk that hits the corpus by exact
   hash contributes its `inst_count` as a vote toward the corpus
   functions that contain that chunk. Chunks appearing in >6
   distinct corpus functions are dropped (boilerplate). The
   suggested name is the top-voted; confidence is the margin
   `top1 / (top1 + top2)`.

The default threshold of 0.85 gives ~83% precision in cross-version
glibc tests; 0.95 raises it toward 87%, with proportionally lower
recall.

### Windows corpus

`scripts/build_corpus_windows.sh` is the equivalent for analyzing
PE32+ Windows binaries (RAT samples, MSVC-compiled malware, retail
Windows apps). It walks a directory of **real Microsoft** Windows
DLLs and tags each with its runtime: `msvcrt`, `ucrt`, `vcruntime`
(modern MSVC support), `cxxmsvc` (msvcp140's std:: surface),
`winapi` (kernel32/ntdll/user32/gdi32/advapi32/shell32/etc), or
plain `c` for everything else.

```sh
# From a Windows install (preferred):
WIN_LIBS=/path/to/Windows/System32 bash scripts/build_corpus_windows.sh

# Or from a Microsoft Symbol Server downloader's output dir.
```

**Do not use Wine's `system32` for the corpus.** Wine's DLLs are
reimplementations of the Win32 API; their internal structure
differs from Microsoft's, so a Wine-built corpus produces
false negatives against real Windows malware. The script
detects Wine prefixes and refuses by default (override with
`FORCE_WINE=1` for script self-testing).

The recognizer's `detect_query_runtime` heuristic already handles
the Windows side: MSVC `?...`-mangled names → `cxxmsvc`,
Win32 imports (`GetProcAddress`/`VirtualAlloc`/`Nt*` etc) → `winapi`,
CRT entry points (`_initterm`/`__chkstk`/etc) → `msvcrt`. Cross-
language exclusion blocks `cxxmsvc` ↔ `libstdcxx` (different ABIs)
and `cxxmsvc` ↔ `rust`. C-family (libc / msvcrt / ucrt / vcruntime /
plain c) match each other freely — `memcpy` is `memcpy`.

### Corpus build

`scripts/build_corpus_linux_x86.sh` builds a Linux x86-64 corpus
covering glibc, libstdc++, libgcc_s, libm, libpthread, libssl,
libcrypto, libz, libzstd, libbz2, libxxhash, plus Rust std and a
broad-API extractor binary that surfaces the concrete std-fn
instantiations Rust binaries actually link in. ~23 K named
functions, ~1.5 M chunks, ~150 MB of TSVs.

For Rust binaries specifically: the `.so` ships with the rustup
toolchain at
`<sysroot>/lib/rustlib/x86_64-unknown-linux-gnu/lib/libstd-*.so` —
that gets fingerprinted directly. The rlib `.o` files we'd extract
on top of that contain mostly generic-only code that's
demand-instantiated; they don't add much to the corpus.

The "extractor" Rust source at `scripts/rust_corpus_extractor/`
is a single Rust program that uses Vec, HashMap, BTreeMap,
HashSet, VecDeque, String formatting, BufReader, BufWriter,
fs::metadata, env::current_dir, Arc, Mutex, RwLock, atomic,
mpsc::channel, threads, iter combinators, sort/binary_search,
Option/Result. Building it with `--release -C debug=2` produces
a binary with thousands of concrete monomorphized std functions
named via the standard Rust mangler (`_RNvCs...` and `_ZN3std...`).
TEEF on that gives us ~2 K Rust-named entries.

Real-world result: a 5 MB `cargo build --release` test binary
recognized **537 functions** at threshold 0.85 against this corpus,
with the top hits being whole-exact matches like
`_RNvCsiGVaDesi5rv_7___rustc17rust_begin_unwind`,
`_ZN9hashbrown3raw13RawTableInner15rehash_in_place`, and
`_ZN3std12backtrace_rs9backtrace9libunwind5trace8trace_fn`.

## CLI

`ember --teef <binary>` emits a TSV with two row types:

```
F  <addr>  <exact_hash>  <mh0..mh7>  <name>
C  <addr>  <region_kind>  <inst_count>  <exact_hash>  <mh0..mh7>  <name>
```

One `F` row per function, plus zero-or-more `C` rows for chunkable
sub-regions. Cached as `teef-v2`. Thread-pooled at the CLI; full
glibc takes ~2 seconds wall clock on 16 cores.

The TSV is the corpus format — index by name, by exact_hash, and by
chunk_hash to support the vote-based matcher described above.
