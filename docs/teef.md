# TEEF Max

Library-function recognition that survives compiler-version drift,
optimization-level changes, cross-compiler builds (gcc ↔ clang), and —
within reason — end-to-end function refactors. What FLIRT does for
IDA, without inheriting FLIRT's brittleness to byte-level perturbation.

This is the high-level walkthrough. For wire-format details, schema
strings, and the recognizer's verdict thresholds, see the inline
docstrings on `core/include/ember/analysis/teef*.hpp`.

---

## The problem in one paragraph

You're staring at a stripped binary. Lots of `sub_4012a0` placeholder
names. You'd like to know which of those are `memcpy`, which is
`malloc`, which is `EVP_CIPHER_CTX_new`, etc. FLIRT-style byte
fingerprints solve this for the case where the binary was compiled
with the same toolchain as the signature library. As soon as the
compiler version drifts, or `-O2` becomes `-O3`, or someone turns on
LTO, the bytes change and FLIRT misses entirely. We measured this:
glibc 2.35 vs glibc 2.39 (one year apart, same gcc family) — only
27.8% of functions still byte-match. Anything longer than ~80
instructions falls off the cliff:

| Size       | Byte-match recall |
|------------|-------------------|
| ≤5 inst    | 96.5% |
| 6–20       | 78.0% |
| 21–80      | 12.8% |
| 81–300     |  0.3% |
| > 300      |  0.0% |

Tiny stubs match by accident — their bytes can't change much.
Anything substantive fails. Exactly where you most need help, the
byte-fp gives you nothing.

TEEF is the answer to that. TEEF Max is the answer that also handles
gcc → clang and `-O2` → `-Os`.

---

## Three signals, stacked

For each function we compute three independent fingerprints. They're
listed in order of "shallow but cheap" → "deep but expensive". The
recognizer uses all three; each one fills in cases the others miss.

### L0 — topology hash (CFG shape)

A single u64 derived from six features of the function's control-flow
graph:

```
num_blocks · num_edges · max_in_degree · max_out_degree
   · num_loop_headers · num_returns
```

Cost: ~5 µs/fn. It's just integer arithmetic over the already-built
CFG. Two structurally-identical CFGs collide; small CFG diffs (one
extra cleanup block from inlining) shift the hash.

What it's good for: fast pre-filter. Given a 100K-fn corpus and a
query function, the corpus index `{topo_hash → [entry_idx]}` lets
the recognizer say "out of 100K, only 12 corpus entries have this
shape — only score those" without touching content. It's lossy
(misses cross-shape matches) but never rejects a candidate; it's
purely a way to look in the right place first.

### L2 — cleanup-canonical hash (the original TEEF)

Hash of the structured IR token stream after lift → SSA → cleanup →
structurer. Plus an 8-slot MinHash sketch over canonical token bigrams
for partial-overlap recovery.

Walk the structured Region tree (the same tree the pseudo-C emitter
walks) and emit one canonical token per node. SSA temps and registers
get alpha-renamed in first-appearance order, so `mov rax, rbx` and
`mov rdi, rsi` hash the same as `mov v_0, v_1` — they're the same
shape under different naming. Immediates split into two classes:
small literals (≤ 0x10000, kept verbatim because they're identifying
— bit masks, syscall numbers, struct offsets) and addresses (resolved
to PLT/GOT/symbol names where possible, otherwise an `ADDR` class
token).

Anchor names — calls to named imports, named intrinsics — are kept
verbatim *and weighted 3×* in the token stream. A function calling
`malloc + free + memcpy` has a more discriminating identity than two
unrelated functions sharing reg-arith patterns; the anchor weighting
ensures the named calls dominate the hash and the MinHash slots.

What L2 catches: same-source, same-compiler, similar-opt builds. Most
"normal" recognize lookups hit L2 as `whole-exact` (1.0 confidence)
or `whole-jaccard` (0.875+ jaccard). What it misses: cross-compiler
builds where one compiler picks a different lowering, and any
loop-shape transformation (gcc -O2 strength-reduces an induction
variable; gcc -Os doesn't).

### L4 — behavioural fingerprint (the loop-shape-invariant signal)

The big idea: if two functions compute the same answer on the same
inputs, they're behaviourally equivalent — even if their IR is
totally different shape. So instead of hashing the IR, we run it.

For each function we sample K = 64 random argument vectors. Each vector
sets `rdi/rsi/rdx/rcx/r8/r9` (SysV ABI argument registers) to values
drawn from a deliberately diverse distribution: zero, one, all-ones,
small ints, large random, pointer-shaped (heap-ish addresses), byte-
masked. Then we run the function under an abstract-state IR
interpreter:

- **Memory** is a lazy dictionary. First load from address `A` returns
  `mix64(A, salt)`; subsequent loads from `A` return the same value.
  Stores update the dict. This way memory is *deterministic* — two
  compilations of the same source see the same memory contents under
  the same input vector — but no actual binary memory is touched.
- **Calls** to direct imports return `mix64(target_class, sorted_args)`
  — deterministic by signature.
- **Branches** on concrete conditions follow the natural path. Branches
  on synthesized values (rare) follow the first successor.
- **Intrinsics** with known semantics (`bswap`, `bsr`, `bsf`, `popcnt`,
  `mulh.{s,u}.64`, `divq.{s,u}.64`, `divr.{s,u}.64`, `parity`,
  `unordered_fp_compare`) are computed precisely. So clang's
  `bswap` intrinsic and gcc's open-coded `((x >> 24) | ...)` produce
  the same trace value.

Each completed trace yields a u64 outcome combining the input seed,
the return value, and a hash of the side-effect multiset (calls and
stores observed). 64 traces per function → MinHash[8] sketch + a
single 64-bit exact hash of the sorted multiset.

What L4 catches that L2 can't:

- **Loop shape changes**. gcc -O2 might compile `sum_array` with a
  pre-computed end pointer and pointer-walk. gcc -Os might keep an
  index counter and address arithmetic. Both compute the same sum
  for the same input array → same L4 hash. L2 sees two completely
  different IR shapes and gives up.
- **Algorithmic variants**. `popcount_swar` (bit-twiddling SWAR
  pattern) and `popcount_loop` (while-loop counting set bits) have
  *radically* different IR — but the same I/O behaviour. Same L4
  hash.
- **Compiler-emitted intrinsics**. `bswap`, `popcnt`, `lzcnt`,
  `bsr`/`bsf` get lowered by some compiler+arch combinations but not
  others. The intrinsic semantic modeling above means open-coded and
  intrinsic versions agree.

What L4 doesn't catch: functions that compute *genuinely different
things*. A real win, not a workaround.

---

## How recognize uses the cascade

`ember --recognize` runs each query function through this pipeline of
match paths, in order. The first one to fire returns; later paths
only run if earlier ones didn't reach the confidence floor.

1. **behav-exact** — L4 hash collision against the corpus index.
   Highest precision: an accidental 64-trace I/O collision between
   two semantically-distinct functions is vanishingly rare. A `behav-
   exact` match emits at confidence 1.0. A bucket of >4 same-L4
   entries triggers the popularity guard — too many collisions = the
   hash is a "trivial-shape behaviour" (return-zero, identity stub)
   and we don't pick a single canonical name.

2. **whole-exact** — L2 hash collision. Confidence 1.0 when the
   bucket has one unique name; ties surface as `whole-exact-tied`
   at `1/N` confidence.

3. **whole-jaccard+behav** — combined L2+L4 jaccard scoring. Built
   on top of an L2 *MinHash inverted index*: for each of the 8 L2
   MinHash slots, the corpus has a bucket `slot_value → entry_idxs`.
   The query's 8 slot lookups produce candidates with hit counts;
   entries hit in ≥ 2 of 8 slots get scored. Score is
   `0.5 · L2_jaccard + 0.5 · L4_jaccard`; bar 0.6 with 0.20
   second-best margin when L4 corroborates, conservative L2-only bar
   0.875 / 0.25 margin when the query has no L4. The 0.6 bar is
   safe because a strong L4 corroboration (jaccard 1.0) requires
   only L2 jaccard 0.2 to cross — exactly the case L2 alone would
   reject as too weak but L4 confirms is real.

   Falls back to the L0 topo bucket when slot collisions are too
   sparse to cross threshold — small fns where MinHash entropy is
   low and jaccard estimates are noisy.

4. **chunk-vote+behav** — for each query chunk (substantive sub-region
   of a structured function), look up corpus chunks that share its
   exact hash, weight by chunk size, accumulate votes per candidate
   name. Top-voted name wins; the margin `top1 / (top1 + top2)` is
   the confidence. Boilerplate chunks (>6 corpus fns) are dropped.
   When the query has L4 and the top vote winner has corroborating
   L4, the via tag becomes `chunk-vote+behav` and confidence gets a
   +0.25 boost. Useful for big functions whose whole-fn TEEF can't
   see through library-version refactors but whose inner loops stay
   stable.

A typical match line in the output:

```
21ca   error           error          1.000   behav-exact
237c   error_at_line   error_at_line  1.000   behav-exact
```

`addr  current_name  suggested_name  confidence  via  [alt=conf...]`.

---

## Performance: corpus build

The full pipeline (lift → SSA → cleanup → L4 traces → structurer)
runs once per function via `compute_teef_max`. Per-fn cost is
~10–15 ms with all signals computed. Parallelized across cores at
the CLI.

| Binary | Fns | Wall time | After all optimizations |
|---|---|---|---|
| /usr/bin/grep | 289 | 0.19 s | (was 1.28 s pre-opt) |
| /usr/bin/find | 328 | 0.24 s | (was 2.30 s) |
| /usr/bin/eu-readelf | 482 | 0.60 s | (was 4.71 s) |
| /usr/bin/dolphin | 3288 | 1.79 s | (was 14.74 s) |

Optimizations stacked:

- **Shared pipeline**: `compute_teef_max` runs lift+SSA+cleanup once
  and forks into both L2 (structurer + region tokenization) and L4
  (trace pass), instead of running the pipeline twice. ~3× wall.
- **Sub_\* skip**: `--teef` (corpus build mode) drops the L4 pass
  for unnamed functions — `TeefCorpus::load_tsv` discards them
  anyway after counting their L2 popularity, so computing L4 is
  pure waste. Additional 2–3× on stripped libraries.
- **`--min-fn-size N`**: drops fns smaller than N bytes before
  fingerprinting. Obfuscator-spawned binaries (Themida, Lua-VM,
  hellgate-style) emit hundreds of thousands of trivial sub-32-byte
  stubs. Filter cuts work proportionally. CFG-discovered fns whose
  size is unknown get a gap-derived size estimate (distance to the
  next discovered fn) so the filter still applies on stripped code.

Live progress UI (TTY-only):

```
fingerprint [12300/467000] 1820 fn/s · elapsed 6.8s · eta 250s
```

Tells you immediately whether throughput is steady or one giant
function is dominating.

---

## Performance: corpus load + recognize

Corpus TSV files for a 4-library combo (libcrypto + libssl +
libstdc++ + libc) total ~80 MB / 1.4M rows. Load is mmap'd and
parallel-parsed:

```
ember: corpus libcrypto.tsv: 35.2 MB / 666973 rows
       (mmap+pre 0ms · parse 89ms ×16 · merge 178ms · total 267ms)
ember: corpus loaded: 41200 fns / 8421 chunks across 4 TSVs
       (1398470 rows) in 564 ms
```

The phase breakdown shows mmap setup, parallel parse (with thread
count), and serial index merge separately. Helps spot if one phase
is misbehaving.

Recognize-time scan is the bulk of `--recognize` cost on big
corpora. Worst case before optimization was an O(N) full jaccard
scan per query fn — minutes on a 100K-fn corpus, 11+ minutes on the
4-library combo with libroblox queries. Now there's an L2 MinHash
inverted index built at load time (`whole_minhash_[k] : slot_value →
[entry_idx]` for k ∈ [0,8)). At query time we look up each of the 8
slots, count per-entry hits, and only score entries with ≥ 2 slot
hits. Reduces O(N) full-scan to O(slot_bucket × 8). Slot values that
match more than 5000 entries are skipped (set with
`EMBER_TEEF_MAX_SLOT_BUCKET`) — popular trivial bits.

Live progress + ETA on the scan:

```
recognize [40000/43109] 4521 fn/s · elapsed 8.8s · eta 0.7s
```

Match output streams as it's produced (under a stdout mutex), not
buffered to the end. You see results in completion order, not
addr-sorted; `| sort -n` if you want sorted.

---

## CLI

### Build a corpus

```sh
ember --teef <library>                       # write corpus to disk cache
ember --teef --no-cache <library> > foo.tsv  # write corpus TSV to a file
ember --teef --min-fn-size 32 <library>      # drop tiny stubs first
```

Outputs a TSV with `F` rows (one per fn), `S` rows (per-fn reachable
strings), and `C` rows (per-fn structured chunks). 24-field `F` row,
keyed by the schema string `kTeefSchema = "max.2"`. Cache lives at
`~/.cache/ember/<binary-key>/teef-max.2`.

`scripts/build_corpus_linux_x86.sh` builds a Linux x86-64 corpus
covering glibc, libstdc++, libgcc_s, libm, libpthread, libssl,
libcrypto, libz, libzstd, libbz2, libxxhash, plus Rust std and a
broad-API extractor that surfaces concrete std-fn instantiations.

`scripts/build_corpus_windows.sh` is the equivalent for PE32+
targets — needs **real Microsoft** DLLs from a Windows install or
symbol server (Wine reimplementations produce false negatives, the
script refuses by default).

### Recognize

```sh
ember --recognize --corpus libcrypto.tsv --corpus libssl.tsv <binary>
ember --recognize --corpus libcrypto.tsv --recognize-threshold 0.7 <binary>
ember --recognize --l0-prefilter --corpus ... <binary>      # speedup, lossy on cross-opt
ember --recognize --min-fn-size 32 --corpus ... <binary>    # drop stubs first
```

Output rows:

```
<addr>  <current_name>  <suggested_name>  <confidence>  <via>  [alt=conf, alt=conf]
```

`<via>` is one of:

| via | meaning |
|---|---|
| `behav-exact` | L4 multiset-hash collision (highest precision) |
| `behav-exact-tied` | L4 collision with multiple distinct names |
| `whole-exact` | L2 cleanup-canonical hash collision |
| `whole-exact-tied` | L2 collision with multiple distinct names |
| `whole-jaccard+behav` | L2+L4 combined jaccard above threshold |
| `whole-jaccard` | L2 jaccard alone (query had no L4) |
| `chunk-vote+behav` | chunk vote with L4 corroboration on the winner |
| `chunk-vote` | chunk vote alone |

### Tuning

| Flag | Default | What it does |
|---|---|---|
| `--recognize-threshold T` | 0.6 | Confidence floor for emitting a match |
| `--min-fn-size N` | 0 | Drop fns smaller than N bytes before fingerprinting |
| `--l0-prefilter` | off | Skip L4 on target fns whose L0 isn't in the corpus. Fast on obfuscator-heavy targets, lossy on cross-opt-level matches. |
| `--no-cache` | — | Bypass disk caches (corpus TSV + target fingerprint TSV both cache by `path \| size \| mtime \| version`) |

| Env var | Default | What it does |
|---|---|---|
| `EMBER_TEEF_MAX_INSNS` | 4096 | Per-fn IR insn cap; huge VMP fns past this skip L2 |
| `EMBER_TEEF_MAX_SLOT_BUCKET` | 5000 | Skip MinHash slot values matching more entries than this (popular trivial bits) |
| `EMBER_BEHAV_DEBUG` | off | Log every L4 trace abort with reason |
| `EMBER_QUIET` | off | Suppress all stderr progress / phase output |

---

## TSV schema (kTeefSchema = "max.2")

Tab-separated rows. First field is the row-type tag.

```
F  addr  L2_exact  L2_mh*8  name  L4_exact  L4_mh*8  L4_done  L4_aborted  topo_hash
                                                                          (24 fields)

S  addr  hash1,hash2,...
                                  (per-fn reachable strings)

C  addr  region_kind  inst_count  exact_hash  mh*8  name
                                  (per-fn substructure)

T  runtime  <tag>
                                  (runtime ABI tag; applies to subsequent F/C rows)
```

Schema string `kTeefSchema` is folded into every hash so corpora
built under different schemas can't silently collide. Bumped on
F-row layout or rule-set changes; old caches are orphaned but
harmless.

Runtime tags in current use:

| Tag | Identifier patterns |
|---|---|
| `rust` | `_R`-mangled, `__rust_*` |
| `libstdcxx` | `_ZSt…`, `_ZNSt…` |
| `cxx` | other `_Z`-mangled |
| `libc` | glibc / musl |
| `openssl` | libssl / libcrypto |
| `c` | plain C (libgcc_s, libm, libz, …) |
| `msvcrt` / `ucrt` / `vcruntime` | Windows C runtimes |
| `cxxmsvc` | MSVC's C++ stdlib |
| `winapi` | kernel32 / ntdll / user32 / etc |

The recognizer auto-detects the query binary's runtime and refuses
implausible cross-language matches (Rust ↔ libstdc++, Itanium C++ ↔
MSVC C++). C-family runtimes match each other freely (memcpy is
memcpy regardless of POSIX or Windows source).

---

## Validation

### Cross-config recognize matrix

probe2.c — 30 algorithms (string ops, hashes, sorts, search, bit
twiddling, parsing, switch dispatch). Compiled across 6 configs:
gcc -O0/-O2/-O3/-Os, clang -O2/-O3. For each pair (corpus_config,
target_config), build corpus from one, recognize against the other,
score against debug names.

```
30 directed cross-config pairs:
  correct       361 / 1050 named-pool entries
  recall        34.4%
  precision     100%   (0 false positives)
  via breakdown:
    behav-exact          306
    whole-jaccard+behav   47
    chunk-vote            24
    whole-exact           11
    chunk-vote+behav       2
```

The behav-exact path carries 90%+ of the load. Cross-compiler unique
wins (matches present in TEEF Max but not in pure-L2):
`strchr_byte`, `strstr_naive`, `gcd_iter`, `popcount_swar`,
`count_set_bits`, `strcmp_like`, `sum_array`, `dot_product`,
`fnv1a_hash` — fns where L2 alone misses because of compiler
diversity in loop shape or intrinsic emission.

### Real cross-binary

`/usr/bin/sha256sum` corpus → `/usr/bin/md5sum` target: 2/2 named
gnulib helpers (`error`, `error_at_line`) recognized via behav-exact
at confidence 1.0. The two binaries are stripped on Arch, so most
fns are sub_*; only the externally-named gnulib functions are
verifiable, but those work.

False-positive sanity: probe2 corpus → /usr/bin/find with no real
overlap: **0 matches** at threshold 0.6.

### glibc 2.35 → 2.39 (the original validation)

Per-bucket recall on the original (pre-Max) TEEF, now superseded by
the cross-config matrix above:

| Bucket | Byte-fp | Whole TEEF | + Chunk vote (top-1) | + top-3 |
|---|---|---|---|---|
| tiny (≤5 inst) | 96.5% | 51.3% | 51.3% | 51.3% |
| small (6–20) | 78.0% | 80.1% | 80.3% | 80.3% |
| medium (21–80) | 12.8% | 26.1% | 39.4% | 40.9% |
| large (81–300) | 0.3% | 6.2% | 28.8% | 35.7% |
| huge (>300) | 0.0% | 1.3% | 19.4% | 28.6% |

TEEF Max numbers on the same setup will be higher across the board
once the corpus is rebuilt under the v6 schema; the medium / large /
huge buckets specifically benefit from L4.

---

## What's still hard

**Heavy obfuscation**. VMProtect, Themida virtualization, and Lua-VM-
style interpreters expand each original fn into thousands of junk-
injected dispatcher steps. The `EMBER_TEEF_MAX_INSNS=4096` gate
short-circuits L2 on those, and L4's per-trace `kBehavMaxInsnsTrace`
similarly bounds the interpreter. Output: empty fingerprint, zero
match. `--min-fn-size 32` reduces the noise but doesn't recover the
content. Defeating these is a separate research problem (orbit-class
fingerprinting via e-graph saturation lives in `core/src/analysis/
egraph.cpp` as a building block, but isn't yet on the recognize
critical path).

**`-O0` ↔ optimized cross-config matches**. Unoptimized code keeps
every IR insn in its naive form so cross-flag overlap collapses.
Real-world recognize doesn't usually face this case (people don't
ship `-O0` libraries) but the cross-config matrix shows 0% recall
on `gO0 → gO2` pairs.

**Cross-architecture**. The L2 hash is alpha-renamed but reg names
are in arch-specific encoding. AArch64 ↔ x86-64 fingerprint matching
isn't done yet — the canonical-role-tag refactor (arg0..arg5,
ret0..ret1, stack) lives in the design doc but not in the lifter
output.

---

## Internal layout

| File | What |
|---|---|
| `core/include/ember/analysis/teef.hpp` | `TeefSig`, `TeefFunction`, `TeefChunk`, schema |
| `core/include/ember/analysis/teef_behav.hpp` | L4 surface (`BehavSig`, `compute_behav_sig`) |
| `core/include/ember/analysis/teef_recognize.hpp` | `TeefCorpus`, `TeefMatch` |
| `core/src/analysis/teef.cpp` | L2 + L0; `compute_teef_max` (shared pipeline) |
| `core/src/analysis/teef_behav.cpp` | L4 interpreter, intrinsic semantic modeling |
| `core/src/analysis/teef_recognize.cpp` | Corpus load (mmap+parallel parse), recognize cascade, MinHash inverted index |
| `core/src/analysis/teef_orbit.cpp` | E-graph orbit-class fingerprint (foundation, not on critical path) |
| `core/src/analysis/egraph.cpp` | Bounded e-graph saturation engine |
| `cli/src/subcommands.cpp` | `--teef` / `--recognize` / `--orbit-dump` drivers |

Self-contained unit tests in `tests/egraph_test.cpp` cover the
e-graph core (hash-cons, congruence closure, every rule family,
budget bail-out). The TEEF-itself behaviour is validated through
the cross-config matrix in `/tmp/ember_orbit_exp/` and the existing
golden tests in `tests/golden/`.
