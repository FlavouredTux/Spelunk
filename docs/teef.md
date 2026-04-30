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
