#pragma once

#include <array>
#include <string_view>
#include <vector>

#include <ember/analysis/teef_behav.hpp>
#include <ember/binary/binary.hpp>
#include <ember/common/types.hpp>

namespace ember {

// TEEF Max — the production fingerprint cascade for ember.
//
// Two complementary signals fold into every corpus row:
//   L2 (this header): hash of the canonicalized post-cleanup IR token
//        stream. Captures structural identity — same algorithm shape
//        across most cosmetic compiler diversity. Single-point hash
//        with a MinHash[8] sketch for partial-overlap recovery.
//   L4 (teef_behav.hpp): hash of the I/O-tuple multiset produced by
//        running the function under K random concrete inputs through
//        an abstract-state IR interpreter. Loop-shape invariant by
//        construction; recovers cross-compiler / cross-flag matches
//        L2's single-point hash misses (induction-variable strength
//        reduction, vectorization, pointer-vs-index lowering).
//
// The recognizer (teef_recognize.hpp) runs CEBin-style two-stage
// retrieval: L2 narrows candidates, L4 verifies/re-ranks. Behavioural
// exact-match is the highest-precision path; L4-corroborated
// whole-jaccard recovers near-matches that L2 alone wouldn't trust.
//
// Schema string is folded into every hash so corpora produced under
// different rule sets can't silently collide. Bumped on F-row format
// or any per-fn signal change.
inline constexpr std::string_view kTeefSchema = "max.2";

// Per-function signature: an exact hash of the canonicalized pseudo-C
// (precision: identifies bit-equivalent algorithms across compiler
// changes that didn't perturb the decompile output) plus an 8-slot
// MinHash sketch over canonical token bigrams (estimates Jaccard
// similarity between two functions to recover near-matches that
// the exact hash misses).
struct TeefSig {
    u64                  exact_hash = 0;     // 0 = could not fingerprint
    std::array<u64, 8>   minhash    = {};
};

// Estimate Jaccard similarity from two MinHash sketches: fraction of
// positions where the minimum-hash agrees. Standard MinHash result.
[[nodiscard]] float jaccard_estimate(const TeefSig& a, const TeefSig& b) noexcept;

// Compute TEEF for the function entering at `fn_start`. Runs the full
// decompile pipeline (lift → ssa → cleanup → structure → emit) so it's
// significantly more expensive than compute_fingerprint; expect 1-100ms
// per function depending on size. Cache aggressively.
[[nodiscard]] TeefSig compute_teef(const Binary& b, addr_t fn_start);

// One sub-function "chunk" — a region of the structured IR substantial
// enough to be its own identification target. Big functions tend to
// be unrecognizable as a whole between library versions because of
// refactors (added fast paths, rearranged error handling) but their
// inner loops, switch tables, and large branches stay invariant. A
// chunk is fingerprinted with a fresh canonicalizer, so its hash is
// independent of where it appears in its parent.
struct TeefChunk {
    TeefSig sig;
    u32     inst_count = 0;     // structured-region size; weight in matchers
    u8      kind       = 0;     // RegionKind cast to u8 — for analysis grouping
};

struct TeefFunction {
    TeefSig                 whole;
    std::vector<TeefChunk>  chunks;        // sorted by inst_count desc
    // Identifying strings reachable from this function — fnv1a64 of
    // up to 8 distinct strings, length-biased toward unique ones. Set
    // only by build_teef_tsv / parse_teef_tsv (TSV-level concept);
    // compute_teef_with_chunks leaves it empty.
    std::vector<u64>        string_hashes;
    // L4 behavioural signature. compute_teef_with_chunks doesn't
    // populate it (it's a flat-IR concern, not structurer-level);
    // corpus build paths call compute_behav_sig and stuff it into the
    // F row, parse_teef_tsv reads it back. exact_hash == 0 means the
    // interpreter aborted on this fn (rare; the recognizer's L4 paths
    // gate on it).
    BehavSig                behav;
    // L0 topology hash — a u64 over a small set of CFG-shape features
    // (block count, edge count, in/out-degree maxes, loop-header count,
    // return count). Cheap to compute (~5 µs/fn) and serves as a
    // pre-filter for L2 jaccard scans: corpus entries grouped by topo
    // hash narrow the candidate set without touching content. Two
    // structurally-identical CFGs collide; near-but-not-identical ones
    // (one extra cleanup block from compiler diversity) miss the
    // pre-filter and fall through to the full scan, so it's lossy for
    // performance, not for correctness.
    u64                     topo_hash = 0;
};

// Compute the function-level TEEF and per-chunk fingerprints for any
// region whose subtree contains ≥ `min_chunk_insts` IR instructions.
// Smaller regions are skipped to avoid corpus pollution by trivial
// blocks (return/branch-only fragments that match across thousands
// of unrelated functions). The sweet spot empirically is ~10.
[[nodiscard]] TeefFunction
compute_teef_with_chunks(const Binary& b, addr_t fn_start,
                         u32 min_chunk_insts = 10);

// Hash + MinHash a pseudo-C source string directly. Useful for
// callers that already have the emitted text (the CLI fingerprint
// command, the UI's per-function diff). Same canonicalization as
// compute_teef — splitting it out lets us unit-test the hashing
// independently of the decompile pipeline.
[[nodiscard]] TeefSig teef_from_pseudo_c(std::string_view pseudo_c);

}  // namespace ember
