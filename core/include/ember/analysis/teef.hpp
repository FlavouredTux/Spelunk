#pragma once

#include <array>
#include <string_view>
#include <vector>

#include <ember/binary/binary.hpp>
#include <ember/common/types.hpp>

namespace ember {

// Tree-Edit Equivalence Fingerprint (TEEF). Hashes the canonicalized
// pseudo-C output of a function rather than its IR or bytes. Decompiled
// output is downstream of every compiler decision but upstream of the
// source — far more invariant across compiler version / optimization
// level than the IR layer is. See docs/teef.md for the full design and
// the cross-glibc-version validation experiment.
//
// Schema bumped on canonicalization rule changes; folded into the
// hash so cached TSVs from a different schema can't collide silently.
inline constexpr std::string_view kTeefSchema = "v5";

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
