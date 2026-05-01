#pragma once

#include <array>
#include <string_view>

#include <ember/binary/binary.hpp>
#include <ember/common/types.hpp>
#include <ember/ir/ir.hpp>

namespace ember {

// L4 of TEEF Max — behavioural fingerprint via bounded IR
// interpretation under K random concrete inputs. Captures WHAT a
// function computes, not HOW its loop body is shaped — invariant under
// the compiler-driven loop transforms (induction-variable strength
// reduction, pointer-vs-index, unrolling) that L2 (cleanup-canonical)
// and L3 (orbit) can't recover.
//
// Approach (BLEX-inspired but interpreter-only, no symbolic execution):
//   1. Generate K = 64 random argument vectors per function. Each fills
//      rdi/rsi/rdx/rcx/r8/r9 (SysV) with values drawn from a mixed
//      distribution: small ints, booleans, large random, common
//      pointer-shaped values (the address of a synthetic 4 KiB page).
//   2. For each vector, run the interpreter on the function's IR.
//      Memory loads are materialized lazily — first access at address
//      A returns a deterministic mix64(A, salt); subsequent accesses
//      return the same value. Stores update the dict. Calls return an
//      opaque mix64(target_class, sorted_args). Branches on concrete
//      conditions are followed; abort if cond is non-concrete.
//   3. Each completed trace yields a (input_hash, return_value,
//      side_effects_multiset_hash) tuple. Hash to one u64.
//   4. Sort, dedupe, MinHash → L4 sketch.
//
// Two functions implementing the same algorithm — even with completely
// different IR shape — produce the same K return values and side
// effects, so their L4 multisets coincide. The fingerprint is purely
// behavioural, so it tolerates arbitrary syntactic compiler diversity.
//
// Schema is bumped on input-distribution / interpreter-semantic
// changes. Folded into the hash so cross-schema corpora can't collide.
inline constexpr std::string_view kBehavSchema = "max.behav.1";

inline constexpr std::size_t kBehavTraces        = 64;
inline constexpr std::size_t kBehavMaxInsnsTrace = 4096;
inline constexpr std::size_t kBehavMaxLoadsTrace = 1024;

struct BehavSig {
    // Hash of the sorted, deduped multiset of per-trace outcome hashes.
    u64                  exact_hash      = 0;
    // 8-slot MinHash for partial-overlap recovery.
    std::array<u64, 8>   minhash         = {};
    // Telemetry: how many of the K traces ran to completion vs.
    // hit a non-concrete branch / instruction-budget cap. Recognizers
    // may downweight signatures with few completions.
    u8                   traces_done     = 0;
    u8                   traces_aborted  = 0;
};

[[nodiscard]] BehavSig compute_behav_sig(const Binary& bin, addr_t fn_start);

// Compute the behavioural sig from an already-pipelined IrFunction
// (post-lift, post-SSA, post-cleanup). compute_teef_max() uses this to
// avoid re-running the pipeline that compute_teef_with_chunks already
// runs — both the L2 and L4 paths consume the cleaned flat IR, so
// sharing the pipeline halves the per-fn work in corpus build.
[[nodiscard]] BehavSig
compute_behav_sig_from_ir(const IrFunction& fn, const Binary& bin);

[[nodiscard]] float behav_jaccard(const BehavSig& a, const BehavSig& b) noexcept;

}  // namespace ember
