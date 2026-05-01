#pragma once

#include <array>

#include <ember/binary/binary.hpp>
#include <ember/common/types.hpp>
#include <ember/ir/ir.hpp>

namespace ember {

// L3 of TEEF Max — equivalence-orbit fingerprint via bounded
// e-graph saturation. Conceptually:
//
//   1. Lift the function to ember IR (post-SSA, post-cleanup — same as
//      compute_teef_with_chunks).
//   2. Walk the IR into an e-graph node-by-node. Arithmetic / bitwise /
//      compare / cast / select map to first-class e-graph ops; loads,
//      stores, calls, and other side-effecting nodes become Opaque
//      leaves carrying a stable address-class hash so they participate
//      in hash-cons but never algebraically unify.
//   3. Apply ~30 semantic-preserving rewrite rules covering the
//      compiler-equivalent transformations real toolchains do
//      (commutativity / associativity / identity / absorption /
//      strength reduction / De Morgan / shift normalize / fold).
//   4. Saturate to a node-count budget.
//   5. Multiset-hash the canonical (smallest-cost) form of every
//      live e-class.
//
// Two builds of the same source compiled with different flags or
// compilers tend to land at *two distinct points in the same orbit*.
// Both points appear in the saturated e-graph, so their canonical-hash
// multisets overlap heavily — Jaccard recovers the match where the
// single-point cleanup-canonical hash (L2) would miss.
//
// Schema bumped on rule-set / canonicalization changes; folded into the
// hash so cached fingerprints from a different schema can't collide.
inline constexpr std::string_view kOrbitSchema = "max.orbit";

struct OrbitSig {
    // Hash of the sorted multiset of canonical e-class hashes. Pure
    // exact-match: two fns with identical orbit signatures are highly
    // likely the same algorithm modulo our rule set.
    u64                  exact_hash = 0;
    // 16-slot MinHash over the orbit multiset for partial-overlap
    // recovery. Wider than L2's 8 slots because the orbit signal is
    // diluted across more elements.
    std::array<u64, 16>  minhash    = {};
    // Telemetry — saturation may bail on huge fns (VMP, hand-written asm
    // bombs); recognizers may prefer to skip a budget_hit signature.
    u32                  egraph_nodes  = 0;
    u8                   total_iters   = 0;
    bool                 budget_hit    = false;
};

[[nodiscard]] OrbitSig compute_orbit_sig(const Binary& bin, addr_t fn_start);

// Saturation budget knobs. Both can be overridden at runtime via the
// EMBER_ORBIT_MAX_NODES / EMBER_ORBIT_MAX_ITERS env vars (parsed once
// per process). The defaults target ~5–10 ms per typical fn.
inline constexpr std::size_t kOrbitDefaultMaxNodes = 4096;
inline constexpr std::size_t kOrbitDefaultMaxIters = 16;

// Estimate Jaccard similarity from two orbit MinHash sketches.
[[nodiscard]] float orbit_jaccard(const OrbitSig& a, const OrbitSig& b) noexcept;

}  // namespace ember
