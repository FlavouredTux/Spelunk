#pragma once

#include <array>
#include <map>

#include <ember/analysis/ir_cache.hpp>
#include <ember/binary/binary.hpp>
#include <ember/common/types.hpp>
#include <ember/ir/abi.hpp>
#include <ember/ir/types.hpp>

namespace ember {

// Per-function inferred-signature hints. The legacy `charp` bitset is
// preserved as the fast-path/back-compat view of "param i is char*";
// Phase 3 adds the richer TypeRef fields that index into the
// InferenceResult's binary-wide TypeArena.
//
//   * params[i] == Top  → no IPA evidence; emitter falls back to its
//     local heuristics (the old charp / arity flow still works).
//   * return_type == Top → no IPA evidence for the return type; emitter
//     falls back to inferring from the Return-region's bit-width.
struct InferredSig {
    std::array<bool, kMaxAbiIntArgs>     charp       = {};
    std::array<TypeRef, kMaxAbiIntArgs>  params      = {};
    TypeRef                              return_type = {};
};

// Output of binary-wide signature inference. The arena owns every type
// mentioned by every InferredSig in `sigs` — TypeRefs are stable for the
// lifetime of this struct and only valid when looked up via `arena`.
struct InferenceResult {
    TypeArena                       arena;
    std::map<addr_t, InferredSig>   sigs;
};

// Compute char*-arg + typed param/return hints for every reachable
// function, with fixed-point propagation over the call graph:
//
//   1. Seed each function's charp set from direct calls to libc char*
//      sinks (strlen, strcmp, puts, fopen, ...).
//   2. Iterate: for every call to a function with known charp slots, tag
//      the caller's corresponding own arg slots if the data flows there.
//   3. After convergence, harvest typed return + typed params from each
//      function's local Phase 2 inference (infer_local_types) and meet
//      them into the binary-wide arena. (Phase 3 v0: harvest only — no
//      iterative re-propagation of typed fields. The worklist version
//      is Phase 3.5.)
//
// Runs the CFG+IR+SSA+cleanup pipeline per function once. For a binary
// with hundreds of thousands of functions this is expensive the first
// time — up to a few minutes — but deterministic and cacheable.
// `cache`, when non-null, is reused for every per-function lift the IPA
// fixed-point performs. Subsequent passes (e.g. resolve_indirect_calls)
// can be handed the same cache so a function only ever pays its lift +
// SSA + cleanup cost once across the whole CLI invocation.
[[nodiscard]] InferenceResult
infer_signatures(const Binary& b, IrCache* cache = nullptr);

}  // namespace ember
