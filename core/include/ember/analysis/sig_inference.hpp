#pragma once

#include <array>
#include <map>

#include <ember/binary/binary.hpp>
#include <ember/common/types.hpp>

namespace ember {

// Per-function inferred-signature hints. Currently just "which SysV int-arg
// slots are char*"; grows as we teach the inferencer more patterns.
struct InferredSig {
    std::array<bool, 6> charp = {};
};

// Compute char*-arg hints for every function reachable in the binary, with
// fixed-point propagation over the call graph:
//
//   1. Seed each function's charp set from direct calls to libc char*
//      sinks (strlen, strcmp, puts, fopen, ...).
//   2. Iterate: for every call to a function with known charp slots, tag
//      the caller's corresponding own arg slots if the data flows there.
//   3. Repeat until no new tags appear.
//
// Runs the CFG+IR+SSA+cleanup pipeline per function once. For a 380k-function
// RobloxPlayer this is expensive the first time — up to a few minutes — but
// deterministic and cacheable. Callers that don't need IPA for a one-shot
// emission should skip this and rely on the intra-procedural char* inference
// the emitter already does.
[[nodiscard]] std::map<addr_t, InferredSig>
infer_signatures(const Binary& b);

}  // namespace ember
