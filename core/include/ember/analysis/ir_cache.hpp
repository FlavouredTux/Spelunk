#pragma once

#include <map>
#include <memory>
#include <set>

#include <ember/common/types.hpp>
#include <ember/ir/ir.hpp>

namespace ember {

class Binary;

// Memoized "lift one function to SSA-cleaned IR" cache. Building a single
// IrFunction is a chain of CFG → IR lift → SSA conversion → cleanup
// passes that costs ~5-10ms on a typical x86-64 function; binary-wide
// analyses (IPA, indirect-call resolution, fingerprinting) all walk the
// same set of functions, so they can amortize that cost across each other
// by sharing one IrCache. Misses on a `failed` address (decoder rejection,
// missing bytes, …) are sticky so we don't keep retrying.
struct IrCache {
    std::map<addr_t, std::unique_ptr<IrFunction>> by_addr;
    std::set<addr_t> failed;
};

// Look up — and build on cache miss — the SSA-cleaned IR of the function
// at `fn`. Returns nullptr if any step in the lift chain fails (the
// failure is remembered so callers don't retry).
[[nodiscard]] IrFunction* lift_cached(IrCache& cache, const Binary& b, addr_t fn);

}  // namespace ember
