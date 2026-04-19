#pragma once

#include <map>
#include <vector>

#include <ember/common/types.hpp>
#include <ember/ir/ir.hpp>

namespace ember {

// Reverse-post-order of the IR CFG starting at `fn.start`. Iterative DFS —
// safe for deep pathological CFGs where the recursive lambda version would
// blow the stack. Deterministic given stable block_at / successors order.
[[nodiscard]] std::vector<addr_t> compute_rpo(const IrFunction& fn);

// Cooper-Harvey-Kennedy immediate dominators. `rpo_index[b]` must map every
// reachable block's address to its index in `rpo`.
[[nodiscard]] std::map<addr_t, addr_t>
compute_idoms(const IrFunction& fn,
              const std::vector<addr_t>& rpo,
              const std::map<addr_t, std::size_t>& rpo_index);

}  // namespace ember
