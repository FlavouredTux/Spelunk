#pragma once

#include <span>
#include <unordered_map>
#include <vector>

#include <ember/common/types.hpp>
#include <ember/ir/ir.hpp>

namespace ember {

// Reverse-post-order of the IR CFG starting at `fn.start`. Iterative DFS —
// safe for deep pathological CFGs where the recursive lambda version would
// blow the stack. Deterministic given stable block_at / successors order.
[[nodiscard]] std::vector<addr_t> compute_rpo(const IrFunction& fn);

// Cooper-Harvey-Kennedy immediate dominators. `rpo_index[b]` must map every
// reachable block's address to its index in `rpo`. Unordered: the algorithm
// only reads via find(), so lookup-heavy hashing beats the red-black tree.
[[nodiscard]] std::unordered_map<addr_t, addr_t>
compute_idoms(const IrFunction& fn,
              std::span<const addr_t> rpo,
              const std::unordered_map<addr_t, std::size_t>& rpo_index);

}  // namespace ember
