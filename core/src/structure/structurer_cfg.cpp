// Dominators, post-dominators and loop discovery over the IR CFG.

#include <algorithm>
#include <cstddef>
#include <deque>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <unordered_map>
#include <utility>
#include <vector>

#include <spelunk/analysis/cfg_util.hpp>
#include <spelunk/analysis/function.hpp>
#include <spelunk/common/types.hpp>
#include <spelunk/ir/ir.hpp>

#include "structurer_internal.hpp"

namespace spelunk::structurer {

namespace {

// compute_rpo + compute_idoms live in <spelunk/analysis/cfg_util.hpp>.
// Cooper-Harvey-Kennedy on the reverse CFG: compute immediate post-dominators.
// The virtual exit (kNoAddr) is the root; forward-terminating blocks are its
// reverse-CFG predecessors.
[[nodiscard]] std::unordered_map<addr_t, addr_t>
compute_ipdoms(const IrFunction& fn) {
    std::vector<addr_t> post;   // post-order on reverse CFG from virtual exit
    std::set<addr_t>    seen;

    std::function<void(addr_t)> visit = [&](addr_t n) {
        if (!seen.insert(n).second) return;
        if (n == kNoAddr) {
            // Reverse-CFG successors of the virtual exit = forward-terminating
            // blocks (return, unreachable, or indirect-jmp-with-no-modeled-target).
            for (const auto& bb : fn.blocks) {
                if (bb.successors.empty()) visit(bb.start);
            }
        } else {
            auto it = fn.block_at.find(n);
            if (it != fn.block_at.end()) {
                // Reverse-CFG successors = forward predecessors.
                for (addr_t p : fn.blocks[it->second].predecessors) visit(p);
            }
        }
        post.push_back(n);
    };
    visit(kNoAddr);

    // RPO of reverse CFG = reverse of post-order.
    std::vector<addr_t> rpo(post.rbegin(), post.rend());
    std::unordered_map<addr_t, std::size_t> rpo_idx;
    rpo_idx.reserve(rpo.size());
    for (std::size_t i = 0; i < rpo.size(); ++i)
        rpo_idx[rpo[i]] = i;

    std::unordered_map<addr_t, addr_t> ipdom;
    ipdom[kNoAddr] = kNoAddr;

    auto intersect = [&](addr_t b1, addr_t b2) noexcept -> addr_t {
        while (b1 != b2) {
            auto i1 = rpo_idx.find(b1);
            auto i2 = rpo_idx.find(b2);
            if (i1 == rpo_idx.end() || i2 == rpo_idx.end()) return b1;
            while (i1->second > i2->second) {
                auto it = ipdom.find(b1);
                if (it == ipdom.end()) return b2;
                b1 = it->second;
                i1 = rpo_idx.find(b1);
                if (i1 == rpo_idx.end()) return b2;
            }
            while (i2->second > i1->second) {
                auto it = ipdom.find(b2);
                if (it == ipdom.end()) return b1;
                b2 = it->second;
                i2 = rpo_idx.find(b2);
                if (i2 == rpo_idx.end()) return b1;
            }
        }
        return b1;
    };

    bool changed = true;
    while (changed) {
        changed = false;
        for (std::size_t i = 1; i < rpo.size(); ++i) {
            const addr_t b = rpo[i];
            if (b == kNoAddr) continue;
            auto it = fn.block_at.find(b);
            if (it == fn.block_at.end()) continue;
            const auto& bb = fn.blocks[it->second];

            // Reverse-CFG predecessors of b = forward successors of b,
            // with kNoAddr substituted for a forward-terminating case.
            std::vector<addr_t> rev_preds;
            if (bb.successors.empty()) {
                rev_preds.push_back(kNoAddr);
            } else {
                for (addr_t s : bb.successors) rev_preds.push_back(s);
            }

            std::optional<addr_t> new_ipdom;
            for (addr_t p : rev_preds) {
                if (!ipdom.contains(p)) continue;
                new_ipdom = new_ipdom ? intersect(p, *new_ipdom) : p;
            }
            if (!new_ipdom) continue;

            auto cur = ipdom.find(b);
            if (cur == ipdom.end() || cur->second != *new_ipdom) {
                ipdom[b] = *new_ipdom;
                changed = true;
            }
        }
    }

    return ipdom;
}

[[nodiscard]] bool dominates(const std::unordered_map<addr_t, addr_t>& idom,
                             addr_t dominator, addr_t node) noexcept {
    while (true) {
        if (node == dominator) return true;
        auto it = idom.find(node);
        if (it == idom.end()) return false;
        if (it->second == node) return false;
        node = it->second;
    }
}

}  // namespace

void find_loops(const IrFunction& fn, CfgInfo& info) {
    for (const auto& bb : fn.blocks) {
        for (addr_t s : bb.successors) {
            if (dominates(info.idom, /*dominator=*/s, /*node=*/bb.start)) {
                info.loop_headers[s].insert(bb.start);
            }
        }
    }

    auto can_reach = [&](addr_t start, const std::set<addr_t>& targets, addr_t forbidden) -> bool {
        std::set<addr_t> seen;
        std::deque<addr_t> q;
        q.push_back(start);
        while (!q.empty()) {
            addr_t n = q.front();
            q.pop_front();
            if (n == forbidden) continue;
            if (!seen.insert(n).second) continue;
            if (targets.contains(n)) return true;
            auto it = fn.block_at.find(n);
            if (it == fn.block_at.end()) continue;
            for (addr_t s : fn.blocks[it->second].successors) q.push_back(s);
        }
        return false;
    };

    for (auto& [header, backs] : info.loop_headers) {
        auto hit = fn.block_at.find(header);
        if (hit == fn.block_at.end()) continue;
        const auto& hbb = fn.blocks[hit->second];
        // A throw/abort guard in the header is not the loop's normal
        // continuation. Prefer an ordinary latch exit when one is proven;
        // otherwise retain the old header-exit choice as a safe fallback.
        const auto terminal_guard = [&](addr_t start) {
            std::set<addr_t> visiting;
            std::map<addr_t, bool> memo;
            unsigned budget = 64;
            const auto visit = [&](auto&& self, addr_t address) -> bool {
                if (auto found = memo.find(address); found != memo.end()) return found->second;
                if (!budget || !visiting.insert(address).second) return false;
                --budget;
                const auto found = fn.block_at.find(address);
                if (found == fn.block_at.end()) return false;
                const auto& block = fn.blocks[found->second];
                bool terminal = !block.insts.empty() && block.insts.back().op == IrOp::Unreachable;
                if (!terminal && !block.successors.empty() && block.kind != BlockKind::Return &&
                    block.kind != BlockKind::TailCall) {
                    terminal = std::ranges::all_of(block.successors,
                        [&](addr_t successor) { return self(self, successor); });
                }
                visiting.erase(address);
                memo.emplace(address, terminal);
                return terminal;
            };
            return visit(visit, start);
        };
        addr_t guarded_exit = kNoAddr;
        // Top-tested loop (while/for): header itself is the predicate
        // and exactly one arm exits the loop.
        if (hbb.kind == BlockKind::Conditional && hbb.successors.size() == 2) {
            addr_t s1 = hbb.successors[0];
            addr_t s2 = hbb.successors[1];
            const bool s1_loops = can_reach(s1, backs, /*forbidden=*/header);
            const bool s2_loops = can_reach(s2, backs, /*forbidden=*/header);
            if (s1_loops != s2_loops) {
                const auto exit = s1_loops ? s2 : s1;
                info.loop_exit[header] = exit;
                if (!terminal_guard(exit)) continue;
                guarded_exit = exit;
            }
            // Both arms loop - header's conditional is internal to the
            // body (e.g. a skip-and-accumulate fork), and the real exit
            // sits on a back-edge tail. Fall through to do-while
            // detection rather than leaving loop_exit unset, which would
            // strand the post-loop block in the parent build_sequence.
        }
        // Some compilers put an unconditional jump on the back edge and the
        // actual exit test in an earlier block. Examine the complete natural
        // loop, not just its latches, before choosing a continuation.
        std::set<addr_t> natural{header};
        std::vector<addr_t> pending(backs.begin(), backs.end());
        while (!pending.empty()) {
            const auto address = pending.back(); pending.pop_back();
            if (!natural.insert(address).second) continue;
            const auto found = fn.block_at.find(address);
            if (found == fn.block_at.end()) continue;
            for (const auto pred : fn.blocks[found->second].predecessors)
                if (dominates(info.idom, header, pred)) pending.push_back(pred);
        }
        std::set<addr_t> ordinary_exits;
        bool has_terminal_guard = false;
        for (const auto address : natural) {
            const auto found = fn.block_at.find(address);
            if (found == fn.block_at.end()) continue;
            for (const auto successor : fn.blocks[found->second].successors) {
                if (natural.contains(successor)) continue;
                if (terminal_guard(successor)) has_terminal_guard = true;
                else ordinary_exits.insert(successor);
            }
        }
        addr_t guarded_continuation = kNoAddr;
        if (has_terminal_guard && !ordinary_exits.empty()) {
            // Ordinary post-dominance includes throw paths. Find the first
            // common continuation of *returning* paths instead, keeping each
            // side's terminal guards before that join. Exit trampolines and
            // exits that themselves contain a throw check both occur here.
            const auto reaches = [&](addr_t start, addr_t candidate, bool avoid) {
                std::vector<addr_t> work{start};
                std::set<addr_t> seen;
                while (!work.empty()) {
                    const auto node = work.back(); work.pop_back();
                    if (!seen.insert(node).second) continue;
                    if (node == candidate) { if (!avoid) return true; else continue; }
                    if (natural.contains(node)) { if (avoid) return true; else continue; }
                    if (terminal_guard(node)) continue;
                    const auto found = fn.block_at.find(node);
                    if (found == fn.block_at.end()) { if (avoid) return true; else continue; }
                    const auto& block = fn.blocks[found->second];
                    if (avoid && (block.successors.empty() || block.kind == BlockKind::Return ||
                                  block.kind == BlockKind::TailCall)) return true;
                    work.insert(work.end(), block.successors.begin(), block.successors.end());
                }
                return false;
            };
            std::deque<addr_t> candidates{*ordinary_exits.begin()};
            std::set<addr_t> seen;
            unsigned budget = 128;
            while (!candidates.empty() && budget) {
                --budget;
                const auto node = candidates.front(); candidates.pop_front();
                if (!seen.insert(node).second || !fn.block_at.contains(node) ||
                    natural.contains(node) || terminal_guard(node)) continue;
                if (std::ranges::all_of(ordinary_exits, [&](addr_t start) {
                        return reaches(start, node, false) && !reaches(start, node, true);
                    })) {
                    guarded_continuation = node;
                    info.loop_exit[header] = node;
                    break;
                }
                const auto found = fn.block_at.find(node);
                if (found != fn.block_at.end()) for (const auto next : fn.blocks[found->second].successors)
                    candidates.push_back(next);
            }
        }

        // Bottom-tested loop analysis. A single conditional back-edge tail can
        // become `do { ... } while (cond)` only when it is the loop's sole
        // latch. With multiple latches we may still retain a proven common exit
        // for a generic Loop, but must leave every tail test explicit.
        struct TailCandidate {
            addr_t tail = kNoAddr;
            addr_t exit = kNoAddr;
        };
        std::vector<TailCandidate> candidates;
        bool supported_latches = true;
        for (const addr_t tail : backs) {
            auto tit = fn.block_at.find(tail);
            if (tit == fn.block_at.end()) {
                supported_latches = false;
                break;
            }
            const auto& tbb = fn.blocks[tit->second];
            const bool direct_back_jump =
                (tbb.kind == BlockKind::Unconditional ||
                 tbb.kind == BlockKind::Fallthrough) &&
                tbb.successors.size() == 1 &&
                tbb.successors.front() == header;
            if (direct_back_jump) continue;

            if (tbb.kind != BlockKind::Conditional ||
                tbb.successors.size() != 2) {
                supported_latches = false;
                break;
            }
            const addr_t t1 = tbb.successors[0];
            const addr_t t2 = tbb.successors[1];
            if ((t1 == header) == (t2 == header)) {
                supported_latches = false;
                break;
            }
            const addr_t candidate_exit = t1 == header ? t2 : t1;
            if (can_reach(candidate_exit, backs, /*forbidden=*/header)) {
                // The non-header arm remains in the loop; it is not an exit.
                supported_latches = false;
                break;
            }
            candidates.push_back({tail, candidate_exit});
        }
        if (!supported_latches || candidates.empty()) continue;

        const addr_t common_exit = candidates.front().exit;
        const bool share_exit = std::ranges::all_of(
            candidates, [&](const TailCandidate& candidate) {
                return candidate.exit == common_exit;
            });
        if (guarded_exit != kNoAddr && (!share_exit || terminal_guard(common_exit))) continue;
        if (guarded_continuation != kNoAddr && common_exit != guarded_continuation) continue;
        if (share_exit) info.loop_exit[header] = common_exit;
        if (backs.size() == 1 && candidates.size() == 1) {
            info.do_while_tail[header] = candidates.front().tail;
        }
    }
}

CfgInfo analyze_cfg(const IrFunction& fn) {
    CfgInfo info;
    info.rpo = compute_rpo(fn);
    info.rpo_index.reserve(info.rpo.size());
    for (std::size_t i = 0; i < info.rpo.size(); ++i)
        info.rpo_index[info.rpo[i]] = i;
    info.idom  = compute_idoms(fn, info.rpo, info.rpo_index);
    info.ipdom = compute_ipdoms(fn);
    find_loops(fn, info);
    return info;
}

}  // namespace spelunk::structurer
