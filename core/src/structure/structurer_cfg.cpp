// Dominators, post-dominators and loop discovery over the IR CFG.

#include <cstddef>
#include <deque>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <unordered_map>
#include <utility>
#include <vector>

#include <ember/analysis/cfg_util.hpp>
#include <ember/analysis/function.hpp>
#include <ember/common/types.hpp>
#include <ember/ir/ir.hpp>

#include "structurer_internal.hpp"

namespace ember::structurer {

namespace {

// compute_rpo + compute_idoms live in <ember/analysis/cfg_util.hpp>.
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
        // Top-tested loop (while/for): header itself is the predicate
        // and exactly one arm exits the loop.
        if (hbb.kind == BlockKind::Conditional && hbb.successors.size() == 2) {
            addr_t s1 = hbb.successors[0];
            addr_t s2 = hbb.successors[1];
            const bool s1_loops = can_reach(s1, backs, /*forbidden=*/header);
            const bool s2_loops = can_reach(s2, backs, /*forbidden=*/header);
            if (s1_loops && !s2_loops)      { info.loop_exit[header] = s2; continue; }
            else if (s2_loops && !s1_loops) { info.loop_exit[header] = s1; continue; }
            // Both arms loop - header's conditional is internal to the
            // body (e.g. a skip-and-accumulate fork), and the real exit
            // sits on a back-edge tail. Fall through to do-while
            // detection rather than leaving loop_exit unset, which would
            // strand the post-loop block in the parent build_sequence.
        }
        // Bottom-tested loop (do-while): header isn't conditional, but a
        // back-edge tail tests-and-exits. Pick the first qualifying tail's
        // non-back-edge successor as the loop's exit so build_sequence can
        // continue past the loop.
        for (const addr_t tail : backs) {
            auto tit = fn.block_at.find(tail);
            if (tit == fn.block_at.end()) continue;
            const auto& tbb = fn.blocks[tit->second];
            if (tbb.kind != BlockKind::Conditional || tbb.successors.size() != 2) continue;
            const addr_t t1 = tbb.successors[0];
            const addr_t t2 = tbb.successors[1];
            if      (t1 == header) { info.loop_exit[header] = t2; break; }
            else if (t2 == header) { info.loop_exit[header] = t1; break; }
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

}  // namespace ember::structurer
