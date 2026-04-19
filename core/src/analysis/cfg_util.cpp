#include <ember/analysis/cfg_util.hpp>

#include <algorithm>
#include <optional>
#include <set>
#include <utility>
#include <vector>

namespace ember {

std::vector<addr_t> compute_rpo(const IrFunction& fn) {
    std::vector<addr_t> post;
    std::set<addr_t>    seen;

    // Iterative DFS. Each stack frame tracks (block, next-successor-index) so
    // we can resume the successor walk after descending into a child.
    struct Frame { addr_t a; std::size_t next_succ; };
    std::vector<Frame> stack;

    auto push = [&](addr_t a) {
        if (!seen.insert(a).second) return;
        stack.push_back({a, 0});
    };
    push(fn.start);

    while (!stack.empty()) {
        Frame& f = stack.back();
        auto it = fn.block_at.find(f.a);
        if (it == fn.block_at.end()) {
            post.push_back(f.a);
            stack.pop_back();
            continue;
        }
        const auto& succs = fn.blocks[it->second].successors;
        if (f.next_succ < succs.size()) {
            const addr_t s = succs[f.next_succ++];
            if (!seen.contains(s)) push(s);
            continue;
        }
        post.push_back(f.a);
        stack.pop_back();
    }

    std::reverse(post.begin(), post.end());
    return post;
}

std::map<addr_t, addr_t>
compute_idoms(const IrFunction& fn,
              const std::vector<addr_t>& rpo,
              const std::map<addr_t, std::size_t>& rpo_index) {
    std::map<addr_t, addr_t> idom;
    if (rpo.empty()) return idom;
    idom[fn.start] = fn.start;

    auto intersect = [&](addr_t b1, addr_t b2) noexcept -> addr_t {
        while (b1 != b2) {
            auto i1 = rpo_index.find(b1);
            auto i2 = rpo_index.find(b2);
            if (i1 == rpo_index.end() || i2 == rpo_index.end()) return b1;
            while (i1->second > i2->second) {
                auto it = idom.find(b1);
                if (it == idom.end()) return b2;
                b1 = it->second;
                i1 = rpo_index.find(b1);
                if (i1 == rpo_index.end()) return b2;
            }
            while (i2->second > i1->second) {
                auto it = idom.find(b2);
                if (it == idom.end()) return b1;
                b2 = it->second;
                i2 = rpo_index.find(b2);
                if (i2 == rpo_index.end()) return b1;
            }
        }
        return b1;
    };

    bool changed = true;
    while (changed) {
        changed = false;
        for (std::size_t i = 1; i < rpo.size(); ++i) {
            const addr_t b = rpo[i];
            auto it = fn.block_at.find(b);
            if (it == fn.block_at.end()) continue;
            const auto& bb = fn.blocks[it->second];

            std::optional<addr_t> new_idom;
            for (addr_t p : bb.predecessors) {
                if (!idom.contains(p)) continue;
                new_idom = new_idom ? intersect(p, *new_idom) : p;
            }
            if (!new_idom) continue;

            auto cur = idom.find(b);
            if (cur == idom.end() || cur->second != *new_idom) {
                idom[b] = *new_idom;
                changed = true;
            }
        }
    }

    return idom;
}

}  // namespace ember
