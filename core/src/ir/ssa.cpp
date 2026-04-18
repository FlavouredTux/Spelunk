#include <ember/ir/ssa.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <deque>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <utility>
#include <vector>

#include <ember/common/types.hpp>

namespace ember {

namespace {

// Map every sub-register (al/ah/ax/eax) to its 64-bit canonical form. Xmm
// registers are self-canonical — we don't model sub-xmm slicing.
constexpr std::array<Reg, 92> kCanonical = {
    Reg::None,
    Reg::Rax, Reg::Rcx, Reg::Rdx, Reg::Rbx,
    Reg::Rax, Reg::Rcx, Reg::Rdx, Reg::Rbx,
    Reg::Rsp, Reg::Rbp, Reg::Rsi, Reg::Rdi,
    Reg::R8,  Reg::R9,  Reg::R10, Reg::R11,
    Reg::R12, Reg::R13, Reg::R14, Reg::R15,
    Reg::Rax, Reg::Rcx, Reg::Rdx, Reg::Rbx,
    Reg::Rsp, Reg::Rbp, Reg::Rsi, Reg::Rdi,
    Reg::R8,  Reg::R9,  Reg::R10, Reg::R11,
    Reg::R12, Reg::R13, Reg::R14, Reg::R15,
    Reg::Rax, Reg::Rcx, Reg::Rdx, Reg::Rbx,
    Reg::Rsp, Reg::Rbp, Reg::Rsi, Reg::Rdi,
    Reg::R8,  Reg::R9,  Reg::R10, Reg::R11,
    Reg::R12, Reg::R13, Reg::R14, Reg::R15,
    Reg::Rax, Reg::Rcx, Reg::Rdx, Reg::Rbx,
    Reg::Rsp, Reg::Rbp, Reg::Rsi, Reg::Rdi,
    Reg::R8,  Reg::R9,  Reg::R10, Reg::R11,
    Reg::R12, Reg::R13, Reg::R14, Reg::R15,
    Reg::Es, Reg::Cs, Reg::Ss, Reg::Ds, Reg::Fs, Reg::Gs,
    Reg::Rip,
    Reg::Xmm0,  Reg::Xmm1,  Reg::Xmm2,  Reg::Xmm3,
    Reg::Xmm4,  Reg::Xmm5,  Reg::Xmm6,  Reg::Xmm7,
    Reg::Xmm8,  Reg::Xmm9,  Reg::Xmm10, Reg::Xmm11,
    Reg::Xmm12, Reg::Xmm13, Reg::Xmm14, Reg::Xmm15,
};

struct VarKey {
    u8 kind = 0;   // 0 = Reg, 1 = Flag
    u8 id   = 0;   // Reg enum value or Flag enum value

    auto operator<=>(const VarKey&) const = default;

    static VarKey of_reg(Reg r) noexcept {
        return {0, static_cast<u8>(canonical_reg(r))};
    }
    static VarKey of_flag(Flag f) noexcept {
        return {1, static_cast<u8>(f)};
    }
};

[[nodiscard]] std::optional<VarKey> variable_of(const IrValue& v) noexcept {
    if (v.kind == IrValueKind::Reg)  return VarKey::of_reg(v.reg);
    if (v.kind == IrValueKind::Flag) return VarKey::of_flag(v.flag);
    return std::nullopt;
}

// ===== CFG analyses =====

[[nodiscard]] std::vector<addr_t> compute_rpo(const IrFunction& fn) {
    std::vector<addr_t> post;
    std::set<addr_t>    seen;

    std::function<void(addr_t)> visit = [&](addr_t a) {
        if (!seen.insert(a).second) return;
        auto it = fn.block_at.find(a);
        if (it == fn.block_at.end()) return;
        const auto& bb = fn.blocks[it->second];
        for (addr_t s : bb.successors) visit(s);
        post.push_back(a);
    };

    visit(fn.start);
    std::reverse(post.begin(), post.end());
    return post;
}

[[nodiscard]] std::map<addr_t, addr_t>
compute_idoms(const IrFunction& fn, const std::vector<addr_t>& rpo) {
    std::map<addr_t, std::size_t> rpo_index;
    for (std::size_t i = 0; i < rpo.size(); ++i) rpo_index[rpo[i]] = i;

    std::map<addr_t, addr_t> idom;
    idom[fn.start] = fn.start;

    auto intersect = [&](addr_t b1, addr_t b2) noexcept -> addr_t {
        while (b1 != b2) {
            while (rpo_index[b1] > rpo_index[b2]) {
                auto it = idom.find(b1);
                if (it == idom.end()) return b2;
                b1 = it->second;
            }
            while (rpo_index[b2] > rpo_index[b1]) {
                auto it = idom.find(b2);
                if (it == idom.end()) return b1;
                b2 = it->second;
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

[[nodiscard]] std::map<addr_t, std::set<addr_t>>
compute_df(const IrFunction& fn, const std::map<addr_t, addr_t>& idom) {
    std::map<addr_t, std::set<addr_t>> df;

    for (const auto& bb : fn.blocks) {
        if (bb.predecessors.size() < 2) continue;
        const addr_t b = bb.start;
        auto bi = idom.find(b);
        if (bi == idom.end()) continue;
        const addr_t b_idom = bi->second;

        for (addr_t p : bb.predecessors) {
            addr_t runner = p;
            while (runner != b_idom) {
                df[runner].insert(b);
                auto ri = idom.find(runner);
                if (ri == idom.end() || ri->second == runner) break;
                runner = ri->second;
            }
        }
    }

    return df;
}

// ===== Phi placement =====

void insert_phis(IrFunction& fn,
                 const std::map<addr_t, std::set<addr_t>>& df) {
    std::map<VarKey, std::set<addr_t>> defs;
    for (const auto& bb : fn.blocks) {
        for (const auto& inst : bb.insts) {
            if (auto v = variable_of(inst.dst); v) {
                defs[*v].insert(bb.start);
            }
        }
    }

    for (const auto& [var, def_sites] : defs) {
        std::set<addr_t>   has_phi;
        std::deque<addr_t> wl(def_sites.begin(), def_sites.end());

        while (!wl.empty()) {
            const addr_t b = wl.front();
            wl.pop_front();

            auto dfi = df.find(b);
            if (dfi == df.end()) continue;

            for (addr_t y : dfi->second) {
                if (!has_phi.insert(y).second) continue;

                auto yit = fn.block_at.find(y);
                if (yit == fn.block_at.end()) continue;
                auto& by = fn.blocks[yit->second];

                IrInst phi;
                phi.op = IrOp::Phi;
                if (var.kind == 0) {
                    const Reg canon = static_cast<Reg>(var.id);
                    phi.dst = IrValue::make_reg(canon,
                        type_for_bits(reg_size(canon) * 8));
                } else {
                    phi.dst = IrValue::make_flag(static_cast<Flag>(var.id));
                }
                for (addr_t p : by.predecessors) {
                    phi.phi_operands.push_back(phi.dst);
                    phi.phi_preds.push_back(p);
                }

                by.insts.insert(by.insts.begin(), std::move(phi));

                if (!def_sites.contains(y)) {
                    wl.push_back(y);
                }
            }
        }
    }
}

// ===== Renaming =====

void rename_variables(IrFunction& fn,
                      const std::map<addr_t, addr_t>& idom) {
    std::map<VarKey, std::vector<u32>> stacks;
    std::map<VarKey, u32>              counters;

    std::map<addr_t, std::vector<addr_t>> children;
    for (const auto& [node, parent] : idom) {
        if (node != parent) children[parent].push_back(node);
    }

    auto current_version = [&](VarKey v) -> u32 {
        auto it = stacks.find(v);
        if (it == stacks.end() || it->second.empty()) return 0;
        return it->second.back();
    };

    std::function<void(addr_t)> recurse = [&](addr_t block_addr) {
        auto it = fn.block_at.find(block_addr);
        if (it == fn.block_at.end()) return;
        auto& bb = fn.blocks[it->second];

        std::vector<VarKey> defined_here;

        for (auto& inst : bb.insts) {
            if (inst.op != IrOp::Phi) {
                for (u8 k = 0; k < inst.src_count && k < inst.srcs.size(); ++k) {
                    auto& src = inst.srcs[k];
                    if (auto v = variable_of(src); v) {
                        src.version = current_version(*v);
                    }
                }
            }

            if (auto dv = variable_of(inst.dst); dv) {
                const u32 new_ver = ++counters[*dv];
                stacks[*dv].push_back(new_ver);
                inst.dst.version = new_ver;
                defined_here.push_back(*dv);
            }
        }

        for (addr_t s : bb.successors) {
            auto sit = fn.block_at.find(s);
            if (sit == fn.block_at.end()) continue;
            auto& sbb = fn.blocks[sit->second];
            for (auto& inst : sbb.insts) {
                if (inst.op != IrOp::Phi) break;
                const auto dv = variable_of(inst.dst);
                if (!dv) continue;
                const u32 cur = current_version(*dv);
                for (std::size_t k = 0; k < inst.phi_preds.size(); ++k) {
                    if (inst.phi_preds[k] == block_addr) {
                        if (k < inst.phi_operands.size()) {
                            inst.phi_operands[k].version = cur;
                        }
                        break;
                    }
                }
            }
        }

        auto cit = children.find(block_addr);
        if (cit != children.end()) {
            for (addr_t c : cit->second) recurse(c);
        }

        for (const VarKey& v : defined_here) {
            auto& st = stacks[v];
            if (!st.empty()) st.pop_back();
        }
    };

    recurse(fn.start);
}

}  // namespace

Reg canonical_reg(Reg r) noexcept {
    const auto i = static_cast<std::size_t>(r);
    if (i >= kCanonical.size()) return r;
    return kCanonical[i];
}

Result<void> SsaBuilder::convert(IrFunction& fn) const {
    if (fn.blocks.empty()) return {};

    const auto rpo = compute_rpo(fn);
    if (rpo.empty()) return {};

    const auto idoms = compute_idoms(fn, rpo);
    const auto df    = compute_df(fn, idoms);

    insert_phis(fn, df);
    rename_variables(fn, idoms);

    return {};
}

}  // namespace ember
