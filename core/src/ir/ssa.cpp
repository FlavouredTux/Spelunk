#include <ember/ir/ssa.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <deque>
#include <functional>
#include <map>
#include <optional>
#include <ranges>
#include <set>
#include <unordered_map>
#include <utility>
#include <vector>

#include <ember/analysis/cfg_util.hpp>
#include <ember/common/types.hpp>

namespace ember {

namespace {

// Map every sub-register (al/ah/ax/eax) to its 64-bit canonical form. Xmm
// registers are self-canonical — we don't model sub-xmm slicing.
constexpr std::array<Reg, static_cast<std::size_t>(Reg::Count)> kCanonical = {
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
    Reg::PpcR0,  Reg::PpcR1,  Reg::PpcR2,  Reg::PpcR3,
    Reg::PpcR4,  Reg::PpcR5,  Reg::PpcR6,  Reg::PpcR7,
    Reg::PpcR8,  Reg::PpcR9,  Reg::PpcR10, Reg::PpcR11,
    Reg::PpcR12, Reg::PpcR13, Reg::PpcR14, Reg::PpcR15,
    Reg::PpcR16, Reg::PpcR17, Reg::PpcR18, Reg::PpcR19,
    Reg::PpcR20, Reg::PpcR21, Reg::PpcR22, Reg::PpcR23,
    Reg::PpcR24, Reg::PpcR25, Reg::PpcR26, Reg::PpcR27,
    Reg::PpcR28, Reg::PpcR29, Reg::PpcR30, Reg::PpcR31,
    Reg::PpcLr, Reg::PpcCtr,
};

// Canonical form of the last entry must still map to itself; this catches
// out-of-order sentinel moves where Xmm15 drifts off the end of the table.
static_assert(kCanonical.back() == Reg::PpcCtr,
              "kCanonical must be updated to match Reg enum");

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

}  // namespace

// ===== SSA identity helpers (shared across passes + emitter) =====

std::optional<SsaKey> ssa_key(const IrValue& v) noexcept {
    switch (v.kind) {
        case IrValueKind::Reg:
            return SsaKey{0, static_cast<u32>(canonical_reg(v.reg)), v.version};
        case IrValueKind::Flag:
            return SsaKey{1, static_cast<u32>(v.flag), v.version};
        case IrValueKind::Temp:
            return SsaKey{2, v.temp, 0};
        case IrValueKind::Imm: {
            // Synthesize a stable key so memory passes can treat
            // `store [0x404018], v` as a write to a known address.
            const u64 uv = static_cast<u64>(v.imm);
            return SsaKey{3,
                          static_cast<u32>(uv & 0xFFFFFFFFu),
                          static_cast<u32>(uv >> 32)};
        }
        default:
            return std::nullopt;
    }
}

bool same_ssa_value(const IrValue& a, const IrValue& b) noexcept {
    if (a.kind != b.kind) return false;
    if (a.type != b.type) return false;
    if (a.kind == IrValueKind::Imm) return a.imm == b.imm;
    const auto ka = ssa_key(a);
    const auto kb = ssa_key(b);
    return ka && kb && *ka == *kb;
}

namespace {

// compute_rpo + compute_idoms live in <ember/analysis/cfg_util.hpp>.

[[nodiscard]] std::map<addr_t, std::set<addr_t>>
compute_df(const IrFunction& fn, const std::unordered_map<addr_t, addr_t>& idom) {
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
                      const std::unordered_map<addr_t, addr_t>& idom) {
    std::map<VarKey, std::vector<u32>> stacks;
    std::map<VarKey, u32>              counters;

    // Canonicalise sibling order: idom is unordered, but sibling traversal
    // order drives global counters[*dv] and therefore visible SSA versions.
    // Sorting each child list by address makes the renumbering deterministic
    // independent of the hash function.
    std::map<addr_t, std::vector<addr_t>> children;
    for (const auto& [node, parent] : idom) {
        if (node != parent) children[parent].push_back(node);
    }
    for (auto& [_, siblings] : children) std::ranges::sort(siblings);

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

    std::unordered_map<addr_t, std::size_t> rpo_index;
    rpo_index.reserve(rpo.size());
    for (const auto [i, addr] : std::views::enumerate(rpo))
        rpo_index[addr] = static_cast<std::size_t>(i);

    const auto idoms = compute_idoms(fn, rpo, rpo_index);
    const auto df    = compute_df(fn, idoms);

    insert_phis(fn, df);
    rename_variables(fn, idoms);

    return {};
}

}  // namespace ember
