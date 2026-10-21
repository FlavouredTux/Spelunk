#include <spelunk/ir/ssa.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <deque>
#include <iterator>
#include <map>
#include <optional>
#include <ranges>
#include <set>
#include <unordered_map>
#include <utility>
#include <vector>

#include <spelunk/analysis/cfg_util.hpp>
#include <spelunk/common/error.hpp>
#include <spelunk/common/types.hpp>
#include <spelunk/disasm/register.hpp>
#include <spelunk/ir/ir.hpp>

namespace spelunk {

namespace {

// Map every sub-register (al/ah/ax/eax) to its 64-bit canonical form. Xmm
// registers are self-canonical - we don't model sub-xmm slicing.
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
    Reg::Xmm16, Reg::Xmm17, Reg::Xmm18, Reg::Xmm19,
    Reg::Xmm20, Reg::Xmm21, Reg::Xmm22, Reg::Xmm23,
    Reg::Xmm24, Reg::Xmm25, Reg::Xmm26, Reg::Xmm27,
    Reg::Xmm28, Reg::Xmm29, Reg::Xmm30, Reg::Xmm31,
    Reg::Ymm0,  Reg::Ymm1,  Reg::Ymm2,  Reg::Ymm3,
    Reg::Ymm4,  Reg::Ymm5,  Reg::Ymm6,  Reg::Ymm7,
    Reg::Ymm8,  Reg::Ymm9,  Reg::Ymm10, Reg::Ymm11,
    Reg::Ymm12, Reg::Ymm13, Reg::Ymm14, Reg::Ymm15,
    Reg::Ymm16, Reg::Ymm17, Reg::Ymm18, Reg::Ymm19,
    Reg::Ymm20, Reg::Ymm21, Reg::Ymm22, Reg::Ymm23,
    Reg::Ymm24, Reg::Ymm25, Reg::Ymm26, Reg::Ymm27,
    Reg::Ymm28, Reg::Ymm29, Reg::Ymm30, Reg::Ymm31,
    Reg::Zmm0,  Reg::Zmm1,  Reg::Zmm2,  Reg::Zmm3,
    Reg::Zmm4,  Reg::Zmm5,  Reg::Zmm6,  Reg::Zmm7,
    Reg::Zmm8,  Reg::Zmm9,  Reg::Zmm10, Reg::Zmm11,
    Reg::Zmm12, Reg::Zmm13, Reg::Zmm14, Reg::Zmm15,
    Reg::Zmm16, Reg::Zmm17, Reg::Zmm18, Reg::Zmm19,
    Reg::Zmm20, Reg::Zmm21, Reg::Zmm22, Reg::Zmm23,
    Reg::Zmm24, Reg::Zmm25, Reg::Zmm26, Reg::Zmm27,
    Reg::Zmm28, Reg::Zmm29, Reg::Zmm30, Reg::Zmm31,
    Reg::K0, Reg::K1, Reg::K2, Reg::K3,
    Reg::K4, Reg::K5, Reg::K6, Reg::K7,
    Reg::PpcR0,  Reg::PpcR1,  Reg::PpcR2,  Reg::PpcR3,
    Reg::PpcR4,  Reg::PpcR5,  Reg::PpcR6,  Reg::PpcR7,
    Reg::PpcR8,  Reg::PpcR9,  Reg::PpcR10, Reg::PpcR11,
    Reg::PpcR12, Reg::PpcR13, Reg::PpcR14, Reg::PpcR15,
    Reg::PpcR16, Reg::PpcR17, Reg::PpcR18, Reg::PpcR19,
    Reg::PpcR20, Reg::PpcR21, Reg::PpcR22, Reg::PpcR23,
    Reg::PpcR24, Reg::PpcR25, Reg::PpcR26, Reg::PpcR27,
    Reg::PpcR28, Reg::PpcR29, Reg::PpcR30, Reg::PpcR31,
    Reg::PpcLr, Reg::PpcCtr, Reg::PpcXer,
    Reg::PpcGqr0, Reg::PpcGqr1, Reg::PpcGqr2, Reg::PpcGqr3,
    Reg::PpcGqr4, Reg::PpcGqr5, Reg::PpcGqr6, Reg::PpcGqr7,
    Reg::PpcF0,  Reg::PpcF1,  Reg::PpcF2,  Reg::PpcF3,
    Reg::PpcF4,  Reg::PpcF5,  Reg::PpcF6,  Reg::PpcF7,
    Reg::PpcF8,  Reg::PpcF9,  Reg::PpcF10, Reg::PpcF11,
    Reg::PpcF12, Reg::PpcF13, Reg::PpcF14, Reg::PpcF15,
    Reg::PpcF16, Reg::PpcF17, Reg::PpcF18, Reg::PpcF19,
    Reg::PpcF20, Reg::PpcF21, Reg::PpcF22, Reg::PpcF23,
    Reg::PpcF24, Reg::PpcF25, Reg::PpcF26, Reg::PpcF27,
    Reg::PpcF28, Reg::PpcF29, Reg::PpcF30, Reg::PpcF31,
    // AArch64 X*: self-canonical.
    Reg::X0,  Reg::X1,  Reg::X2,  Reg::X3,  Reg::X4,  Reg::X5,  Reg::X6,  Reg::X7,
    Reg::X8,  Reg::X9,  Reg::X10, Reg::X11, Reg::X12, Reg::X13, Reg::X14, Reg::X15,
    Reg::X16, Reg::X17, Reg::X18, Reg::X19, Reg::X20, Reg::X21, Reg::X22, Reg::X23,
    Reg::X24, Reg::X25, Reg::X26, Reg::X27, Reg::X28, Reg::X29, Reg::X30,
    Reg::Xsp, Reg::Xzr,
    // W* canonicalise to the matching X*.
    Reg::X0,  Reg::X1,  Reg::X2,  Reg::X3,  Reg::X4,  Reg::X5,  Reg::X6,  Reg::X7,
    Reg::X8,  Reg::X9,  Reg::X10, Reg::X11, Reg::X12, Reg::X13, Reg::X14, Reg::X15,
    Reg::X16, Reg::X17, Reg::X18, Reg::X19, Reg::X20, Reg::X21, Reg::X22, Reg::X23,
    Reg::X24, Reg::X25, Reg::X26, Reg::X27, Reg::X28, Reg::X29, Reg::X30,
    Reg::Xsp, Reg::Xzr,
    // V* are self-canonical (no sub-register S*/D* views modeled yet).
    Reg::V0,  Reg::V1,  Reg::V2,  Reg::V3,  Reg::V4,  Reg::V5,  Reg::V6,  Reg::V7,
    Reg::V8,  Reg::V9,  Reg::V10, Reg::V11, Reg::V12, Reg::V13, Reg::V14, Reg::V15,
    Reg::V16, Reg::V17, Reg::V18, Reg::V19, Reg::V20, Reg::V21, Reg::V22, Reg::V23,
    Reg::V24, Reg::V25, Reg::V26, Reg::V27, Reg::V28, Reg::V29, Reg::V30, Reg::V31,
    // ARM A32 GPRs: self-canonical (no sub-register views).
    Reg::ArmR0,  Reg::ArmR1,  Reg::ArmR2,  Reg::ArmR3,
    Reg::ArmR4,  Reg::ArmR5,  Reg::ArmR6,  Reg::ArmR7,
    Reg::ArmR8,  Reg::ArmR9,  Reg::ArmR10, Reg::ArmR11, Reg::ArmR12,
    Reg::Asp, Reg::Alr, Reg::Apc,
    Reg::St0, Reg::St1, Reg::St2, Reg::St3,
    Reg::St4, Reg::St5, Reg::St6, Reg::St7,
};

// Canonical form of the last entry must still map to itself; this catches
// out-of-order sentinel moves where the table drifts off the end.
static_assert(kCanonical.back() == Reg::St7,
              "kCanonical must be updated to match Reg enum");

struct VarKey {
    u8  kind = 0;   // 0 = Reg, 1 = Flag
    u32 id   = 0;   // Reg enum value or Flag enum value

    auto operator<=>(const VarKey&) const = default;

    static VarKey of_reg(Reg r) noexcept {
        return {0, static_cast<u32>(canonical_reg(r))};
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
    // First field is u8; brace-init the integer literal as `u8{N}` so MSVC
    // doesn't fire C4244 on the int→u8 narrowing conversion.
    switch (v.kind) {
        case IrValueKind::Reg:
            return SsaKey{u8{0}, static_cast<u32>(canonical_reg(v.reg)), v.version};
        case IrValueKind::Flag:
            return SsaKey{u8{1}, static_cast<u32>(v.flag), v.version};
        case IrValueKind::Temp:
            return SsaKey{u8{2}, v.temp, 0u};
        case IrValueKind::Imm: {
            // Synthesize a stable key so memory passes can treat
            // `store [0x404018], v` as a write to a known address.
            const u64 uv = static_cast<u64>(v.imm);
            return SsaKey{u8{3},
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

// compute_rpo + compute_idoms live in <spelunk/analysis/cfg_util.hpp>.

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
    std::map<VarKey, IrType> observed_types;
    std::set<VarKey> type_conflicts;
    for (const auto& bb : fn.blocks) {
        for (const auto& inst : bb.insts) {
            if (auto v = variable_of(inst.dst); v) {
                defs[*v].insert(bb.start);
                auto [it, inserted] = observed_types.emplace(*v, inst.dst.type);
                if (!inserted && it->second != inst.dst.type) type_conflicts.insert(*v);
            }
        }
    }

    // Phis are staged per block and spliced once. Repeated insert-at-front
    // into a block's instruction vector is O(k^2) element shifting for k
    // phis, which compounds on large functions with thousands of defs.
    // Splicing in reverse arrival order ahead of the existing instructions
    // keeps the final layout identical to the old front-insertion behavior.
    std::map<addr_t, std::vector<IrInst>> staged;

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
                    IrType type = is_ppc_fpr(canon) ? IrType::F64
                                                    : type_for_bits(reg_size(canon) * 8);
                    const auto observed = observed_types.find(var);
                    const bool is_ppc_register =
                        canon >= Reg::PpcR0 && canon <= Reg::PpcF31;
                    const bool is_x86_gpr = canon >= Reg::Rax && canon <= Reg::Rdi;
                    if ((is_ppc_register || is_x86_gpr) &&
                        observed != observed_types.end() &&
                        !type_conflicts.contains(var)) {
                        // PPC register width is ABI-dependent (32-bit on Wii),
                        // and paired-single FPRs carry a vector type. The
                        // legacy x86 GPRs are 32-bit in protected mode. Preserve
                        // the lifter's concrete type instead of reconstructing
                        // it from the architecture-neutral register size.
                        type = observed->second;
                    }
                    phi.dst = IrValue::make_reg(canon, type);
                } else {
                    phi.dst = IrValue::make_flag(static_cast<Flag>(var.id));
                }
                for (addr_t p : by.predecessors) {
                    phi.phi_operands.push_back(phi.dst);
                    phi.phi_preds.push_back(p);
                }

                staged[y].push_back(std::move(phi));

                if (!def_sites.contains(y)) {
                    wl.push_back(y);
                }
            }
        }
    }

    for (auto& [y, phis] : staged) {
        auto yit = fn.block_at.find(y);
        if (yit == fn.block_at.end()) continue;
        auto& insts = fn.blocks[yit->second].insts;
        std::vector<IrInst> merged;
        merged.reserve(phis.size() + insts.size());
        for (auto pit = phis.rbegin(); pit != phis.rend(); ++pit)
            merged.push_back(std::move(*pit));
        merged.insert(merged.end(),
                      std::move_iterator(insts.begin()),
                      std::move_iterator(insts.end()));
        insts = std::move(merged);
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

    // Explicit-frame preorder walk of the dominator tree - the same
    // treatment compute_rpo already received. The previous recursive
    // lambda overflowed the call stack on deep pathological CFGs (long
    // if/else chains, huge straight-line runs). Traversal order is kept
    // byte-identical: children ascending by address, version counters
    // bumped on entry, SSA stacks popped when the frame is left.
    struct Frame {
        addr_t              node;
        std::size_t         next_child = 0;
        std::vector<VarKey> defined_here;
    };
    std::vector<Frame> stack;

    auto enter = [&](Frame& fr) {
        auto it = fn.block_at.find(fr.node);
        if (it == fn.block_at.end()) return;
        auto& bb = fn.blocks[it->second];

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
                fr.defined_here.push_back(*dv);
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
                // Fill every operand slot whose predecessor matches the
                // current block. If a CFG has parallel edges from this
                // block to the same successor (a Conditional whose two
                // arms target the same block, for instance), the
                // predecessor list contains the source twice and BOTH
                // operand slots need the renamed version. Breaking
                // after the first match left the second slot at
                // version 0, surfacing as a phantom live-in elsewhere.
                for (std::size_t k = 0; k < inst.phi_preds.size(); ++k) {
                    if (inst.phi_preds[k] == fr.node &&
                        k < inst.phi_operands.size()) {
                        inst.phi_operands[k].version = cur;
                    }
                }
            }
        }
    };

    auto leave = [&](Frame& fr) {
        for (const VarKey& v : fr.defined_here) {
            auto& st = stacks[v];
            if (!st.empty()) st.pop_back();
        }
    };

    // A missing start block means nothing is reachable from the dominator
    // tree's root: the old recursion returned before visiting any child,
    // so mirror that and rename nothing.
    if (fn.block_at.find(fn.start) == fn.block_at.end()) return;

    stack.push_back(Frame{fn.start, 0, {}});
    enter(stack.back());

    while (!stack.empty()) {
        Frame& top = stack.back();
        auto   cit = children.find(top.node);
        if (cit != children.end() && top.next_child < cit->second.size()) {
            const addr_t c = cit->second[top.next_child++];
            stack.push_back(Frame{c, 0, {}});
            enter(stack.back());
        } else {
            leave(top);
            stack.pop_back();
        }
    }
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
    for (std::size_t i = 0; i < rpo.size(); ++i)
        rpo_index[rpo[i]] = i;

    const auto idoms = compute_idoms(fn, rpo, rpo_index);
    const auto df    = compute_df(fn, idoms);

    insert_phis(fn, df);
    rename_variables(fn, idoms);

    return {};
}

}  // namespace spelunk
