#include <ember/ir/passes.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <map>
#include <optional>
#include <span>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

#include <ember/common/types.hpp>
#include <ember/ir/ssa.hpp>

namespace ember {

namespace {

// ============================================================================
// Mask i64 result to an IrType width (sign-extending from low bits)
// ============================================================================

// Helper bound: i64 representation. Widths > 64 (I128) can't fit and don't
// occur on the constant-fold path — SIMD never folds through these helpers.
// Guarded with a passthrough so a future code path that DOES hit them won't
// silently corrupt; the i64 payload is returned unchanged.
[[nodiscard]] i64 mask_signed(i64 v, IrType t) noexcept {
    const unsigned bits = type_bits(t);
    if (bits == 0 || bits >= 64) return v;
    const unsigned sign_bit = bits - 1;
    const u64 mask = (u64(1) << bits) - 1;
    u64 u = static_cast<u64>(v) & mask;
    if (u & (u64(1) << sign_bit)) u |= ~mask;
    return static_cast<i64>(u);
}

[[nodiscard]] u64 mask_unsigned(i64 v, IrType t) noexcept {
    const unsigned bits = type_bits(t);
    if (bits >= 64) return static_cast<u64>(v);
    const u64 mask = (u64(1) << bits) - 1;
    return static_cast<u64>(v) & mask;
}

// ============================================================================
// Iterate over value references in an instruction
// ============================================================================

template <class F>
void for_each_use(IrInst& inst, F f) {
    if (inst.op == IrOp::Phi) {
        for (auto& v : inst.phi_operands) f(v);
    } else {
        for (u8 k = 0; k < inst.src_count && k < inst.srcs.size(); ++k) {
            f(inst.srcs[k]);
        }
    }
}

template <class F>
void for_each_use(const IrInst& inst, F f) {
    if (inst.op == IrOp::Phi) {
        for (const auto& v : inst.phi_operands) f(v);
    } else {
        for (u8 k = 0; k < inst.src_count && k < inst.srcs.size(); ++k) {
            f(inst.srcs[k]);
        }
    }
}

// ============================================================================
// AnalysisManager — lazy, invalidatable function-wide analyses
// ============================================================================
//
// Today there's just one cached analysis: a `SsaKey -> (block, inst)` map of
// every instruction's SSA-keyed dst. cast_simplify, trivial_phi, and dce all
// used to rebuild this independently each call; the manager builds it once
// per fixpoint iteration and only rebuilds after a pass that mutates dst
// locations (currently just DCE, which deletes instructions).

struct DefLoc { u32 block; u32 inst; };

// SsaKey is std::tuple<u8, u32, u32>; the standard library doesn't auto-
// hash tuples, so the cleanup pipeline historically stored its lookups
// in std::map<SsaKey, …> (red-black tree, every probe = O(log N) plus
// a heap-allocated node per insert). Profiling on ember-on-itself
// identified copy_prop, trivial_phi, and the def-map cache as hot — all
// of them are hash-shaped lookups by their nature. A simple mix of the
// three fields is enough; all SsaKeys with kind != 3 (Imm) have the
// version field 0 most of the time, so we make sure it's mixed in too.
struct SsaKeyHash {
    [[nodiscard]] std::size_t operator()(const SsaKey& k) const noexcept {
        const auto [kind, id, ver] = k;
        u64 h = static_cast<u64>(id) * 0x9E3779B97F4A7C15ull;
        h ^= static_cast<u64>(ver) * 0xBF58476D1CE4E5B9ull;
        h ^= static_cast<u64>(kind) * 0x94D049BB133111EBull;
        h ^= h >> 30;
        return static_cast<std::size_t>(h);
    }
};

template <typename V>
using SsaMap = std::unordered_map<SsaKey, V, SsaKeyHash>;

class AnalysisManager {
public:
    void invalidate_defs() noexcept { def_map_.reset(); }

    const SsaMap<DefLoc>& defs(const IrFunction& fn) {
        if (!def_map_) {
            SsaMap<DefLoc> m;
            // Reserve up-front so the rehash storm during construction
            // turns into a single allocation. ~1 entry per IR inst is a
            // safe upper bound (only insts with stable dsts contribute).
            std::size_t reserve = 0;
            for (const auto& bb : fn.blocks) reserve += bb.insts.size();
            m.reserve(reserve);
            for (u32 bi = 0; bi < fn.blocks.size(); ++bi) {
                const auto& bb = fn.blocks[bi];
                for (u32 ii = 0; ii < bb.insts.size(); ++ii) {
                    if (auto k = ssa_key(bb.insts[ii].dst); k) {
                        m[*k] = {bi, ii};
                    }
                }
            }
            def_map_ = std::move(m);
        }
        return *def_map_;
    }

private:
    std::optional<SsaMap<DefLoc>> def_map_;
};

// Walk either a caller-supplied block list or all blocks. Pass entries use
// this so the same body handles both first-iteration full sweeps and
// subsequent dirty-only sweeps.
template <class F>
void for_blocks(IrFunction& fn, std::span<const u32> blocks, F f) {
    for (u32 bi : blocks) f(bi, fn.blocks[bi]);
}

// ============================================================================
// Pass: constant folding + identity folding
// ============================================================================

[[nodiscard]] std::optional<IrValue>
try_fold(const IrInst& inst) noexcept {
    const IrType dt = inst.dst.type;

    // Unary
    if (inst.src_count == 1) {
        const auto& a = inst.srcs[0];
        if (a.kind != IrValueKind::Imm) return std::nullopt;
        switch (inst.op) {
            case IrOp::Neg:   return IrValue::make_imm(mask_signed(-a.imm, dt), dt);
            case IrOp::Not:   return IrValue::make_imm(mask_signed(~a.imm, dt), dt);
            case IrOp::ZExt:  return IrValue::make_imm(
                                  static_cast<i64>(mask_unsigned(a.imm, a.type)), dt);
            case IrOp::SExt:  return IrValue::make_imm(mask_signed(a.imm, a.type), dt);
            case IrOp::Trunc: return IrValue::make_imm(mask_signed(a.imm, dt), dt);
            case IrOp::Assign:
                if (a.kind == IrValueKind::Imm) return a;
                return std::nullopt;
            default: return std::nullopt;
        }
    }

    // Binary
    if (inst.src_count == 2) {
        const auto& a = inst.srcs[0];
        const auto& b = inst.srcs[1];
        const bool ai = a.kind == IrValueKind::Imm;
        const bool bi = b.kind == IrValueKind::Imm;

        // Identities (work even with non-constants)
        switch (inst.op) {
            case IrOp::Add:
                if (ai && a.imm == 0) return b;
                if (bi && b.imm == 0) return a;
                break;
            case IrOp::Sub:
                if (bi && b.imm == 0) return a;
                if (same_ssa_value(a, b)) return IrValue::make_imm(0, dt);
                break;
            case IrOp::Mul:
                if (ai && a.imm == 0) return IrValue::make_imm(0, dt);
                if (bi && b.imm == 0) return IrValue::make_imm(0, dt);
                if (ai && a.imm == 1) return b;
                if (bi && b.imm == 1) return a;
                break;
            case IrOp::Div:
                if (bi && b.imm == 1) return a;
                if (same_ssa_value(a, b)) return IrValue::make_imm(1, dt);
                break;
            case IrOp::Mod:
                if (bi && b.imm == 1) return IrValue::make_imm(0, dt);
                if (same_ssa_value(a, b)) return IrValue::make_imm(0, dt);
                break;
            case IrOp::And:
                if (ai && a.imm == 0) return IrValue::make_imm(0, dt);
                if (bi && b.imm == 0) return IrValue::make_imm(0, dt);
                if (same_ssa_value(a, b)) return a;
                break;
            case IrOp::Or:
                if (ai && a.imm == 0) return b;
                if (bi && b.imm == 0) return a;
                if (same_ssa_value(a, b)) return a;
                break;
            case IrOp::Xor:
                if (ai && a.imm == 0) return b;
                if (bi && b.imm == 0) return a;
                if (same_ssa_value(a, b)) return IrValue::make_imm(0, dt);
                break;
            case IrOp::Shl:
            case IrOp::Lshr:
            case IrOp::Ashr:
                if (bi && b.imm == 0) return a;
                break;
            default:
                break;
        }

        if (!ai || !bi) return std::nullopt;

        // Full constant folding
        switch (inst.op) {
            case IrOp::Add: return IrValue::make_imm(mask_signed(a.imm + b.imm, dt), dt);
            case IrOp::Sub: return IrValue::make_imm(mask_signed(a.imm - b.imm, dt), dt);
            case IrOp::Mul: return IrValue::make_imm(mask_signed(a.imm * b.imm, dt), dt);
            // IrOp::Div / IrOp::Mod don't carry signedness — the same opcode
            // is emitted for both DIV (unsigned) and IDIV (signed) lowerings.
            // Folding with C++ `/` and `%` always uses signed semantics, so
            // an unsigned divide of operands with the high bit set in their
            // operand width produces wrong arithmetic. Skip the fold; the
            // emitter prints `a / b` literally, which is correct C as long as
            // the operand types match — the optimization opportunity is
            // small (constant-by-constant divides are rare in real code) and
            // not worth the silent miscomputation.
            case IrOp::Div:
            case IrOp::Mod:
                return std::nullopt;
            case IrOp::And: return IrValue::make_imm(mask_signed(a.imm & b.imm, dt), dt);
            case IrOp::Or:  return IrValue::make_imm(mask_signed(a.imm | b.imm, dt), dt);
            case IrOp::Xor: return IrValue::make_imm(mask_signed(a.imm ^ b.imm, dt), dt);
            case IrOp::Shl: {
                const unsigned shift = static_cast<unsigned>(b.imm) & 63u;
                return IrValue::make_imm(
                    mask_signed(static_cast<i64>(static_cast<u64>(a.imm) << shift), dt), dt);
            }
            case IrOp::Lshr: {
                const unsigned shift = static_cast<unsigned>(b.imm) & 63u;
                const u64 av = mask_unsigned(a.imm, a.type);
                return IrValue::make_imm(static_cast<i64>(av >> shift), dt);
            }
            case IrOp::Ashr: {
                const unsigned shift = static_cast<unsigned>(b.imm) & 63u;
                return IrValue::make_imm(mask_signed(a.imm >> shift, dt), dt);
            }
            case IrOp::CmpEq:  return IrValue::make_imm(a.imm == b.imm ? 1 : 0, IrType::I1);
            case IrOp::CmpNe:  return IrValue::make_imm(a.imm != b.imm ? 1 : 0, IrType::I1);
            case IrOp::CmpSlt: return IrValue::make_imm(a.imm <  b.imm ? 1 : 0, IrType::I1);
            case IrOp::CmpSle: return IrValue::make_imm(a.imm <= b.imm ? 1 : 0, IrType::I1);
            case IrOp::CmpSgt: return IrValue::make_imm(a.imm >  b.imm ? 1 : 0, IrType::I1);
            case IrOp::CmpSge: return IrValue::make_imm(a.imm >= b.imm ? 1 : 0, IrType::I1);
            // Unsigned compares: i64 imms are sign-extended into the i64
            // payload, so a 32-bit value of 0x80000000 is stored as
            // 0xffffffff80000000. A direct cast to u64 reads it as a huge
            // unsigned number instead of 2147483648. Mask to the operand
            // width first so the comparison reflects the actual u32/u16/u8
            // value the program intended.
            case IrOp::CmpUlt:
                return IrValue::make_imm(mask_unsigned(a.imm, a.type) <  mask_unsigned(b.imm, b.type) ? 1 : 0, IrType::I1);
            case IrOp::CmpUle:
                return IrValue::make_imm(mask_unsigned(a.imm, a.type) <= mask_unsigned(b.imm, b.type) ? 1 : 0, IrType::I1);
            case IrOp::CmpUgt:
                return IrValue::make_imm(mask_unsigned(a.imm, a.type) >  mask_unsigned(b.imm, b.type) ? 1 : 0, IrType::I1);
            case IrOp::CmpUge:
                return IrValue::make_imm(mask_unsigned(a.imm, a.type) >= mask_unsigned(b.imm, b.type) ? 1 : 0, IrType::I1);
            default: return std::nullopt;
        }
    }

    // Ternary
    if (inst.src_count == 3 && inst.op == IrOp::Select) {
        const auto& c = inst.srcs[0];
        const auto& t = inst.srcs[1];
        const auto& f = inst.srcs[2];
        if (c.kind == IrValueKind::Imm) {
            return c.imm ? t : f;
        }
        if (same_ssa_value(t, f)) return t;
    }

    return std::nullopt;
}

[[nodiscard]] std::size_t pass_constant_fold(
    IrFunction& fn, AnalysisManager& /*am*/,
    std::span<const u32> dirty, std::vector<u32>& touched)
{
    std::size_t count = 0;
    for_blocks(fn, dirty, [&](u32 bi, IrBlock& bb) {
        const std::size_t before = count;
        for (auto& inst : bb.insts) {
            if (inst.op == IrOp::Assign || inst.op == IrOp::Nop) continue;
            if (inst.op == IrOp::Phi) continue;
            auto folded = try_fold(inst);
            if (!folded) continue;
            if (folded->type != inst.dst.type) {
                folded->type = inst.dst.type;
            }
            inst.op        = IrOp::Assign;
            inst.srcs[0]   = *folded;
            inst.srcs[1]   = IrValue{};
            inst.srcs[2]   = IrValue{};
            inst.src_count = 1;
            ++count;
        }
        if (count != before) touched.push_back(bi);
    });
    return count;
}

// ============================================================================
// Pass: copy propagation
// ============================================================================
//
// Whole-function: builds the substitution map from every Assign in the
// function and applies it to every use site. Cannot scope to dirty blocks
// because a new Assign in a dirty block can propagate into uses anywhere.
// We do still report the blocks where substitutions actually landed so the
// next iteration can scope per-block passes appropriately.

[[nodiscard]] std::size_t pass_copy_prop(
    IrFunction& fn, AnalysisManager& /*am*/,
    std::span<const u32> /*dirty*/, std::vector<u32>& touched)
{
    SsaMap<IrValue> subst;

    for (const auto& bb : fn.blocks) {
        for (const auto& inst : bb.insts) {
            if (inst.op != IrOp::Assign) continue;
            if (inst.src_count != 1) continue;
            const auto& src = inst.srcs[0];
            if (src.kind == IrValueKind::None) continue;
            if (src.type != inst.dst.type) continue;
            auto k = ssa_key(inst.dst);
            if (!k) continue;
            subst[*k] = src;
        }
    }
    if (subst.empty()) return 0;

    // Chase transitively
    for (auto& [k, v] : subst) {
        int guard = 0;
        while (guard++ < 256) {
            auto vk = ssa_key(v);
            if (!vk) break;
            auto it = subst.find(*vk);
            if (it == subst.end()) break;
            if (it->second.type != v.type) break;
            if (ssa_key(it->second) == vk) break;
            v = it->second;
        }
    }

    std::size_t count = 0;
    for (u32 bi = 0; bi < fn.blocks.size(); ++bi) {
        auto& bb = fn.blocks[bi];
        const std::size_t before = count;
        auto apply = [&](IrValue& v) {
            auto k = ssa_key(v);
            if (!k) return;
            auto it = subst.find(*k);
            if (it == subst.end()) return;
            if (it->second.type != v.type) return;
            if (same_ssa_value(v, it->second)) return;
            v = it->second;
            ++count;
        };
        for (auto& inst : bb.insts) {
            for_each_use(inst, apply);
        }
        if (count != before) touched.push_back(bi);
    }
    return count;
}

// ============================================================================
// Pass: trivial phi elimination
// ============================================================================

[[nodiscard]] std::size_t pass_trivial_phi(
    IrFunction& fn, AnalysisManager& am,
    std::span<const u32> /*dirty*/, std::vector<u32>& touched)
{
    SsaMap<IrValue> subst;
    std::size_t removed = 0;

    // Pre-index all defs so we can chase Assign chains when comparing phi
    // operands. Without this, `phi(rax_7, t28)` where `t28 = Assign(rax_7)`
    // looks non-trivial to the operand-equality check, and rax stays phi'd
    // — the pattern that produces the `rax_10` leaks in the emitter.
    const auto& defs = am.defs(fn);
    auto strip_assigns = [&](IrValue v) {
        for (int hop = 0; hop < 16; ++hop) {
            auto k = ssa_key(v);
            if (!k) return v;
            auto it = defs.find(*k);
            if (it == defs.end()) return v;
            const IrInst& d = fn.blocks[it->second.block].insts[it->second.inst];
            if (d.op != IrOp::Assign || d.src_count != 1) return v;
            if (d.srcs[0].type != v.type) return v;  // type-shifting assign
            v = d.srcs[0];
        }
        return v;
    };
    auto equivalent = [&](const IrValue& a, const IrValue& b) {
        return same_ssa_value(strip_assigns(a), strip_assigns(b));
    };

    for (u32 bi = 0; bi < fn.blocks.size(); ++bi) {
        auto& bb = fn.blocks[bi];
        bool removed_here = false;
        for (auto& inst : bb.insts) {
            if (inst.op != IrOp::Phi) continue;

            auto dst_key = ssa_key(inst.dst);
            if (!dst_key) continue;

            std::optional<IrValue> unique;
            bool trivial = true;

            for (const auto& op : inst.phi_operands) {
                auto op_key = ssa_key(op);
                if (op_key && *op_key == *dst_key) continue;  // self-reference
                if (!unique) {
                    unique = op;
                } else if (!equivalent(*unique, op)) {
                    trivial = false;
                    break;
                }
            }

            if (trivial && unique) {
                subst[*dst_key] = strip_assigns(*unique);
                inst.op = IrOp::Nop;
                inst.phi_operands.clear();
                inst.phi_preds.clear();
                inst.src_count = 0;
                ++removed;
                removed_here = true;
            }
        }
        if (removed_here) touched.push_back(bi);
    }
    if (subst.empty()) return removed;

    // Chase
    for (auto& [k, v] : subst) {
        int guard = 0;
        while (guard++ < 256) {
            auto vk = ssa_key(v);
            if (!vk) break;
            auto it = subst.find(*vk);
            if (it == subst.end()) break;
            if (it->second.type != v.type) break;
            if (ssa_key(it->second) == vk) break;
            v = it->second;
        }
    }

    for (u32 bi = 0; bi < fn.blocks.size(); ++bi) {
        auto& bb = fn.blocks[bi];
        bool applied_here = false;
        auto apply = [&](IrValue& v) {
            auto k = ssa_key(v);
            if (!k) return;
            auto it = subst.find(*k);
            if (it == subst.end()) return;
            if (it->second.type != v.type) return;
            v = it->second;
            applied_here = true;
        };
        for (auto& inst : bb.insts) {
            for_each_use(inst, apply);
        }
        if (applied_here) touched.push_back(bi);
    }

    return removed;
}

// ============================================================================
// Pass: dead code elimination
// ============================================================================

[[nodiscard]] bool is_side_effect(IrOp op) noexcept {
    switch (op) {
        case IrOp::Store:
        case IrOp::Branch:
        case IrOp::BranchIndirect:
        case IrOp::CondBranch:
        case IrOp::Call:
        case IrOp::CallIndirect:
        case IrOp::Return:
        case IrOp::Unreachable:
        case IrOp::Intrinsic:
            return true;
        default:
            return false;
    }
}

// ============================================================================
// Pass: local GVN (intra-block value numbering)
// ============================================================================
//
// Collapses duplicate pure computations within a block into a single temp,
// so that downstream consumers (including memory_forward) see stable SSA
// identities for equivalent expressions like `rsp - 0x14`, which the lifter
// emits afresh every time it computes an effective address.

struct GvnOp {
    u8                                               op;      // IrOp cast
    u8                                               type;    // dst IrType
    std::array<std::optional<SsaKey>, 3>             src_keys;
    std::array<i64, 3>                               imm_vals;
    std::array<u8,  3>                               src_forms;  // 0=None, 1=Imm, 2=Key

    bool operator<(const GvnOp& o) const noexcept {
        if (op    != o.op)    return op    < o.op;
        if (type  != o.type)  return type  < o.type;
        for (std::size_t i = 0; i < 3; ++i) {
            if (src_forms[i] != o.src_forms[i]) return src_forms[i] < o.src_forms[i];
            if (src_forms[i] == 1) {
                if (imm_vals[i] != o.imm_vals[i]) return imm_vals[i] < o.imm_vals[i];
            } else if (src_forms[i] == 2) {
                if (src_keys[i] != o.src_keys[i]) return src_keys[i] < o.src_keys[i];
            }
        }
        return false;
    }
};

[[nodiscard]] bool gvn_eligible(IrOp op) noexcept {
    switch (op) {
        case IrOp::Add: case IrOp::Sub: case IrOp::Mul:
        case IrOp::And: case IrOp::Or:  case IrOp::Xor:
        case IrOp::Neg: case IrOp::Not:
        case IrOp::Shl: case IrOp::Lshr: case IrOp::Ashr:
        case IrOp::CmpEq: case IrOp::CmpNe:
        case IrOp::CmpUlt: case IrOp::CmpUle: case IrOp::CmpUgt: case IrOp::CmpUge:
        case IrOp::CmpSlt: case IrOp::CmpSle: case IrOp::CmpSgt: case IrOp::CmpSge:
        case IrOp::ZExt: case IrOp::SExt: case IrOp::Trunc:
            return true;
        default:
            return false;
    }
}

[[nodiscard]] std::optional<GvnOp> gvn_key_of(const IrInst& inst) noexcept {
    if (!gvn_eligible(inst.op)) return std::nullopt;
    GvnOp g{};
    g.op   = static_cast<u8>(inst.op);
    g.type = static_cast<u8>(inst.dst.type);
    for (u8 i = 0; i < inst.src_count && i < 3; ++i) {
        const IrValue& v = inst.srcs[i];
        if (v.kind == IrValueKind::Imm) {
            g.src_forms[i] = 1;
            g.imm_vals[i]  = v.imm;
        } else if (auto k = ssa_key(v); k) {
            g.src_forms[i] = 2;
            g.src_keys[i]  = *k;
        } else {
            return std::nullopt;  // un-keyable operand; give up on this inst
        }
    }
    return g;
}

[[nodiscard]] std::size_t pass_local_gvn(
    IrFunction& fn, AnalysisManager& /*am*/,
    std::span<const u32> dirty, std::vector<u32>& touched)
{
    std::size_t count = 0;
    for_blocks(fn, dirty, [&](u32 bi, IrBlock& bb) {
        const std::size_t before = count;
        std::map<GvnOp, IrValue> seen;
        for (auto& inst : bb.insts) {
            auto k = gvn_key_of(inst);
            if (!k) continue;
            auto it = seen.find(*k);
            if (it == seen.end()) {
                seen.emplace(*k, inst.dst);
                continue;
            }
            if (it->second.type != inst.dst.type) continue;
            inst.op        = IrOp::Assign;
            inst.srcs[0]   = it->second;
            inst.srcs[1]   = IrValue{};
            inst.srcs[2]   = IrValue{};
            inst.src_count = 1;
            ++count;
        }
        if (count != before) touched.push_back(bi);
    });
    return count;
}

// ============================================================================
// Pass: intra-block dead-store elimination
// ============================================================================

[[nodiscard]] std::size_t pass_dead_store_elim(
    IrFunction& fn, AnalysisManager& /*am*/,
    std::span<const u32> dirty, std::vector<u32>& touched)
{
    std::size_t count = 0;
    for_blocks(fn, dirty, [&](u32 bi, IrBlock& bb) {
        const std::size_t before = count;
        SsaMap<std::pair<std::size_t, IrType>> last_store;
        for (std::size_t i = 0; i < bb.insts.size(); ++i) {
            auto& inst = bb.insts[i];
            switch (inst.op) {
                case IrOp::Store: {
                    if (inst.src_count < 2) break;
                    auto k = ssa_key(inst.srcs[0]);
                    if (!k) { last_store.clear(); break; }
                    const IrType new_ty = inst.srcs[1].type;
                    auto it = last_store.find(*k);
                    if (it != last_store.end() && it->second.second == new_ty) {
                        auto& prior = bb.insts[it->second.first];
                        prior.op        = IrOp::Nop;
                        prior.src_count = 0;
                        prior.srcs      = {};
                        prior.segment   = Reg::None;
                        ++count;
                    }
                    last_store[*k] = {i, new_ty};
                    break;
                }
                case IrOp::Load: {
                    if (inst.src_count < 1) break;
                    if (auto k = ssa_key(inst.srcs[0]); k) {
                        last_store.erase(*k);
                    }
                    break;
                }
                case IrOp::Call:
                case IrOp::CallIndirect:
                case IrOp::Intrinsic:
                    last_store.clear();
                    break;
                default:
                    break;
            }
        }
        if (count != before) touched.push_back(bi);
    });
    return count;
}

// ============================================================================
// Pass: intra-block store-to-load forwarding (memory SSA, lightweight)
// ============================================================================

[[nodiscard]] std::size_t pass_memory_forward(
    IrFunction& fn, AnalysisManager& /*am*/,
    std::span<const u32> dirty, std::vector<u32>& touched)
{
    std::size_t count = 0;
    for_blocks(fn, dirty, [&](u32 bi, IrBlock& bb) {
        const std::size_t before = count;
        SsaMap<IrValue> stored;
        for (auto& inst : bb.insts) {
            switch (inst.op) {
                case IrOp::Store: {
                    if (inst.src_count < 2) break;
                    auto k = ssa_key(inst.srcs[0]);
                    if (!k) { stored.clear(); break; }
                    stored[*k] = inst.srcs[1];
                    break;
                }
                case IrOp::Load: {
                    if (inst.src_count >= 1) {
                        auto k = ssa_key(inst.srcs[0]);
                        if (!k) break;
                        auto it = stored.find(*k);
                        if (it == stored.end()) break;
                        if (it->second.type != inst.dst.type) break;
                        inst.op        = IrOp::Assign;
                        inst.srcs[0]   = it->second;
                        inst.src_count = 1;
                        inst.segment   = Reg::None;
                        ++count;
                    }
                    break;
                }
                case IrOp::Call:
                case IrOp::CallIndirect:
                case IrOp::Intrinsic:
                    stored.clear();
                    break;
                default:
                    break;
            }
        }
        if (count != before) touched.push_back(bi);
    });
    return count;
}

// ============================================================================
// Pass: cast simplification
// ============================================================================

[[nodiscard]] std::size_t pass_cast_simplify(
    IrFunction& fn, AnalysisManager& am,
    std::span<const u32> dirty, std::vector<u32>& touched)
{
    const auto& defs = am.defs(fn);

    auto is_cast = [](IrOp op) noexcept {
        return op == IrOp::Trunc || op == IrOp::ZExt || op == IrOp::SExt;
    };

    std::size_t changes = 0;
    for_blocks(fn, dirty, [&](u32 bi, IrBlock& bb) {
        const std::size_t before = changes;
        for (auto& inst : bb.insts) {
            if (!is_cast(inst.op)) continue;
            if (inst.src_count != 1) continue;
            const IrValue& src = inst.srcs[0];
            const IrType   dt  = inst.dst.type;

            // Identity: cast to same type is a no-op.
            if (src.type == dt) {
                inst.op = IrOp::Assign;
                ++changes;
                continue;
            }

            auto k = ssa_key(src);
            if (!k) continue;
            auto it = defs.find(*k);
            if (it == defs.end()) continue;
            const IrInst* def = &fn.blocks[it->second.block].insts[it->second.inst];
            if (!is_cast(def->op) || def->src_count != 1) continue;
            const IrValue& inner = def->srcs[0];

            if (inst.op == IrOp::Trunc) {
                if ((def->op == IrOp::ZExt || def->op == IrOp::SExt) &&
                    inner.type == dt) {
                    inst.op      = IrOp::Assign;
                    inst.srcs[0] = inner;
                    ++changes;
                    continue;
                }
                // Trunc-of-ZExt: the zero-extended high bits never survive
                // the trunc, so this collapses to a direct trunc of the
                // original value (or no-op when widths match by construction).
                // ZExt sign-agnosticism extends to the SExt case when the
                // outer trunc width fits inside the original (sign bits we'd
                // be testing are below the trunc cut-off).
                if ((def->op == IrOp::ZExt || def->op == IrOp::SExt) &&
                    type_bits(dt) <= type_bits(inner.type)) {
                    inst.srcs[0] = inner;  // Trunc(<ext>(x)) → Trunc(x)
                    ++changes;
                    continue;
                }
                // Trunc-of-ZExt where the trunc widens past the original:
                // `Trunc i32 (ZExt i64 (i8 x))` is just `ZExt i32 x`. The
                // trunc never reaches into the zero-extended bytes, so the
                // chain reduces to one widening step. SExt mirrors when
                // signedness of the result matches the input's sign domain.
                if (def->op == IrOp::ZExt &&
                    type_bits(dt) > type_bits(inner.type)) {
                    inst.op      = IrOp::ZExt;
                    inst.srcs[0] = inner;
                    ++changes;
                    continue;
                }
                if (def->op == IrOp::SExt &&
                    type_bits(dt) > type_bits(inner.type)) {
                    inst.op      = IrOp::SExt;
                    inst.srcs[0] = inner;
                    ++changes;
                    continue;
                }
                if (def->op == IrOp::Trunc && type_bits(inner.type) >= type_bits(dt)) {
                    inst.srcs[0] = inner;  // Trunc(Trunc(x)) → Trunc(x)
                    ++changes;
                    continue;
                }
            }

            if ((inst.op == IrOp::ZExt && def->op == IrOp::ZExt) ||
                (inst.op == IrOp::SExt && def->op == IrOp::SExt)) {
                if (type_bits(inner.type) <= type_bits(dt)) {
                    inst.srcs[0] = inner;  // ZExt(ZExt(x)) → ZExt(x)
                    ++changes;
                    continue;
                }
            }
        }
        if (changes != before) touched.push_back(bi);
    });
    return changes;
}

[[nodiscard]] std::size_t pass_dce(
    IrFunction& fn, AnalysisManager& am,
    std::span<const u32> /*dirty*/, std::vector<u32>& touched)
{
    const auto& defs = am.defs(fn);

    // Live set as a per-block bitvector. Encoded as one big flat vector
    // with per-block offset table — measurably faster than the previous
    // `std::set<pair<size_t,size_t>>` for hot binaries because the
    // hash/lookup turns into a single byte read, no heap traffic, and
    // the worklist below allocates once. (~3.5x speedup on the cleanup
    // pipeline measured against ember-on-itself.)
    std::vector<std::size_t> bb_offsets(fn.blocks.size() + 1, 0);
    for (std::size_t bi = 0; bi < fn.blocks.size(); ++bi) {
        bb_offsets[bi + 1] = bb_offsets[bi] + fn.blocks[bi].insts.size();
    }
    const std::size_t total_insts = bb_offsets.back();
    std::vector<u8> live(total_insts, 0);
    auto live_idx = [&](std::size_t bi, std::size_t ii) {
        return bb_offsets[bi] + ii;
    };
    auto mark_live = [&](std::size_t bi, std::size_t ii) {
        const std::size_t idx = live_idx(bi, ii);
        if (live[idx]) return false;
        live[idx] = 1;
        return true;
    };

    std::vector<std::pair<u32, u32>> wl;
    wl.reserve(64);
    for (std::size_t bi = 0; bi < fn.blocks.size(); ++bi) {
        auto& bb = fn.blocks[bi];
        for (std::size_t ii = 0; ii < bb.insts.size(); ++ii) {
            if (is_side_effect(bb.insts[ii].op)) {
                if (mark_live(bi, ii)) {
                    wl.push_back({static_cast<u32>(bi), static_cast<u32>(ii)});
                }
            }
        }
    }

    while (!wl.empty()) {
        const auto [bi, ii] = wl.back();
        wl.pop_back();
        const auto& inst = fn.blocks[bi].insts[ii];
        for_each_use(inst, [&](const IrValue& v) {
            auto k = ssa_key(v);
            if (!k) return;
            auto it = defs.find(*k);
            if (it == defs.end()) return;
            const DefLoc loc = it->second;
            if (mark_live(loc.block, loc.inst)) {
                wl.push_back({static_cast<u32>(loc.block),
                              static_cast<u32>(loc.inst)});
            }
        });
    }

    std::size_t removed = 0;
    for (std::size_t bi = 0; bi < fn.blocks.size(); ++bi) {
        auto& bb = fn.blocks[bi];
        const std::size_t base = bb_offsets[bi];
        // Pre-flight: scan once to see if anything will be removed. The
        // common case after the first iteration is "block already clean",
        // and this lets us skip the kept-vector rebuild + move entirely.
        bool any_dead = false;
        for (std::size_t ii = 0; ii < bb.insts.size(); ++ii) {
            const auto& inst = bb.insts[ii];
            if (inst.op == IrOp::Nop) { any_dead = true; break; }
            if (!live[base + ii] && !is_side_effect(inst.op)) {
                any_dead = true; break;
            }
        }
        if (!any_dead) continue;

        const std::size_t before = removed;
        std::size_t write = 0;
        for (std::size_t ii = 0; ii < bb.insts.size(); ++ii) {
            auto& inst = bb.insts[ii];
            if (inst.op == IrOp::Nop) { ++removed; continue; }
            if (live[base + ii] || is_side_effect(inst.op)) {
                if (write != ii) bb.insts[write] = std::move(inst);
                ++write;
            } else {
                ++removed;
            }
        }
        bb.insts.resize(write);
        if (removed != before) touched.push_back(static_cast<u32>(bi));
    }
    return removed;
}

// ============================================================================
// PassManager — fixpoint driver with per-block dirty tracking
// ============================================================================
//
// Iteration 0 sweeps all blocks. After each iteration, the union of blocks
// that any pass actually mutated becomes the input dirty set for the next
// iteration; per-block passes restrict their work to that set, while
// whole-function passes (copy_prop, trivial_phi, dce) still run but skip
// quickly if no Assigns / Phis / dead insts changed shape.
//
// DCE is the only pass that mutates instruction *locations* (it deletes
// Nops and dead insts), so it's the only pass that invalidates the cached
// def map.

CleanupStats run_pipeline(IrFunction& fn) {
    CleanupStats stats;
    AnalysisManager am;
    constexpr std::size_t kMaxIter = 16;

    std::vector<u32> dirty;
    dirty.reserve(fn.blocks.size());
    for (u32 i = 0; i < static_cast<u32>(fn.blocks.size()); ++i) dirty.push_back(i);

    for (std::size_t it = 0; it < kMaxIter; ++it) {
        ++stats.iterations;
        std::vector<u32> next_dirty;

        const auto folded  = pass_constant_fold (fn, am, dirty, next_dirty);
        const auto casted  = pass_cast_simplify (fn, am, dirty, next_dirty);
        // GVN must run before memory_forward so both stores and loads see
        // the same canonical SSA id for their address expression.
        const auto gvned   = pass_local_gvn     (fn, am, dirty, next_dirty);
        const auto memfwd  = pass_memory_forward(fn, am, dirty, next_dirty);
        const auto dse     = pass_dead_store_elim(fn, am, dirty, next_dirty);
        const auto copied  = pass_copy_prop     (fn, am, dirty, next_dirty);
        const auto phied   = pass_trivial_phi   (fn, am, dirty, next_dirty);
        const auto deleted = pass_dce           (fn, am, dirty, next_dirty);
        if (deleted) am.invalidate_defs();

        stats.constants_folded  += folded + casted;
        stats.copies_propagated += copied + memfwd + gvned;
        stats.phis_removed      += phied;
        stats.insts_removed     += deleted + dse;

        if (!folded && !casted && !gvned && !memfwd &&
            !dse && !copied && !phied && !deleted) break;

        std::sort(next_dirty.begin(), next_dirty.end());
        next_dirty.erase(std::unique(next_dirty.begin(), next_dirty.end()),
                         next_dirty.end());
        dirty = std::move(next_dirty);
        if (dirty.empty()) break;
    }

    return stats;
}

}  // namespace

Result<CleanupStats> run_cleanup(IrFunction& fn) {
    return run_pipeline(fn);
}

}  // namespace ember
