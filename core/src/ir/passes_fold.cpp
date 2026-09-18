// Constant folding, copy propagation and trivial-phi removal.

#include <bit>
#include <cstddef>
#include <optional>
#include <span>
#include <vector>

#include <spelunk/common/types.hpp>
#include <spelunk/ir/ir.hpp>
#include <spelunk/ir/ssa.hpp>

#include "passes_internal.hpp"

namespace spelunk::ir_passes {

// ============================================================================
// Pass: constant folding + identity folding
// ============================================================================
std::optional<IrValue>
try_fold(const IrInst& inst) noexcept {
    const IrType dt = inst.dst.type;
    // FP immediates hold IEEE bit patterns. Integer identities and arithmetic
    // on those bits lose NaNs, signed zero, and rounding behavior. Copies and
    // selections remain valid because they preserve the chosen representation.
    if (inst.op != IrOp::Assign && inst.op != IrOp::Select) {
        if (is_float_type(dt)) return std::nullopt;
        for (u8 i = 0; i < inst.src_count; ++i) {
            if (is_float_type(inst.srcs[i].type)) return std::nullopt;
        }
    }
    // Integer IR wraps at its declared width; host signed overflow is UB even
    // when the result is immediately masked. Compute the bit pattern first.
    const auto wrapped = [dt](u64 bits) {
        return IrValue::make_imm(mask_signed(std::bit_cast<i64>(bits), dt), dt);
    };

    // Unary
    if (inst.src_count == 1) {
        const auto& a = inst.srcs[0];
        if (a.kind != IrValueKind::Imm) return std::nullopt;
        switch (inst.op) {
            case IrOp::Neg:   return wrapped(u64{0} - static_cast<u64>(a.imm));
            case IrOp::Not:   return IrValue::make_imm(mask_signed(~a.imm, dt), dt);
            case IrOp::Clz: {
                const u32 value = static_cast<u32>(mask_unsigned(a.imm, IrType::I32));
                return IrValue::make_imm(static_cast<i64>(std::countl_zero(value)), dt);
            }
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
                // Imms are stored sign-extended, so -1 is the all-ones
                // pattern at every width <= 64: x & ~0 -> x.
                if (ai && a.imm == -1) return b;
                if (bi && b.imm == -1) return a;
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
            case IrOp::Add: return wrapped(static_cast<u64>(a.imm) + static_cast<u64>(b.imm));
            case IrOp::Sub: return wrapped(static_cast<u64>(a.imm) - static_cast<u64>(b.imm));
            case IrOp::Mul: return wrapped(static_cast<u64>(a.imm) * static_cast<u64>(b.imm));
            // IrOp::Div / IrOp::Mod don't carry signedness - the same opcode
            // is emitted for both DIV (unsigned) and IDIV (signed) lowerings.
            // Folding with C++ `/` and `%` always uses signed semantics, so
            // an unsigned divide of operands with the high bit set in their
            // operand width produces wrong arithmetic. Skip the fold; the
            // emitter prints `a / b` literally, which is correct C as long as
            // the operand types match - the optimization opportunity is
            // small (constant-by-constant divides are rare in real code) and
            // not worth the silent miscomputation.
            case IrOp::Div:
            case IrOp::Mod:
                return std::nullopt;
            case IrOp::And: return IrValue::make_imm(mask_signed(a.imm & b.imm, dt), dt);
            case IrOp::Or:  return IrValue::make_imm(mask_signed(a.imm | b.imm, dt), dt);
            case IrOp::Xor: return IrValue::make_imm(mask_signed(a.imm ^ b.imm, dt), dt);
            case IrOp::Shl: {
                // x86 masks the shift count to 5 bits for 8/16/32-bit
                // operands and 6 bits for 64-bit. A blanket 63-bit mask
                // miscomputed `shl i32 x, 32` as 0 instead of x (real
                // hardware: 32 & 0x1f = 0 → no shift). Match hardware
                // for all three Shl/Lshr/Ashr below.
                const unsigned shift = static_cast<unsigned>(b.imm) &
                                       (type_bits(a.type) == 64 ? 63u : 31u);
                return IrValue::make_imm(
                    mask_signed(static_cast<i64>(static_cast<u64>(a.imm) << shift), dt), dt);
            }
            case IrOp::Lshr: {
                const unsigned shift = static_cast<unsigned>(b.imm) &
                                       (type_bits(a.type) == 64 ? 63u : 31u);
                const u64 av = mask_unsigned(a.imm, a.type);
                return IrValue::make_imm(static_cast<i64>(av >> shift), dt);
            }
            case IrOp::Ashr: {
                const unsigned shift = static_cast<unsigned>(b.imm) &
                                       (type_bits(a.type) == 64 ? 63u : 31u);
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

std::size_t pass_constant_fold(
    IrFunction& fn, AnalysisManager& am,
    std::span<const u32> dirty, std::vector<u32>& touched) {
    const auto& defs = am.defs(fn);
    auto peel_to_def = [&](const IrValue& v) -> const IrInst* {
        IrValue cur = v;
        for (int hop = 0; hop < 16; ++hop) {
            auto k = ssa_key(cur);
            if (!k) return nullptr;
            auto it = defs.find(*k);
            if (it == defs.end()) return nullptr;
            const IrInst& d = fn.blocks[it->second.block].insts[it->second.inst];
            if (d.op == IrOp::Assign && d.src_count == 1 &&
                d.srcs[0].type == cur.type) {
                cur = d.srcs[0];
                continue;
            }
            return &d;
        }
        return nullptr;
    };

    std::size_t count = 0;
    for_blocks(fn, dirty, [&](u32 bi, IrBlock& bb) {
        const std::size_t before = count;
        for (auto& inst : bb.insts) {
            if (inst.op == IrOp::Assign || inst.op == IrOp::Nop) continue;
            if (inst.op == IrOp::Phi) continue;

            // Not(Not(x)) -> x
            if (inst.op == IrOp::Not && inst.src_count == 1 &&
                inst.srcs[0].kind != IrValueKind::Imm) {
                const IrInst* inner = peel_to_def(inst.srcs[0]);
                if (inner && inner->op == IrOp::Not && inner->src_count == 1 &&
                    inner->srcs[0].type == inst.dst.type) {
                    inst.op        = IrOp::Assign;
                    inst.srcs[0]   = inner->srcs[0];
                    inst.srcs[1]   = IrValue{};
                    inst.srcs[2]   = IrValue{};
                    inst.src_count = 1;
                    ++count;
                    continue;
                }
            }

            // Xor(Xor(a, b), b) -> a (either operand order on both levels)
            if (inst.op == IrOp::Xor && inst.src_count == 2) {
                bool cancelled = false;
                for (u8 side = 0; side < 2 && !cancelled; ++side) {
                    const IrValue& chained = inst.srcs[side];
                    const IrValue& other   = inst.srcs[1 - side];
                    if (chained.kind == IrValueKind::Imm &&
                        other.kind == IrValueKind::Imm) continue;
                    const IrInst* d = peel_to_def(chained);
                    if (!d || d->op != IrOp::Xor || d->src_count != 2) continue;
                    for (u8 j = 0; j < 2; ++j) {
                        if (!same_ssa_value(d->srcs[j], other)) continue;
                        const IrValue& survivor = d->srcs[1 - j];
                        if (survivor.type != chained.type) break;
                        inst.op        = IrOp::Assign;
                        inst.srcs[0]   = survivor;
                        inst.srcs[1]   = IrValue{};
                        inst.srcs[2]   = IrValue{};
                        inst.src_count = 1;
                        ++count;
                        cancelled = true;
                        break;
                    }
                }
                if (cancelled) continue;
            }

            // Add(x, Neg(x)) -> 0 (either operand order)
            if (inst.op == IrOp::Add && inst.src_count == 2 &&
                !is_float_type(inst.dst.type)) {
                for (u8 side = 0; side < 2; ++side) {
                    const IrValue& other = inst.srcs[side];
                    if (other.kind == IrValueKind::Imm) continue;
                    const IrInst* d = peel_to_def(inst.srcs[1 - side]);
                    if (!d || d->op != IrOp::Neg || d->src_count != 1) continue;
                    if (!same_ssa_value(d->srcs[0], other)) continue;
                    if (d->srcs[0].type != other.type ||
                        d->dst.type != inst.srcs[1 - side].type) continue;
                    inst.op        = IrOp::Assign;
                    inst.srcs[0]   = IrValue::make_imm(0, inst.dst.type);
                    inst.srcs[1]   = IrValue{};
                    inst.srcs[2]   = IrValue{};
                    inst.src_count = 1;
                    ++count;
                    break;
                }
                if (inst.op == IrOp::Assign) continue;
            }

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
std::size_t pass_copy_prop(
    IrFunction& fn, AnalysisManager& /*am*/,
    std::span<const u32> /*dirty*/, std::vector<u32>& touched) {
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
std::size_t pass_trivial_phi(
    IrFunction& fn, AnalysisManager& am,
    std::span<const u32> /*dirty*/, std::vector<u32>& touched) {
    SsaMap<IrValue> subst;
    std::size_t removed = 0;

    // Pre-index all defs so we can chase Assign chains when comparing phi
    // operands. Without this, `phi(rax_7, t28)` where `t28 = Assign(rax_7)`
    // looks non-trivial to the operand-equality check, and rax stays phi'd
    // - the pattern that produces the `rax_10` leaks in the emitter.
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

}  // namespace spelunk::ir_passes
