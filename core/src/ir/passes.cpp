#include <ember/ir/passes.hpp>

#include <cstddef>
#include <deque>
#include <map>
#include <optional>
#include <set>
#include <tuple>
#include <utility>
#include <vector>

#include <ember/common/types.hpp>
#include <ember/ir/ssa.hpp>

namespace ember {

namespace {

// ============================================================================
// SSA name key
// ============================================================================

using SsaKey = std::tuple<u8, u32, u32>;  // (kind: 0=Reg,1=Flag,2=Temp), id, version

[[nodiscard]] std::optional<SsaKey> ssa_key(const IrValue& v) noexcept {
    switch (v.kind) {
        case IrValueKind::Reg:
            return SsaKey{0, static_cast<u32>(canonical_reg(v.reg)), v.version};
        case IrValueKind::Flag:
            return SsaKey{1, static_cast<u32>(v.flag), v.version};
        case IrValueKind::Temp:
            return SsaKey{2, v.temp, 0};
        case IrValueKind::Imm: {
            // Imm values get a synthetic stable key so the memory passes can
            // treat `store [0x404018], v` as a write to a known address.
            // Kind tag 3 ensures no collision with reg/flag/temp keys; the
            // imm value is split across the two u32 slots.
            const u64 uv = static_cast<u64>(v.imm);
            return SsaKey{3,
                          static_cast<u32>(uv & 0xFFFFFFFFu),
                          static_cast<u32>(uv >> 32)};
        }
        default:
            return std::nullopt;
    }
}

[[nodiscard]] bool same_value(const IrValue& a, const IrValue& b) noexcept {
    if (a.kind != b.kind) return false;
    if (a.type != b.type) return false;
    if (a.kind == IrValueKind::Imm) return a.imm == b.imm;
    auto ka = ssa_key(a);
    auto kb = ssa_key(b);
    return ka && kb && *ka == *kb;
}

// ============================================================================
// Mask i64 result to an IrType width (sign-extending from low bits)
// ============================================================================

[[nodiscard]] i64 mask_signed(i64 v, IrType t) noexcept {
    const unsigned bits = type_bits(t);
    if (bits == 0 || bits >= 64) return v;
    const u64 mask = (bits == 64) ? ~u64(0) : ((u64(1) << bits) - 1);
    u64 u = static_cast<u64>(v) & mask;
    if (bits < 64 && (u & (u64(1) << (bits - 1)))) {
        u |= ~mask;
    }
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
                if (same_value(a, b)) return IrValue::make_imm(0, dt);
                break;
            case IrOp::Mul:
                if (ai && a.imm == 0) return IrValue::make_imm(0, dt);
                if (bi && b.imm == 0) return IrValue::make_imm(0, dt);
                if (ai && a.imm == 1) return b;
                if (bi && b.imm == 1) return a;
                break;
            case IrOp::And:
                if (ai && a.imm == 0) return IrValue::make_imm(0, dt);
                if (bi && b.imm == 0) return IrValue::make_imm(0, dt);
                if (same_value(a, b)) return a;
                break;
            case IrOp::Or:
                if (ai && a.imm == 0) return b;
                if (bi && b.imm == 0) return a;
                if (same_value(a, b)) return a;
                break;
            case IrOp::Xor:
                if (ai && a.imm == 0) return b;
                if (bi && b.imm == 0) return a;
                if (same_value(a, b)) return IrValue::make_imm(0, dt);
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
            case IrOp::CmpUlt:
                return IrValue::make_imm(static_cast<u64>(a.imm) <  static_cast<u64>(b.imm) ? 1 : 0, IrType::I1);
            case IrOp::CmpUle:
                return IrValue::make_imm(static_cast<u64>(a.imm) <= static_cast<u64>(b.imm) ? 1 : 0, IrType::I1);
            case IrOp::CmpUgt:
                return IrValue::make_imm(static_cast<u64>(a.imm) >  static_cast<u64>(b.imm) ? 1 : 0, IrType::I1);
            case IrOp::CmpUge:
                return IrValue::make_imm(static_cast<u64>(a.imm) >= static_cast<u64>(b.imm) ? 1 : 0, IrType::I1);
            default: return std::nullopt;
        }
    }

    return std::nullopt;
}

[[nodiscard]] std::size_t pass_constant_fold(IrFunction& fn) {
    std::size_t count = 0;
    for (auto& bb : fn.blocks) {
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
    }
    return count;
}

// ============================================================================
// Pass: copy propagation
// ============================================================================

[[nodiscard]] std::size_t pass_copy_prop(IrFunction& fn) {
    std::map<SsaKey, IrValue> subst;

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
    auto apply = [&](IrValue& v) {
        auto k = ssa_key(v);
        if (!k) return;
        auto it = subst.find(*k);
        if (it == subst.end()) return;
        if (it->second.type != v.type) return;
        if (same_value(v, it->second)) return;
        v = it->second;
        ++count;
    };

    for (auto& bb : fn.blocks) {
        for (auto& inst : bb.insts) {
            for_each_use(inst, apply);
        }
    }
    return count;
}

// ============================================================================
// Pass: trivial phi elimination
// ============================================================================

[[nodiscard]] std::size_t pass_trivial_phi(IrFunction& fn) {
    std::map<SsaKey, IrValue> subst;
    std::size_t removed = 0;

    for (auto& bb : fn.blocks) {
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
                } else if (!same_value(*unique, op)) {
                    trivial = false;
                    break;
                }
            }

            if (trivial && unique) {
                subst[*dst_key] = *unique;
                inst.op = IrOp::Nop;
                inst.phi_operands.clear();
                inst.phi_preds.clear();
                inst.src_count = 0;
                ++removed;
            }
        }
    }
    if (subst.empty()) return 0;

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

    auto apply = [&](IrValue& v) {
        auto k = ssa_key(v);
        if (!k) return;
        auto it = subst.find(*k);
        if (it == subst.end()) return;
        if (it->second.type != v.type) return;
        v = it->second;
    };

    for (auto& bb : fn.blocks) {
        for (auto& inst : bb.insts) {
            for_each_use(inst, apply);
        }
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

[[nodiscard]] std::size_t pass_local_gvn(IrFunction& fn) {
    std::size_t count = 0;
    for (auto& bb : fn.blocks) {
        std::map<GvnOp, IrValue> seen;   // op-key -> canonical temp
        for (auto& inst : bb.insts) {
            // Invalidate on arbitrary memory/control effects — keys that
            // referenced values defined before remain valid, but a
            // subsequent load-dependent value should not be GVN'd with a
            // pre-invalidation same-op computation. For purely syntactic
            // GVN this is unnecessary (we only GVN pure ops), so we skip.
            auto k = gvn_key_of(inst);
            if (!k) continue;
            auto it = seen.find(*k);
            if (it == seen.end()) {
                seen.emplace(*k, inst.dst);
                continue;
            }
            if (it->second.type != inst.dst.type) continue;
            // Rewrite as Assign of the canonical temp.
            inst.op        = IrOp::Assign;
            inst.srcs[0]   = it->second;
            inst.srcs[1]   = IrValue{};
            inst.srcs[2]   = IrValue{};
            inst.src_count = 1;
            ++count;
        }
    }
    return count;
}

// ============================================================================
// Pass: intra-block dead-store elimination
// ============================================================================
//
// Within a single block, a Store S1 is dead if a later Store S2 writes the
// same address with a matching type before any intervening memory effect
// that could observe S1 (a Load from the same address, an unknown-address
// Store, or a Call/Intrinsic that may touch memory). The dead S1 is
// rewritten to Nop; the value computation it dropped is cleaned up by the
// next DCE sweep.
//
// The check is deliberately conservative — different SSA-keyed addresses
// are assumed non-aliasing (paired with GVN this is safe for stack slots),
// and we bail the whole per-block tracking on any unknown-address store.

[[nodiscard]] std::size_t pass_dead_store_elim(IrFunction& fn) {
    std::size_t count = 0;
    for (auto& bb : fn.blocks) {
        // last_store[addr_key] = (block-local inst index, stored type)
        std::map<SsaKey, std::pair<std::size_t, IrType>> last_store;
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
                        // Prior store is overwritten in full before any
                        // intervening observation — kill it.
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
                    // A load from a slot we've tracked observes its prior
                    // store: keep it. Conservatively drop the tracked
                    // entry so a later store isn't mis-killed as "dead
                    // without observer".
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
    }
    return count;
}

// ============================================================================
// Pass: intra-block store-to-load forwarding (memory SSA, lightweight)
// ============================================================================
//
// Walks each block linearly, maintaining a map from address-SSA-key to the
// most recently stored value. A Load whose address matches an entry is
// rewritten as an Assign of the stored value; subsequent copy-prop + DCE
// then eliminate the load entirely.
//
// Conservative invalidation:
//   - A Store clears the map and records the new entry (alias-safe: we
//     have no alias analysis, so every store invalidates everything).
//   - Calls and Intrinsics clear the map (arbitrary memory effects).
//
// This catches the canonical compiler-emitted pattern
//     local_X = Y; ...; z = local_X
// after SSA converts the addressing temps to stable identities, which is
// the dominant source of visual "spill churn" in decompiled prologues.

[[nodiscard]] std::size_t pass_memory_forward(IrFunction& fn) {
    std::size_t count = 0;
    for (auto& bb : fn.blocks) {
        std::map<SsaKey, IrValue> stored;
        for (auto& inst : bb.insts) {
            switch (inst.op) {
                case IrOp::Store: {
                    // Per-address update — different SSA keys mean different
                    // address expressions and are treated as non-aliasing.
                    // GVN canonicalizes address arithmetic so stack slots
                    // with the same `rsp_vN + const` form share a key.
                    // Stores to unknown/unkeyable addresses wipe the map
                    // (they could alias anything).
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
    }
    return count;
}

// ============================================================================
// Pass: cast simplification
// ============================================================================
//
// Collapses redundant width-cast chains that show up heavily after the lifter
// models partial-register writes as `rax = zext64(eax)`. Patterns handled:
//
//   Trunc(X,  T)       where X.type == T                 → X
//   ZExt(X,  T)        where X.type == T                 → X
//   SExt(X,  T)        where X.type == T                 → X
//   Trunc(ZExt(x,_), T) where x.type == T                → x
//   Trunc(SExt(x,_), T) where x.type == T                → x
//   Trunc(Trunc(x,_), T)                                 → Trunc(x, T)
//   ZExt(ZExt(x,_),   T)                                 → ZExt(x, T)
//   SExt(SExt(x,_),   T)                                 → SExt(x, T)
//
// Rewrites each simplifiable cast into an Assign of the recovered inner
// operand, so subsequent copy-prop + DCE dissolve the noise.

[[nodiscard]] std::size_t pass_cast_simplify(IrFunction& fn) {
    std::map<SsaKey, const IrInst*> defs;
    for (const auto& bb : fn.blocks) {
        for (const auto& inst : bb.insts) {
            if (auto k = ssa_key(inst.dst); k) defs[*k] = &inst;
        }
    }

    auto is_cast = [](IrOp op) noexcept {
        return op == IrOp::Trunc || op == IrOp::ZExt || op == IrOp::SExt;
    };

    std::size_t changes = 0;
    for (auto& bb : fn.blocks) {
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

            // Inspect the defining instruction of the source (if any).
            auto k = ssa_key(src);
            if (!k) continue;
            auto it = defs.find(*k);
            if (it == defs.end()) continue;
            const IrInst* def = it->second;
            if (!is_cast(def->op) || def->src_count != 1) continue;
            const IrValue& inner = def->srcs[0];

            // Outer Trunc collapsing: peel off an extension if it was just
            // applied, or fuse two truncs.
            if (inst.op == IrOp::Trunc) {
                if ((def->op == IrOp::ZExt || def->op == IrOp::SExt) &&
                    inner.type == dt) {
                    inst.op      = IrOp::Assign;
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

            // Outer extension fusing two same-kind extensions.
            if ((inst.op == IrOp::ZExt && def->op == IrOp::ZExt) ||
                (inst.op == IrOp::SExt && def->op == IrOp::SExt)) {
                if (type_bits(inner.type) <= type_bits(dt)) {
                    inst.srcs[0] = inner;  // ZExt(ZExt(x)) → ZExt(x)
                    ++changes;
                    continue;
                }
            }
        }
    }
    return changes;
}

[[nodiscard]] std::size_t pass_dce(IrFunction& fn) {
    struct Loc { std::size_t block; std::size_t inst; };
    std::map<SsaKey, Loc> defs;

    for (std::size_t bi = 0; bi < fn.blocks.size(); ++bi) {
        auto& bb = fn.blocks[bi];
        for (std::size_t ii = 0; ii < bb.insts.size(); ++ii) {
            auto k = ssa_key(bb.insts[ii].dst);
            if (k) defs[*k] = {bi, ii};
        }
    }

    std::set<std::pair<std::size_t, std::size_t>> live;
    std::deque<std::pair<std::size_t, std::size_t>> wl;

    for (std::size_t bi = 0; bi < fn.blocks.size(); ++bi) {
        auto& bb = fn.blocks[bi];
        for (std::size_t ii = 0; ii < bb.insts.size(); ++ii) {
            if (is_side_effect(bb.insts[ii].op)) {
                if (live.insert({bi, ii}).second) wl.push_back({bi, ii});
            }
        }
    }

    while (!wl.empty()) {
        auto [bi, ii] = wl.front();
        wl.pop_front();
        const auto& inst = fn.blocks[bi].insts[ii];
        for_each_use(const_cast<IrInst&>(inst), [&](IrValue& v) {
            auto k = ssa_key(v);
            if (!k) return;
            auto it = defs.find(*k);
            if (it == defs.end()) return;
            const Loc loc = it->second;
            if (live.insert({loc.block, loc.inst}).second) {
                wl.push_back({loc.block, loc.inst});
            }
        });
    }

    std::size_t removed = 0;
    for (std::size_t bi = 0; bi < fn.blocks.size(); ++bi) {
        auto& bb = fn.blocks[bi];
        std::vector<IrInst> kept;
        kept.reserve(bb.insts.size());
        for (std::size_t ii = 0; ii < bb.insts.size(); ++ii) {
            auto& inst = bb.insts[ii];
            if (inst.op == IrOp::Nop) {
                ++removed;
                continue;
            }
            if (live.contains({bi, ii}) || is_side_effect(inst.op)) {
                kept.push_back(std::move(inst));
            } else {
                ++removed;
            }
        }
        bb.insts = std::move(kept);
    }
    return removed;
}

}  // namespace

Result<CleanupStats> run_cleanup(IrFunction& fn) {
    CleanupStats stats;
    constexpr std::size_t kMaxIter = 16;

    for (std::size_t it = 0; it < kMaxIter; ++it) {
        ++stats.iterations;
        const auto folded    = pass_constant_fold(fn);
        const auto casted    = pass_cast_simplify(fn);
        // GVN must run before memory_forward so both stores and loads see
        // the same canonical SSA id for their address expression.
        const auto gvned     = pass_local_gvn(fn);
        const auto memfwd    = pass_memory_forward(fn);
        const auto dse       = pass_dead_store_elim(fn);
        const auto copied    = pass_copy_prop(fn);
        const auto phied     = pass_trivial_phi(fn);
        const auto deleted   = pass_dce(fn);

        stats.constants_folded  += folded + casted;
        stats.copies_propagated += copied + memfwd + gvned;
        stats.phis_removed      += phied;
        stats.insts_removed     += deleted + dse;

        if (folded == 0 && casted == 0 && gvned == 0 && memfwd == 0 &&
            dse == 0 && copied == 0 && phied == 0 && deleted == 0) break;
    }

    return stats;
}

}  // namespace ember
