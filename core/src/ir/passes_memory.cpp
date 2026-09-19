// Local GVN, dead-store elimination and store-to-load forwarding.

#include <algorithm>
#include <cstddef>
#include <limits>
#include <map>
#include <optional>
#include <span>
#include <vector>

#include <spelunk/common/types.hpp>
#include <spelunk/disasm/register.hpp>
#include <spelunk/ir/ir.hpp>
#include <spelunk/ir/ssa.hpp>

#include "passes_internal.hpp"

namespace spelunk::ir_passes {

// ============================================================================
// Pass: dead code elimination
// ============================================================================
bool is_side_effect(IrOp op) noexcept {
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

bool gvn_eligible(IrOp op) noexcept {
    switch (op) {
        case IrOp::Add: case IrOp::Sub: case IrOp::Mul:
        case IrOp::And: case IrOp::Or:  case IrOp::Xor:
        case IrOp::Neg: case IrOp::Not: case IrOp::Clz:
        case IrOp::Shl: case IrOp::Lshr: case IrOp::Ashr:
        case IrOp::CmpEq: case IrOp::CmpNe:
        case IrOp::CmpUlt: case IrOp::CmpUle: case IrOp::CmpUgt: case IrOp::CmpUge:
        case IrOp::CmpSlt: case IrOp::CmpSle: case IrOp::CmpSgt: case IrOp::CmpSge:
        case IrOp::ZExt: case IrOp::SExt: case IrOp::Trunc: case IrOp::FpToInt:
            return true;
        default:
            return false;
    }
}

std::optional<GvnOp> gvn_key_of(const IrInst& inst) noexcept {
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

AddressForm resolve_address_form(
    const IrFunction& fn, const SsaMap<DefLoc>& defs,
    IrValue value, unsigned depth) noexcept {
    if (depth > 12) return {};
    if (value.kind == IrValueKind::Imm)
        return {AddressClass::Absolute, value.imm};
    if (value.kind == IrValueKind::Reg && value.reg == Reg::Rsp &&
        value.version == 0)
        return {AddressClass::Stack, 0};
    auto key = ssa_key(value);
    if (!key) return {};
    auto found = defs.find(*key);
    if (found == defs.end()) return {};
    const DefLoc loc = found->second;
    if (loc.block >= fn.blocks.size() ||
        loc.inst >= fn.blocks[loc.block].insts.size()) return {};
    const IrInst& def = fn.blocks[loc.block].insts[loc.inst];
    if (def.op == IrOp::Assign && def.src_count == 1)
        return resolve_address_form(fn, defs, def.srcs[0], depth + 1);
    if ((def.op == IrOp::Add || def.op == IrOp::Sub) && def.src_count == 2) {
        AddressForm base = resolve_address_form(fn, defs, def.srcs[0], depth + 1);
        if (base.cls != AddressClass::Unknown &&
            def.srcs[1].kind == IrValueKind::Imm) {
            const i64 delta = def.srcs[1].imm;
            if ((def.op == IrOp::Add &&
                 ((delta > 0 && base.offset > std::numeric_limits<i64>::max() - delta) ||
                  (delta < 0 && base.offset < std::numeric_limits<i64>::min() - delta))) ||
                (def.op == IrOp::Sub &&
                 ((delta < 0 && base.offset > std::numeric_limits<i64>::max() + delta) ||
                  (delta > 0 && base.offset < std::numeric_limits<i64>::min() + delta)))) {
                return {};
            }
            base.offset = def.op == IrOp::Add
                ? base.offset + delta : base.offset - delta;
            return base;
        }
        if (def.op == IrOp::Add && def.srcs[0].kind == IrValueKind::Imm) {
            AddressForm rhs = resolve_address_form(fn, defs, def.srcs[1], depth + 1);
            if (rhs.cls != AddressClass::Unknown) {
                const i64 delta = def.srcs[0].imm;
                if ((delta > 0 && rhs.offset > std::numeric_limits<i64>::max() - delta) ||
                    (delta < 0 && rhs.offset < std::numeric_limits<i64>::min() - delta))
                    return {};
                rhs.offset += delta;
                return rhs;
            }
        }
    }
    return {};
}

bool definitely_no_alias(AddressForm a, std::size_t a_size,
                                       AddressForm b, std::size_t b_size) noexcept {
    if (a.cls == AddressClass::Unknown || b.cls == AddressClass::Unknown)
        return false;
    // Fixed image addresses and frame-relative stack slots belong to
    // disjoint storage classes for the purposes of local memory SSA.
    if (a.cls != b.cls) return true;
    // Stack displacements are signed offsets; absolute addresses are raw
    // u64 bit patterns. Applying the signed-order bias to an absolute VA
    // would make adjacent ranges across 0x7fff.../0x8000... appear vastly
    // separated and could enable unsound forwarding/DSE.
    const u64 order_bias = a.cls == AddressClass::Stack ? (u64{1} << 63) : 0;
    const u64 ao = static_cast<u64>(a.offset) ^ order_bias;
    const u64 bo = static_cast<u64>(b.offset) ^ order_bias;
    const u64 distance = ao >= bo ? ao - bo : bo - ao;
    const std::size_t earlier_size = ao <= bo ? a_size : b_size;
    return distance >= earlier_size;
}

bool same_address(const IrValue& a, AddressForm af,
                                const IrValue& b, AddressForm bf) noexcept {
    if (same_ssa_value(a, b)) return true;
    return af.cls != AddressClass::Unknown && af.cls == bf.cls &&
           af.offset == bf.offset;
}

std::size_t memory_width(IrType type) noexcept {
    return std::max<std::size_t>(1, type_bits(type) / 8);
}

std::size_t pass_local_gvn(
    IrFunction& fn, AnalysisManager& /*am*/,
    std::span<const u32> dirty, std::vector<u32>& touched) {
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
std::size_t pass_dead_store_elim(
    IrFunction& fn, AnalysisManager& am,
    std::span<const u32> dirty, std::vector<u32>& touched) {
    std::size_t count = 0;
    for_blocks(fn, dirty, [&](u32 bi, IrBlock& bb) {
        const std::size_t before = count;
        struct StoreInfo {
            std::size_t index = 0;
            IrType type = IrType::I64;
            IrValue address_value;
            AddressForm address;
            std::size_t width = 0;
        };
        std::vector<StoreInfo> last_stores;
        const auto& defs = am.defs(fn);
        for (std::size_t i = 0; i < bb.insts.size(); ++i) {
            auto& inst = bb.insts[i];
            if ((inst.op == IrOp::Load || inst.op == IrOp::Store) && inst.segment != Reg::None) {
                // FS/GS add an unknown segment base: the same offset is not
                // the same stack location, and may alias unrelated memory.
                last_stores.clear();
                continue;
            }
            switch (inst.op) {
                case IrOp::Store: {
                    if (inst.src_count < 2) break;
                    const IrType new_ty = inst.srcs[1].type;
                    const IrValue new_value = inst.srcs[0];
                    const AddressForm new_addr =
                        resolve_address_form(fn, defs, new_value);
                    const std::size_t new_width = memory_width(new_ty);
                    for (auto it = last_stores.begin(); it != last_stores.end();) {
                        if (definitely_no_alias(it->address, it->width,
                                                new_addr, new_width)) {
                            ++it;
                            continue;
                        }
                        if (it->type == new_ty &&
                            same_address(it->address_value, it->address,
                                         new_value, new_addr)) {
                            auto& prior = bb.insts[it->index];
                            prior.op        = IrOp::Nop;
                            prior.src_count = 0;
                            prior.srcs      = {};
                            prior.segment   = Reg::None;
                            ++count;
                        }
                        // An intervening may-alias store makes the old
                        // candidate unsuitable for later local DSE even when
                        // the two pointer SSA values differ at compile time.
                        it = last_stores.erase(it);
                    }
                    last_stores.push_back(
                        {i, new_ty, new_value, new_addr, new_width});
                    break;
                }
                case IrOp::Load: {
                    if (inst.src_count < 1) break;
                    const AddressForm load_addr =
                        resolve_address_form(fn, defs, inst.srcs[0]);
                    const std::size_t load_width = memory_width(inst.dst.type);
                    for (auto it = last_stores.begin(); it != last_stores.end();) {
                        if (definitely_no_alias(it->address, it->width,
                                                load_addr, load_width)) ++it;
                        else it = last_stores.erase(it);
                    }
                    break;
                }
                case IrOp::Call:
                case IrOp::CallIndirect:
                case IrOp::Intrinsic:
                    last_stores.clear();
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
std::size_t pass_memory_forward(
    IrFunction& fn, AnalysisManager& am,
    std::span<const u32> dirty, std::vector<u32>& touched) {
    std::size_t count = 0;
    for_blocks(fn, dirty, [&](u32 bi, IrBlock& bb) {
        const std::size_t before = count;
        struct StoredValue {
            IrValue value;
            IrValue address_value;
            AddressForm address;
            std::size_t width = 0;
        };
        std::vector<StoredValue> stored;
        const auto& defs = am.defs(fn);
        for (auto& inst : bb.insts) {
            if ((inst.op == IrOp::Load || inst.op == IrOp::Store) && inst.segment != Reg::None) {
                stored.clear();
                continue;
            }
            switch (inst.op) {
                case IrOp::Store: {
                    if (inst.src_count < 2) break;
                    const IrValue new_value = inst.srcs[0];
                    const AddressForm new_addr =
                        resolve_address_form(fn, defs, new_value);
                    const std::size_t new_width = memory_width(inst.srcs[1].type);
                    for (auto it = stored.begin(); it != stored.end();) {
                        if (definitely_no_alias(it->address, it->width,
                                                new_addr, new_width)) ++it;
                        else it = stored.erase(it);
                    }
                    stored.push_back({inst.srcs[1], new_value, new_addr, new_width});
                    break;
                }
                case IrOp::Load: {
                    if (inst.src_count >= 1) {
                        const IrValue load_value = inst.srcs[0];
                        const AddressForm load_addr =
                            resolve_address_form(fn, defs, load_value);
                        auto it = std::find_if(stored.rbegin(), stored.rend(),
                            [&](const StoredValue& candidate) {
                                return same_address(candidate.address_value,
                                                    candidate.address,
                                                    load_value, load_addr);
                            });
                        if (it == stored.rend()) break;
                        if (it->value.type != inst.dst.type) break;
                        inst.op        = IrOp::Assign;
                        inst.srcs[0]   = it->value;
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

}  // namespace spelunk::ir_passes
