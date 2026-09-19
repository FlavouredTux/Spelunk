// Cast simplification and dead-code elimination.

#include <cstddef>
#include <span>
#include <utility>
#include <vector>

#include <spelunk/common/types.hpp>
#include <spelunk/ir/ir.hpp>
#include <spelunk/ir/ssa.hpp>

#include "passes_internal.hpp"

namespace spelunk::ir_passes {

// ============================================================================
// Pass: cast simplification
// ============================================================================
std::size_t pass_cast_simplify(
    IrFunction& fn, AnalysisManager& am,
    std::span<const u32> dirty, std::vector<u32>& touched) {
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
            // A partial-register write replaces the low bits with a literal.
            // Narrowing it must not retain the old high-register dependency.
            if (inst.op == IrOp::Trunc && type_bits(dt) <= 64 &&
                def->op == IrOp::Or && def->src_count == 2) {
                for (u8 literal = 0; literal < 2; ++literal) {
                    if (def->srcs[literal].kind != IrValueKind::Imm) continue;
                    const auto other = ssa_key(def->srcs[1 - literal]);
                    if (!other) continue;
                    const auto masked = defs.find(*other);
                    if (masked == defs.end()) continue;
                    const auto& mask_inst = fn.blocks[masked->second.block].insts[masked->second.inst];
                    if (mask_inst.op != IrOp::And || mask_inst.src_count != 2) continue;
                    bool clears_low = false;
                    for (u8 i = 0; i < 2; ++i)
                        clears_low |= mask_inst.srcs[i].kind == IrValueKind::Imm &&
                            mask_unsigned(mask_inst.srcs[i].imm, dt) == 0;
                    if (!clears_low) continue;
                    inst.op = IrOp::Assign;
                    inst.srcs[0] = IrValue::make_imm(mask_signed(def->srcs[literal].imm, dt), dt);
                    ++changes;
                    break;
                }
                if (inst.op == IrOp::Assign) continue;
            }
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

std::size_t pass_dce(
    IrFunction& fn, AnalysisManager& am,
    std::span<const u32> /*dirty*/, std::vector<u32>& touched) {
    const auto& defs = am.defs(fn);

    // Live set as a per-block bitvector. Encoded as one big flat vector
    // with per-block offset table - measurably faster than the previous
    // `std::set<pair<size_t,size_t>>` for hot binaries because the
    // hash/lookup turns into a single byte read, no heap traffic, and
    // the worklist below allocates once. (~3.5x speedup on the cleanup
    // pipeline measured against spelunk-on-itself.)
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

}  // namespace spelunk::ir_passes
