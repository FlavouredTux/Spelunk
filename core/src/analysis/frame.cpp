#include <spelunk/analysis/frame.hpp>

#include <format>
#include <map>
#include <optional>
#include <string>
#include <set>
#include <tuple>
#include <vector>

#include <spelunk/binary/binary.hpp>
#include <spelunk/binary/pe.hpp>
#include <spelunk/common/types.hpp>
#include <spelunk/disasm/register.hpp>
#include <spelunk/disasm/x64_decoder.hpp>
#include <spelunk/ir/ir.hpp>
#include <spelunk/ir/ssa.hpp>

namespace spelunk {

namespace {
// CodeView x64 register IDs - only the ones the merge step interprets.
constexpr u16 kCvRegRsp = 332;
constexpr u16 kCvRegRbp = 333;
}  // namespace

namespace {

using DefMap = std::map<SsaKey, const IrInst*>;

[[nodiscard]] DefMap build_defs(const IrFunction& fn) {
    DefMap m;
    for (const auto& bb : fn.blocks) {
        for (const auto& inst : bb.insts) {
            if (auto k = ssa_key(inst.dst); k) m[*k] = &inst;
        }
    }
    return m;
}

// Trace `v` back through Add/Sub/Assign chains looking for entry-rsp
// or entry-rbp as the root. Mirrors the emitter's existing
// `stack_offset()` so a slot we declare is the same one the emitter
// will name in the body.
[[nodiscard]] std::optional<i64>
trace_stack(const IrValue& v, const DefMap& defs, int depth = 0) {
    if (depth > 16) return std::nullopt;
    if (v.kind == IrValueKind::Reg) {
        const Reg c = canonical_reg(v.reg);
        if (c == Reg::Rsp || c == Reg::Rbp || c == Reg::PpcR1 ||
            c == Reg::Xsp || c == Reg::Asp) return 0;
        return std::nullopt;
    }
    if (v.kind != IrValueKind::Temp) return std::nullopt;
    auto k = ssa_key(v);
    if (!k) return std::nullopt;
    auto it = defs.find(*k);
    if (it == defs.end()) return std::nullopt;
    const IrInst* d = it->second;
    switch (d->op) {
        case IrOp::Assign:
            return d->src_count >= 1
                ? trace_stack(d->srcs[0], defs, depth + 1)
                : std::nullopt;
        case IrOp::Add: {
            if (d->src_count < 2) return std::nullopt;
            auto lhs = trace_stack(d->srcs[0], defs, depth + 1);
            if (lhs && d->srcs[1].kind == IrValueKind::Imm) {
                return *lhs + d->srcs[1].imm;
            }
            auto rhs = trace_stack(d->srcs[1], defs, depth + 1);
            if (rhs && d->srcs[0].kind == IrValueKind::Imm) {
                return *rhs + d->srcs[0].imm;
            }
            return std::nullopt;
        }
        case IrOp::Sub: {
            if (d->src_count < 2) return std::nullopt;
            auto lhs = trace_stack(d->srcs[0], defs, depth + 1);
            if (lhs && d->srcs[1].kind == IrValueKind::Imm) {
                return *lhs - d->srcs[1].imm;
            }
            return std::nullopt;
        }
        default:
            return std::nullopt;
    }
}

[[nodiscard]] std::string slot_name(i64 off) {
    if (off < 0) return std::format("local_{:x}", static_cast<u64>(-off));
    if (off == 0) return "stack_top";
    return std::format("arg_{:x}", static_cast<u64>(off));
}

}  // namespace

std::set<const IrInst*> find_x64_stack_reservations(const IrFunction& fn,
                                                  const Binary& binary,
                                                  bool allow_subobject_escape) {
    std::set<const IrInst*> result;
    if (binary.arch() != Arch::X86_64 || fn.blocks.empty()) return result;
    const auto entry = fn.block_at.find(fn.start);
    if (entry == fn.block_at.end()) return result;
    const auto defs = build_defs(fn);
    X64Decoder decoder;
    const auto& first = fn.blocks[entry->second];
    for (std::size_t index = 0; index < first.insts.size(); ++index) {
        const auto& store = first.insts[index];
        if (store.op == IrOp::Call || store.op == IrOp::CallIndirect) break;
        if (store.op != IrOp::Store || store.src_count < 2 || store.srcs[1].type != IrType::I64 ||
            store.srcs[1].kind != IrValueKind::Reg || store.srcs[1].version != 0 ||
            canonical_reg(store.srcs[1].reg) != Reg::Rax) continue;
        const auto base = trace_stack(store.srcs[0], defs);
        if (!base || *base >= 0) continue;
        const auto decoded = decoder.decode(binary.bytes_at(store.source_addr), store.source_addr);
        if (!decoded || decoded->mnemonic != Mnemonic::Push || decoded->num_operands != 1 ||
            decoded->operands[0].kind != Operand::Kind::Register ||
            decoded->operands[0].reg != Reg::Rax) continue;

        // Track overwritten bytes independently: compilers often reserve eight
        // bytes but use only the upper four for a scalar out-parameter.
        using State = std::tuple<std::size_t, std::size_t, unsigned>;
        std::vector<State> pending{{entry->second, index + 1, 0}};
        std::set<State> seen;
        bool safe = true;
        std::size_t budget = 4096;
        const auto mask = [&](i64 offset, unsigned size) {
            unsigned bits = 0;
            for (unsigned byte = 0; byte < 8; ++byte) {
                const i64 address = *base + byte;
                if (offset <= address && static_cast<u64>(address) - static_cast<u64>(offset) < size)
                    bits |= 1u << byte;
            }
            return bits;
        };
        while (safe && !pending.empty() && budget) {
            auto [bi, begin, initialized] = pending.back();
            pending.pop_back();
            if (!seen.emplace(bi, begin, initialized).second) continue;
            const auto& block = fn.blocks[bi];
            for (std::size_t ii = begin; safe && ii < block.insts.size(); ++ii) {
                if (!budget) { safe = false; break; }
                --budget;
                const auto& inst = block.insts[ii];
                if (inst.op == IrOp::BranchIndirect && initialized != 0xffu) safe = false;
                if (inst.op == IrOp::Load && inst.src_count && inst.segment == Reg::None) {
                    if (auto offset = trace_stack(inst.srcs[0], defs))
                        safe &= (mask(*offset, type_bits(inst.dst.type) / 8) & ~initialized) == 0;
                }
                if (inst.op == IrOp::Store && inst.src_count >= 2 && inst.segment == Reg::None) {
                    if (auto offset = trace_stack(inst.srcs[0], defs))
                        initialized |= mask(*offset, type_bits(inst.srcs[1].type) / 8);
                }
                // Escaped subobjects must be initialized from the passed
                // address through the end of the reservation. Do not treat
                // the synthetic call.stack_pointer marker as an escape.
                const bool escapes = (inst.op == IrOp::Intrinsic && inst.name != "call.stack_pointer") ||
                    inst.op == IrOp::Return || inst.op == IrOp::Store || inst.op == IrOp::CallIndirect;
                if (escapes) for (u8 i = inst.op == IrOp::Store ? 1 : 0; i < inst.src_count; ++i) {
                    const auto offset = trace_stack(inst.srcs[i], defs);
                    if (offset && *offset >= *base && static_cast<u64>(*offset) - static_cast<u64>(*base) < 8) {
                        // Pseudo-C may describe the initialized subobject;
                        // strict exports cannot assume an unknown callee will
                        // never look backwards into the reservation's padding.
                        const unsigned required = allow_subobject_escape ? mask(*offset, 8) : 0xffu;
                        safe &= (required & ~initialized) == 0;
                    }
                }
            }
            for (const auto successor : block.successors) {
                if (const auto next = fn.block_at.find(successor); next != fn.block_at.end())
                    pending.emplace_back(next->second, 0, initialized);
            }
        }
        if (safe && pending.empty()) result.insert(&store);
    }
    return result;
}

StackFrameLayout compute_frame_layout(const IrFunction& fn,
                                       const Binary* binary) {
    StackFrameLayout layout;
    if (fn.blocks.empty()) return layout;

    const DefMap defs = build_defs(fn);
    const auto reservations = binary ? find_x64_stack_reservations(fn, *binary) : std::set<const IrInst*>{};

    // Higher-priority observation: a Load/Store directly at the slot
    // tells us its real access width. Wider wins - a slot read both as
    // u32 and u64 ends up u64.
    auto observe = [&](i64 off, IrType t) {
        if (off == 0) return;
        const u32 sz = type_bits(t) / 8;
        if (sz == 0) return;
        auto& s = layout.slots[off];
        if (!s.direct_observed || sz > s.size_bytes ||
            (sz == s.size_bytes && is_float_type(t) &&
             !is_float_type(s.type))) {
            s.size_bytes = sz;
            s.type       = t;
        }
        s.direct_observed = true;
        if (s.name.empty()) {
            s.offset = off;
            s.name   = slot_name(off);
        }
    };

    // Lower-priority observation: an address-of-stack-slot value (e.g.
    // `lea rax, [rbp-0x58]; call stpcpy`) tells us a slot exists at
    // that offset but not its real type. Defaults to u64; the
    // higher-priority pass wins if the same slot is also seen via a
    // direct Load/Store.
    auto observe_addr_only = [&](i64 off) {
        if (off == 0) return;
        auto& s = layout.slots[off];
        if (s.direct_observed || s.size_bytes != 0) return;
        s.offset     = off;
        s.size_bytes = 8;
        s.type       = IrType::I64;
        s.name       = slot_name(off);
    };

    for (const auto& bb : fn.blocks) {
        for (const auto& inst : bb.insts) {
            if (reservations.contains(&inst)) continue;
            if (inst.op == IrOp::Load) {
                if (inst.src_count >= 1) {
                    if (auto off = trace_stack(inst.srcs[0], defs); off) {
                        observe(*off, inst.dst.type);
                    }
                }
                continue;
            }
            if (inst.op == IrOp::Store) {
                if (inst.src_count >= 2) {
                    if (auto off = trace_stack(inst.srcs[0], defs); off) {
                        observe(*off, inst.srcs[1].type);
                    }
                }
                // Also let the stored value participate in the
                // address-only sweep - a stored-then-loaded stack
                // pointer should still surface a declaration.
                if (inst.src_count >= 2) {
                    if (auto off = trace_stack(inst.srcs[1], defs); off) {
                        observe_addr_only(*off);
                    }
                }
                continue;
            }
            for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
                if (auto off = trace_stack(inst.srcs[i], defs); off) {
                    observe_addr_only(*off);
                }
            }
        }
    }

    // Merge PDB-derived locals if the binary supplied any. PDB
    // S_REGREL32 records carry an offset relative to a register's
    // post-prologue value (typically RSP); to match an analysis slot
    // we need to convert that to an entry-rsp-relative offset:
    //
    //   reg = RSP  → entry_offset = pdb_offset - frame_size
    //   reg = RBP  → entry_offset = pdb_offset - 8     (saved-rbp slot)
    //   reg = 0    (S_BPREL32, implicit RBP) → same as RBP
    //
    // Naïvely setting frame_size = -min(slot.offset) breaks on Win64
    // code where the prologue allocates shadow space the body never
    // touches: the deepest *observed* slot is shallower than the real
    // frame. Instead, vote: every (analysis-slot, pdb-RSP-local) pair
    // suggests a candidate frame size = pdb_off - slot_off. The
    // candidate that wins the most votes is the real frame size,
    // because all RSP-relative locals share the same delta to entry-rsp.
    const auto* pe = dynamic_cast<const PeBinary*>(binary);
    if (pe == nullptr) return layout;
    const auto* hints = pe->pdb_locals_for(fn.start);
    if (hints == nullptr || hints->empty()) return layout;

    std::map<i64, int> frame_size_votes;
    for (const auto& [a_off, _] : layout.slots) {
        for (const auto& h : *hints) {
            if (h.reg != kCvRegRsp) continue;
            const i64 candidate = static_cast<i64>(h.frame_offset) - a_off;
            if (candidate <= 0) continue;
            ++frame_size_votes[candidate];
        }
    }
    i64 frame_size = 0;
    int best_votes = 0;
    for (const auto& [f, votes] : frame_size_votes) {
        if (votes > best_votes) {
            best_votes = votes;
            frame_size = f;
        }
    }

    for (const auto& h : *hints) {
        std::optional<i64> entry_off;
        if (h.reg == kCvRegRsp) {
            if (frame_size == 0) continue;     // can't convert without a vote
            entry_off = static_cast<i64>(h.frame_offset) - frame_size;
        } else if (h.reg == kCvRegRbp || h.reg == 0) {
            entry_off = static_cast<i64>(h.frame_offset) - 8;
        }
        if (!entry_off) continue;
        if (*entry_off == 0) continue;
        auto& s = layout.slots[*entry_off];
        s.offset = *entry_off;
        if (s.size_bytes == 0) s.size_bytes = 8;     // type_override carries the real width
        if (!h.name.empty())     s.name          = h.name;
        if (!h.type_str.empty()) s.type_override = h.type_str;
    }

    return layout;
}

}  // namespace spelunk
