#include <ember/analysis/arity.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <unordered_set>
#include <utility>
#include <vector>

#include <ember/analysis/import_sigs.hpp>
#include <ember/analysis/ir_cache.hpp>
#include <ember/binary/arch.hpp>
#include <ember/binary/symbol.hpp>
#include <ember/common/types.hpp>
#include <ember/disasm/instruction.hpp>
#include <ember/disasm/register.hpp>
#include <ember/disasm/x64_decoder.hpp>
#include <ember/ir/abi.hpp>
#include <ember/ir/ir.hpp>
#include <ember/ir/ssa.hpp>
#include <ember/ir/types.hpp>

namespace ember {

namespace {

[[nodiscard]] constexpr i64 ppc_stack_arg_first_offset(Abi abi) noexcept {
    // PPC32: 8-byte linkage area + eight 4-byte GPR parameter-home slots.
    // PPC64: 48-byte linkage area + eight 8-byte GPR parameter-home slots.
    return abi == Abi::Ppc32Sysv ? 0x28 : 0x70;
}

[[nodiscard]] constexpr i64 ppc_stack_arg_word_size(Abi abi) noexcept {
    return abi == Abi::Ppc32Sysv ? 4 : 8;
}

[[nodiscard]] std::vector<InferredArgument>
infer_ppc_arguments_from_ir_impl(IrCache& cache, std::set<addr_t>& visiting,
                                 const Binary& b, addr_t target, Abi abi,
                                 unsigned depth) noexcept {
    // PPC call instructions do not encode arity, and the old x86-only
    // fallback consequently reported every Wii callee as taking zero
    // arguments.  Reuse the lifted SSA here: a version-zero ABI argument
    // register read by a real instruction is a live-in parameter.
    //
    // Deliberately ignore ABI bookkeeping.  call.args.* snapshots all eight
    // registers whether or not the callee consumes them, Phi nodes merge the
    // same conservative register set at joins, and Return reads r3/f1 even
    // for a source-level void function.  Counting any of those would turn
    // nearly every PPC function into an eight-argument value-returning one.
    const bool uncached = !cache.by_addr.contains(target) && !cache.failed.contains(target);
    if (depth > 4 || (uncached && cache.by_addr.size() + cache.failed.size() >= 64) ||
        !visiting.insert(target).second) return {};
    IrFunction* fn = lift_cached(cache, b, target);
    if (!fn) {
        visiting.erase(target);
        return {};
    }

    const auto int_args = int_arg_regs(abi);
    const auto fp_args = fp_arg_regs(abi);
    struct Evidence {
        bool live = false;
        bool pointer_like = false;
        std::size_t first_use = std::numeric_limits<std::size_t>::max();
    };
    std::array<Evidence, kMaxAbiIntArgs> int_evidence{};
    std::array<Evidence, kMaxAbiFpArgs> fp_evidence{};
    struct StackEvidence {
        IrType type = IrType::I64;
        std::size_t first_use = std::numeric_limits<std::size_t>::max();
    };
    std::map<i64, StackEvidence> stack_evidence;
    std::map<SsaKey, std::pair<std::size_t, std::size_t>> def_pos;
    std::map<SsaKey, const IrInst*> defs;
    for (std::size_t bi = 0; bi < fn->blocks.size(); ++bi) {
        const auto& bb = fn->blocks[bi];
        for (std::size_t ii = 0; ii < bb.insts.size(); ++ii) {
            if (auto k = ssa_key(bb.insts[ii].dst); k) {
                def_pos[*k] = {bi, ii};
                defs[*k] = &bb.insts[ii];
            }
        }
    }
    auto is_save_helper_clobber = [&](const IrValue& v) {
        auto key = ssa_key(v);
        if (!key) return false;
        auto pos = def_pos.find(*key);
        if (pos == def_pos.end()) return false;
        const auto [bi, clobber_ii] = pos->second;
        const auto& bb = fn->blocks[bi];
        if (bb.insts[clobber_ii].op != IrOp::Clobber) return false;
        for (std::size_t ii = clobber_ii; ii > 0;) {
            const IrInst& prev = bb.insts[--ii];
            if (prev.op == IrOp::Clobber || prev.op == IrOp::Nop) continue;
            if (prev.op != IrOp::Call) return false;
            const Symbol* sym = b.defined_object_at(prev.target1);
            if (!sym) return false;
            return sym->name.starts_with("_savegpr_") ||
                   sym->name.starts_with("_savefpr_") ||
                   sym->name.starts_with("__save_gpr") ||
                   sym->name.starts_with("__save_fpr");
        }
        return false;
    };

    const auto entry_stack_offset = [&](auto&& self, const IrValue& value,
                                        int trace_depth) -> std::optional<i64> {
        if (trace_depth > 16) return std::nullopt;
        if (value.kind == IrValueKind::Reg) {
            if (canonical_reg(value.reg) != Reg::PpcR1) return std::nullopt;
            if (value.version == 0) return i64{0};
            auto key = ssa_key(value);
            if (!key) return std::nullopt;
            auto it = defs.find(*key);
            if (it == defs.end()) return std::nullopt;
            const IrInst* def = it->second;
            return def->op == IrOp::Assign && def->src_count == 1
                ? self(self, def->srcs[0], trace_depth + 1)
                : std::nullopt;
        }
        if (value.kind != IrValueKind::Temp) return std::nullopt;
        auto key = ssa_key(value);
        if (!key) return std::nullopt;
        auto it = defs.find(*key);
        if (it == defs.end()) return std::nullopt;
        const IrInst* def = it->second;
        if (def->op == IrOp::Assign && def->src_count == 1) {
            return self(self, def->srcs[0], trace_depth + 1);
        }
        if ((def->op == IrOp::Add || def->op == IrOp::Sub) &&
            def->src_count == 2 && def->srcs[1].kind == IrValueKind::Imm) {
            auto base = self(self, def->srcs[0], trace_depth + 1);
            if (!base) return std::nullopt;
            return def->op == IrOp::Add
                ? *base + def->srcs[1].imm
                : *base - def->srcs[1].imm;
        }
        if (def->op == IrOp::Add && def->src_count == 2 &&
            def->srcs[0].kind == IrValueKind::Imm) {
            auto base = self(self, def->srcs[1], trace_depth + 1);
            if (base) return *base + def->srcs[0].imm;
        }
        return std::nullopt;
    };

    auto candidate_for = [&](Reg r) -> std::optional<std::pair<bool, std::size_t>> {
        const Reg canon = canonical_reg(r);
        for (std::size_t i = 0; i < int_args.size(); ++i) {
            if (int_args[i] == canon) return std::pair{false, i};
        }
        for (std::size_t i = 0; i < fp_args.size(); ++i) {
            if (fp_args[i] == canon) return std::pair{true, i};
        }
        return std::nullopt;
    };
    auto trace_candidate = [&](auto&& self, const IrValue& value,
                               int alias_depth) -> std::optional<std::pair<bool, std::size_t>> {
        if (alias_depth > 10 || value.kind != IrValueKind::Reg) return std::nullopt;
        if (value.version == 0 || is_save_helper_clobber(value)) {
            return candidate_for(value.reg);
        }
        auto key = ssa_key(value);
        if (!key) return std::nullopt;
        auto it = defs.find(*key);
        if (it == defs.end()) return std::nullopt;
        const IrInst* def = it->second;
        if (def->op == IrOp::Assign && def->src_count == 1) {
            return self(self, def->srcs[0], alias_depth + 1);
        }
        return std::nullopt;
    };

    auto mark_evidence = [&](const IrValue& src, std::size_t order,
                             bool pointer_like = false) {
        auto candidate = trace_candidate(trace_candidate, src, 0);
        if (!candidate) return;
        const auto [is_fp, index] = *candidate;
        Evidence& evidence = is_fp ? fp_evidence[index]
                                   : int_evidence[index];
        evidence.live = true;
        evidence.pointer_like |= pointer_like;
        evidence.first_use = std::min(evidence.first_use, order);
    };

    const auto mark_pointer_evidence = [&](auto&& self, const IrValue& value,
                                           std::size_t use_order,
                                           int pointer_depth) -> void {
        if (pointer_depth > 8) return;
        if (trace_candidate(trace_candidate, value, 0)) {
            mark_evidence(value, use_order, true);
            return;
        }
        auto key = ssa_key(value);
        if (!key) return;
        auto it = defs.find(*key);
        if (it == defs.end()) return;
        const IrInst* def = it->second;
        if (def->op == IrOp::Assign && def->src_count == 1) {
            self(self, def->srcs[0], use_order, pointer_depth + 1);
            return;
        }
        if ((def->op == IrOp::Add || def->op == IrOp::Sub) &&
            def->src_count == 2) {
            // Base plus a constant displacement is unambiguous pointer
            // arithmetic. Avoid guessing when both operands are dynamic;
            // either one could be an integer index.
            if (def->srcs[1].kind == IrValueKind::Imm) {
                self(self, def->srcs[0], use_order, pointer_depth + 1);
            } else if (def->op == IrOp::Add &&
                       def->srcs[0].kind == IrValueKind::Imm) {
                self(self, def->srcs[1], use_order, pointer_depth + 1);
            }
        }
    };

    std::size_t order = 0;
    for (const auto& bb : fn->blocks) {
        std::vector<IrValue> pending_int;
        std::vector<IrValue> pending_fp;
        for (const auto& inst : bb.insts) {
            ++order;
            if (inst.op == IrOp::Intrinsic &&
                inst.name.starts_with("call.args.")) {
                if (inst.name == "call.args.1") pending_int.clear();
                for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
                    pending_int.push_back(inst.srcs[i]);
                }
                continue;
            }
            if (inst.op == IrOp::Intrinsic &&
                inst.name.starts_with("call.fp_args.")) {
                if (inst.name == "call.fp_args.1") pending_fp.clear();
                for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
                    pending_fp.push_back(inst.srcs[i]);
                }
                continue;
            }
            if (inst.op == IrOp::Call) {
                // Follow short wrapper chains, with a depth and graph budget
                // above. One level loses parameters passed through multiple
                // constructors or allocation wrappers.
                if (depth < 4) {
                    std::vector<InferredArgument> callee_layout;
                    bool callee_layout_is_declared = false;
                    if (const Symbol* callee = b.defined_object_at(inst.target1);
                        callee && callee->kind == SymbolKind::Function &&
                        callee->addr == inst.target1) {
                        TypeArena arena;
                        if (auto spec = lookup_import_sig(callee->name, arena); spec) {
                            callee_layout_is_declared = true;
                            std::size_t int_index = 0;
                            std::size_t fp_index = 0;
                            for (TypeRef param : spec->params) {
                                const TypeKind kind = arena.kind(param);
                                const bool fp = kind == TypeKind::Float;
                                const auto regs = fp ? fp_args : int_args;
                                const std::size_t index = fp ? fp_index++ : int_index++;
                                if (index >= regs.size()) continue;
                                callee_layout.push_back({
                                    regs[index],
                                    fp ? (arena.node(param).f.bits <= 32
                                              ? IrType::F32 : IrType::F64)
                                       : (abi == Abi::Ppc32Sysv
                                              ? IrType::I32 : IrType::I64),
                                    kind == TypeKind::Ptr});
                            }
                        }
                    }
                    if (callee_layout.empty()) {
                        callee_layout = infer_ppc_arguments_from_ir_impl(
                            cache, visiting, b, inst.target1, abi, depth + 1);
                    }
                    for (const auto& arg : callee_layout) {
                        const auto regs = is_ppc_fpr(arg.reg) ? fp_args : int_args;
                        const auto& values = is_ppc_fpr(arg.reg) ? pending_fp
                                                                 : pending_int;
                        for (std::size_t i = 0; i < regs.size() && i < values.size(); ++i) {
                            if (canonical_reg(regs[i]) == canonical_reg(arg.reg)) {
                                // A recursively inferred FPR lane is weak
                                // evidence when this function merely forwards
                                // its untouched entry value.  Every PPC call
                                // snapshots f1..f8, so accepting that evidence
                                // recursively lets one real floating callee
                                // turn an entire integer-only wrapper chain
                                // into phantom FP parameters.  A declared SDK
                                // prototype (for example fmod) remains strong
                                // enough to prove a forwarding wrapper.
                                if (!callee_layout_is_declared && is_ppc_fpr(arg.reg) &&
                                    values[i].kind == IrValueKind::Reg && values[i].version == 0) {
                                    break;
                                }
                                mark_evidence(values[i], order, arg.pointer_like);
                                break;
                            }
                        }
                    }
                }
                pending_int.clear();
                pending_fp.clear();
                continue;
            }
            if (inst.op == IrOp::CallIndirect) {
                // An untouched snapshot is not evidence of a parameter.
                // Moving an incoming integer argument to a different outgoing
                // ABI lane is: virtual allocation wrappers commonly move the
                // requested size from r3 to r4 after installing a receiver.
                for (std::size_t i = 0; i < pending_int.size() && i < int_args.size(); ++i) {
                    auto source = trace_candidate(trace_candidate, pending_int[i], 0);
                    if (source && !source->first && source->second != i)
                        mark_evidence(pending_int[i], order);
                }
                pending_int.clear();
                pending_fp.clear();
                continue;
            }
            if (inst.op == IrOp::Clobber || inst.op == IrOp::Phi ||
                inst.op == IrOp::Return ||
                (inst.op == IrOp::Intrinsic &&
                 (inst.name.starts_with("call.args.") ||
                  inst.name.starts_with("call.fp_args.")))) {
                continue;
            }
            if (inst.op == IrOp::Load && inst.src_count >= 1) {
                if (auto off = entry_stack_offset(entry_stack_offset,
                                                  inst.srcs[0], 0); off) {
                    const i64 first = ppc_stack_arg_first_offset(abi);
                    const i64 word = ppc_stack_arg_word_size(abi);
                    const i64 max = first +
                        static_cast<i64>(kMaxAbiArgs - kMaxAbiIntArgs) * word;
                    if (*off >= first && *off < max && (*off - first) % word == 0) {
                        auto& evidence = stack_evidence[*off];
                        evidence.type = inst.dst.type;
                        evidence.first_use = std::min(evidence.first_use, order);
                        // An overflow integer word proves the preceding GPR
                        // parameter prefix even if those values are unused in
                        // this callee. Exact mixed layouts remain signature-
                        // driven because stripped code does not encode them.
                        for (auto& e : int_evidence) {
                            e.live = true;
                            e.first_use = std::min(e.first_use, order);
                        }
                    }
                }
            }
            if ((inst.op == IrOp::Load || inst.op == IrOp::Store) &&
                inst.src_count >= 1) {
                mark_pointer_evidence(mark_pointer_evidence, inst.srcs[0], order, 0);
            }
            if (inst.op == IrOp::Intrinsic &&
                inst.name.starts_with("ppc.psq_l") && inst.src_count >= 1) {
                mark_pointer_evidence(mark_pointer_evidence, inst.srcs[0], order, 0);
            } else if (inst.op == IrOp::Intrinsic &&
                       inst.name.starts_with("ppc.psq_st") && inst.src_count >= 2) {
                mark_pointer_evidence(mark_pointer_evidence, inst.srcs[1], order, 0);
            }
            for (u8 si = 0; si < inst.src_count && si < inst.srcs.size(); ++si) {
                const IrValue& src = inst.srcs[si];
                mark_evidence(src, order);
            }
        }
    }

    auto prefix_size = [](const auto& evidence, std::size_t limit) {
        std::size_t size = 0;
        for (std::size_t i = 0; i < limit; ++i) {
            if (evidence[i].live) size = i + 1;
        }
        return size;
    };
    const std::size_t int_count = prefix_size(int_evidence, int_args.size());
    const std::size_t fp_count = prefix_size(fp_evidence, fp_args.size());

    auto lane_score = [](const auto& evidence, std::size_t begin,
                         std::size_t count) {
        std::size_t score = std::numeric_limits<std::size_t>::max();
        for (std::size_t i = begin; i < count; ++i) {
            score = std::min(score, evidence[i].first_use);
        }
        return score;
    };

    std::vector<InferredArgument> result;
    result.reserve(int_count + fp_count);
    std::size_t gi = 0;
    std::size_t fi = 0;
    while (gi < int_count || fi < fp_count) {
        const auto gscore = gi < int_count
            ? lane_score(int_evidence, gi, int_count)
            : std::numeric_limits<std::size_t>::max();
        const auto fscore = fi < fp_count
            ? lane_score(fp_evidence, fi, fp_count)
            : std::numeric_limits<std::size_t>::max();
        if (gi < int_count && (fi >= fp_count || gscore <= fscore)) {
            const std::size_t index = gi++;
            result.push_back({int_args[index],
                              abi == Abi::Ppc32Sysv ? IrType::I32 : IrType::I64,
                              int_evidence[index].pointer_like});
        } else {
            // The PPC32 ABI transports scalar float values in the 64-bit FPR
            // representation as well, so scalar instructions alone cannot
            // reliably distinguish a source `float` from `double`. Keep the
            // binary-only declaration conservative; explicit signatures can
            // still pin a parameter to float.
            result.push_back({fp_args[fi++], IrType::F64});
        }
    }
    if (!stack_evidence.empty()) {
        const i64 first = ppc_stack_arg_first_offset(abi);
        const i64 word = ppc_stack_arg_word_size(abi);
        const i64 last = stack_evidence.rbegin()->first;
        for (i64 off = first;
             off <= last && result.size() < kMaxAbiArgs;) {
            auto it = stack_evidence.find(off);
            const IrType type = it == stack_evidence.end()
                ? (abi == Abi::Ppc32Sysv ? IrType::I32 : IrType::I64)
                : it->second.type;
            result.push_back({Reg::None, type, false, off});
            i64 width = static_cast<i64>(std::max<unsigned>(
                static_cast<unsigned>(word), type_bits(type) / 8));
            width = ((width + word - 1) / word) * word;
            off += width;
        }
    }
    visiting.erase(target);
    return result;
}

[[nodiscard]] std::vector<InferredArgument>
infer_ppc_arguments_from_ir(const Binary& b, addr_t target, Abi abi) noexcept {
    IrCache cache;
    std::set<addr_t> visiting;
    return infer_ppc_arguments_from_ir_impl(cache, visiting, b, target, abi, 0);
}

[[nodiscard]] bool is_rsp_adjust(const Instruction& insn, Mnemonic mn) noexcept {
    if (insn.mnemonic != mn || insn.num_operands != 2) return false;
    if (insn.operands[0].kind != Operand::Kind::Register ||
        canonical_reg(insn.operands[0].reg) != Reg::Rsp) {
        return false;
    }
    return insn.operands[1].kind == Operand::Kind::Immediate;
}

[[nodiscard]] std::optional<addr_t>
follow_trivial_wrapper(const Binary& b, addr_t target) noexcept {
    X64Decoder dec;

    auto decode_at = [&](addr_t ip) -> std::optional<Instruction> {
        auto span = b.bytes_at(ip);
        if (span.empty()) return std::nullopt;
        auto decoded = dec.decode(span, ip);
        if (!decoded) return std::nullopt;
        return *decoded;
    };

    auto first = decode_at(target);
    if (!first) return std::nullopt;

    addr_t ip = target;
    if (first->mnemonic == Mnemonic::Endbr64) {
        ip += first->length;
        first = decode_at(ip);
        if (!first) return std::nullopt;
    }

    bool saw_shadow = false;
    if (is_rsp_adjust(*first, Mnemonic::Sub)) {
        saw_shadow = true;
        ip += first->length;
        first = decode_at(ip);
        if (!first) return std::nullopt;
    }

    if (first->mnemonic == Mnemonic::Jmp &&
        first->num_operands == 1 &&
        first->operands[0].kind == Operand::Kind::Relative) {
        return first->operands[0].rel.target;
    }

    if (first->mnemonic != Mnemonic::Call ||
        first->num_operands != 1 ||
        first->operands[0].kind != Operand::Kind::Relative) {
        return std::nullopt;
    }

    addr_t callee = first->operands[0].rel.target;
    ip += first->length;

    auto second = decode_at(ip);
    if (!second) return std::nullopt;
    if (saw_shadow) {
        if (!is_rsp_adjust(*second, Mnemonic::Add)) return std::nullopt;
        ip += second->length;
        second = decode_at(ip);
        if (!second) return std::nullopt;
    }

    if (second->mnemonic != Mnemonic::Ret) return std::nullopt;
    if (callee == target) return std::nullopt;
    return callee;
}

[[nodiscard]] int arg_reg_index(std::span<const Reg> args, Reg r) noexcept {
    const Reg c = canonical_reg(r);
    for (std::size_t i = 0; i < args.size(); ++i) {
        if (c == args[i]) return static_cast<int>(i);
    }
    return -1;
}

enum class DstRole : u8 { WriteOnly, ReadWrite, ReadOnly };

[[nodiscard]] DstRole dst_role(Mnemonic m) noexcept {
    switch (m) {
        case Mnemonic::Mov:  case Mnemonic::Movzx:
        case Mnemonic::Movsx:case Mnemonic::Movsxd:
        case Mnemonic::Lea:  case Mnemonic::Pop:
            return DstRole::WriteOnly;

        case Mnemonic::Add: case Mnemonic::Sub:
        case Mnemonic::Adc: case Mnemonic::Sbb:
        case Mnemonic::And: case Mnemonic::Or: case Mnemonic::Xor:
        case Mnemonic::Neg: case Mnemonic::Not:
        case Mnemonic::Shl: case Mnemonic::Shr: case Mnemonic::Sar:
        case Mnemonic::Inc: case Mnemonic::Dec:
        case Mnemonic::Imul: case Mnemonic::Xchg:
            return DstRole::ReadWrite;

        default:
            return DstRole::ReadOnly;
    }
}

}  // namespace

u8 infer_arity(const Binary& b, addr_t target, Abi abi) noexcept {
    if (b.arch() == Arch::Ppc32 || b.arch() == Arch::Ppc64) {
        return static_cast<u8>(std::min<std::size_t>(
            infer_ppc_arguments_from_ir(b, target, abi).size(),
            std::numeric_limits<u8>::max()));
    }
    if (b.arch() != Arch::X86_64) return 0;
    const auto args = int_arg_regs(abi);
    const u8 max_arity = static_cast<u8>(args.size());

    // Transparently follow trivial wrappers (`jmp target`, `call target; ret`,
    // and the Win64 shadow-space variant) so forwarding stubs inherit the
    // underlying callee's arity instead of appearing variadic or arg-less.
    for (int hops = 0; hops < 6; ++hops) {
        auto hop_target = follow_trivial_wrapper(b, target);
        if (!hop_target) break;
        target = *hop_target;
    }

    auto entry_bytes = b.bytes_at(target);
    if (entry_bytes.empty()) return max_arity;

    // BFS over reachable instruction addresses from `target`, accumulating
    // per-path "first read before any write" information for each int-arg
    // register. We track `written` as a path-state via a parallel mask, but
    // because we want a may-read-before-write across all paths (any path can
    // demonstrate the arg is consumed), we propagate the most-pessimistic
    // written state - i.e. once an arg is reported live-in on any path, it
    // stays live-in regardless of later writes on a different path.
    //
    // Concretely: a register is live-in if some path reads it before writing
    // it. We model that by walking forward, and on a branch enqueue both
    // successors with a copy of the per-path written mask. Visit count is
    // capped at kMaxVisits; addresses already visited with a strictly weaker
    // (subset) written mask are skipped to keep the worklist bounded.
    //
    // Read the call's incoming arguments before marking its caller-saved
    // lanes written; later register reads cannot prove entry live-ins.
    constexpr std::size_t kMaxVisits = 1024;

    std::array<bool, kMaxAbiIntArgs> live_in{};
    std::unordered_set<addr_t> visited;
    visited.reserve(64);

    using Mask = u8;  // up to 8 arg regs, fits in a byte
    static_assert(kMaxAbiIntArgs <= 8);
    auto mask_of = [](const std::array<bool, kMaxAbiIntArgs>& m) -> Mask {
        Mask r = 0;
        for (std::size_t i = 0; i < m.size(); ++i) {
            if (m[i]) r |= static_cast<Mask>(1u << i);
        }
        return r;
    };

    struct WorkItem { addr_t ip; Mask written; };
    std::vector<WorkItem> work;
    work.push_back({target, 0});

    X64Decoder dec;
    std::size_t visits = 0;
    TypeArena import_types;

    while (!work.empty() && visits < kMaxVisits) {
        const auto wi = work.back();
        work.pop_back();

        addr_t ip = wi.ip;
        std::array<bool, kMaxAbiIntArgs> written{};
        for (std::size_t i = 0; i < written.size(); ++i) {
            written[i] = (wi.written >> i) & 1u;
        }

        // Per-path linear walk; on branches we enqueue successors and stop.
        // Cap the per-path step count separately so a tight self-loop without
        // a back-edge break can't spin forever.
        for (int step = 0; step < 256 && visits < kMaxVisits; ++step) {
            ++visits;
            // Visit guard: skip if we've seen this addr with a written mask
            // at least as restrictive (subset). We approximate "subset" with
            // exact equality keyed on (ip), to keep the table small - picks
            // up the common cases (loops, shared prologues) without growing
            // the visited set unboundedly.
            const auto [it, inserted] = visited.insert(ip);
            (void)it;
            if (!inserted) break;

            auto span = b.bytes_at(ip);
            if (span.empty()) break;
            auto decoded = dec.decode(span, ip);
            if (!decoded) break;
            const Instruction& insn = *decoded;

            const DstRole role = dst_role(insn.mnemonic);
            const bool dst_writes = (role == DstRole::WriteOnly || role == DstRole::ReadWrite);
            const bool dst_reads  = (role == DstRole::ReadOnly  || role == DstRole::ReadWrite);
            const bool zero_idiom =
                (insn.mnemonic == Mnemonic::Xor || insn.mnemonic == Mnemonic::Sub) &&
                insn.num_operands == 2 &&
                insn.operands[0].kind == Operand::Kind::Register &&
                insn.operands[1].kind == Operand::Kind::Register &&
                insn.operands[0].reg == insn.operands[1].reg;

            auto touch = [&](Reg r, bool read, bool write) {
                const int idx = arg_reg_index(args, r);
                if (idx < 0) return;
                const auto u = static_cast<std::size_t>(idx);
                if (read && !written[u]) live_in[u] = true;
                if (write) written[u] = true;
            };

            for (u8 j = 0; j < insn.num_operands; ++j) {
                const Operand& op = insn.operands[j];
                const bool is_dst = (j == 0);
                const bool read  = !zero_idiom && (is_dst ? dst_reads : true);
                const bool write = is_dst ? dst_writes : false;

                if (op.kind == Operand::Kind::Register) {
                    touch(op.reg, read, write);
                } else if (op.kind == Operand::Kind::Memory) {
                    if (op.mem.base  != Reg::None) touch(op.mem.base,  true, false);
                    if (op.mem.index != Reg::None) touch(op.mem.index, true, false);
                }
            }

            if ((insn.mnemonic == Mnemonic::Call || insn.mnemonic == Mnemonic::Jmp) &&
                insn.num_operands == 1 &&
                insn.operands[0].kind == Operand::Kind::Relative) {
                const Symbol* s = b.import_at_plt(insn.operands[0].rel.target);
                if (s) {
                    if (auto spec = lookup_import_sig(
                            strip_import_name_decorations(s->name), import_types); spec) {
                        const std::size_t n =
                            std::min<std::size_t>(spec->params.size(), args.size());
                        for (std::size_t i = 0; i < n; ++i) {
                            if (!written[i]) live_in[i] = true;
                        }
                    }
                }
            }

            if (insn.mnemonic == Mnemonic::Ret ||
                insn.mnemonic == Mnemonic::Ud2 ||
                insn.mnemonic == Mnemonic::Hlt) break;

            if (insn.mnemonic == Mnemonic::Call) written.fill(true);

            // Unconditional jmp: follow the target if it's a known relative,
            // otherwise stop this path.
            if (insn.mnemonic == Mnemonic::Jmp) {
                if (insn.num_operands == 1 &&
                    insn.operands[0].kind == Operand::Kind::Relative) {
                    ip = insn.operands[0].rel.target;
                    continue;
                }
                break;
            }

            // Conditional branch: enqueue the target, fall through to the
            // next instruction.
            if (is_conditional_branch(insn.mnemonic) &&
                insn.num_operands == 1 &&
                insn.operands[0].kind == Operand::Kind::Relative) {
                work.push_back({insn.operands[0].rel.target, mask_of(written)});
            }

            ip += insn.length;
        }
    }

    int max_live_in = -1;
    for (std::size_t i = 0; i < live_in.size(); ++i) {
        if (live_in[i]) max_live_in = static_cast<int>(i);
    }
    return static_cast<u8>(max_live_in + 1);
}

void extend_x64_fp_arguments(const IrFunction& fn, Abi abi,
                             std::vector<InferredArgument>& arguments,
                             std::span<const IrValue> call_arguments) {
    if (abi != Abi::SysVAmd64 && abi != Abi::Win64) return;
    std::map<SsaKey, const IrInst*> definitions;
    for (const auto& block : fn.blocks) {
        for (const auto& inst : block.insts) {
            if (auto key = ssa_key(inst.dst)) definitions[*key] = &inst;
        }
    }
    const auto registers = fp_arg_regs(abi);
    const auto integer_registers = int_arg_regs(abi);
    std::size_t integer_count = arguments.size();
    std::map<Reg, IrType> live;
    std::set<std::pair<SsaKey, IrType>> seen;
    std::vector<std::pair<IrValue, IrType>> pending;
    for (const auto& block : fn.blocks) {
        for (const auto& inst : block.insts) {
            if (inst.op == IrOp::Return || inst.op == IrOp::Phi ||
                (inst.op == IrOp::Intrinsic && (inst.name.starts_with("call.args.") ||
                 inst.name.starts_with("call.fp_args.") || inst.name == "call.stack_pointer"))) continue;
            for (u8 i = 0; i < inst.src_count; ++i) {
                if (is_float_type(inst.srcs[i].type)) {
                    pending.emplace_back(inst.srcs[i], inst.srcs[i].type);
                }
            }
        }
    }
    for (const auto& value : call_arguments) pending.emplace_back(value, value.type);
    while (!pending.empty()) {
        auto [value, type] = pending.back();
        pending.pop_back();
        if (is_float_type(value.type)) type = value.type;
        auto key = ssa_key(value);
        if (!key || !seen.emplace(*key, type).second) continue;
        if (value.kind == IrValueKind::Reg && value.version == 0 && !is_float_type(type)) {
            const auto it = std::ranges::find(integer_registers, canonical_reg(value.reg));
            if (it != integer_registers.end()) {
                integer_count = std::max(integer_count,
                    static_cast<std::size_t>(it - integer_registers.begin()) + 1);
            }
        }
        if (value.kind == IrValueKind::Reg && value.version == 0 &&
            is_float_type(type) &&
            std::ranges::find(registers, canonical_reg(value.reg)) != registers.end()) {
            auto [it, inserted] = live.emplace(canonical_reg(value.reg), type);
            if (!inserted && type_bits(type) > type_bits(it->second)) it->second = type;
            continue;
        }
        auto found = definitions.find(*key);
        if (found == definitions.end()) continue;
        const auto& inst = *found->second;
        if (inst.op == IrOp::Assign || inst.op == IrOp::Trunc) {
            if (inst.src_count) pending.emplace_back(inst.srcs[0], type);
        } else if (inst.op == IrOp::Phi) {
            for (const auto& operand : inst.phi_operands) pending.emplace_back(operand, type);
        }
    }
    // SysV's independent banks do not encode their source-level interleaving.
    // Keep the integer prefix, then name proven scalar FP lanes in ABI order.
    while (arguments.size() < integer_count && arguments.size() < integer_registers.size()) {
        arguments.push_back({integer_registers[arguments.size()], IrType::I64});
    }
    std::size_t fp_count = 0;
    for (std::size_t i = 0; i < registers.size(); ++i) {
        if (live.contains(canonical_reg(registers[i]))) fp_count = i + 1;
    }
    for (std::size_t i = 0; i < fp_count; ++i) {
        auto found = live.find(canonical_reg(registers[i]));
        if (abi_positional_arg_slots(abi)) {
            if (found == live.end()) continue;
            const auto ints = int_arg_regs(abi);
            while (arguments.size() <= i) {
                arguments.push_back({ints[arguments.size()], IrType::I64});
            }
            arguments[i] = {registers[i], found->second};
        } else {
            if (arguments.size() == kMaxAbiArgs) break;
            arguments.push_back({registers[i],
                found == live.end() ? IrType::F64 : found->second});
        }
    }
}

std::vector<InferredArgument>
infer_arguments(const Binary& b, addr_t target, Abi abi) noexcept {
    if (b.arch() == Arch::Ppc32 || b.arch() == Arch::Ppc64) {
        return infer_ppc_arguments_from_ir(b, target, abi);
    }
    const auto regs = int_arg_regs(abi);
    const std::size_t count = std::min<std::size_t>(infer_arity(b, target, abi),
                                                    regs.size());
    std::vector<InferredArgument> result;
    result.reserve(count);
    const IrType type = (b.arch() == Arch::Arm) ? IrType::I32 : IrType::I64;
    for (std::size_t i = 0; i < count; ++i) result.push_back({regs[i], type});
    if (b.arch() == Arch::X86_64) {
        IrCache cache;
        if (auto* function = lift_cached(cache, b, target)) {
            extend_x64_fp_arguments(*function, abi, result);
        }
    }
    return result;
}

std::vector<InferredArgument>
infer_arguments(const Binary& b, addr_t target) noexcept {
    return infer_arguments(b, target,
                           abi_for(b.format(), b.arch(), b.endian()));
}

u8 infer_arity(const Binary& b, addr_t target) noexcept {
    return infer_arity(b, target, abi_for(b.format(), b.arch(), b.endian()));
}

}  // namespace ember
