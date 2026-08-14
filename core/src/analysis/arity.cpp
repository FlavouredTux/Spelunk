#include <ember/analysis/arity.hpp>

#include <array>
#include <cstddef>
#include <map>
#include <span>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include <ember/analysis/ir_cache.hpp>
#include <ember/analysis/import_sigs.hpp>
#include <ember/binary/symbol.hpp>
#include <ember/disasm/instruction.hpp>
#include <ember/disasm/register.hpp>
#include <ember/disasm/x64_decoder.hpp>
#include <ember/ir/ssa.hpp>

namespace ember {

namespace {

[[nodiscard]] u8 infer_ppc_arity_from_ir(const Binary& b, addr_t target,
                                         Abi abi) noexcept {
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
    IrCache cache;
    IrFunction* fn = lift_cached(cache, b, target);
    if (!fn) return 0;

    const auto args = int_arg_regs(abi);
    std::array<bool, kMaxAbiIntArgs> live_in{};
    std::map<SsaKey, std::pair<std::size_t, std::size_t>> def_pos;
    for (std::size_t bi = 0; bi < fn->blocks.size(); ++bi) {
        const auto& bb = fn->blocks[bi];
        for (std::size_t ii = 0; ii < bb.insts.size(); ++ii) {
            if (auto k = ssa_key(bb.insts[ii].dst); k) def_pos[*k] = {bi, ii};
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

    for (const auto& bb : fn->blocks) {
        for (const auto& inst : bb.insts) {
            if (inst.op == IrOp::Clobber || inst.op == IrOp::Phi ||
                inst.op == IrOp::Return ||
                (inst.op == IrOp::Intrinsic &&
                 (inst.name == "call.args.1" || inst.name == "call.args.2" ||
                  inst.name == "call.args.3"))) {
                continue;
            }
            for (u8 si = 0; si < inst.src_count && si < inst.srcs.size(); ++si) {
                const IrValue& src = inst.srcs[si];
                if (src.kind != IrValueKind::Reg ||
                    (src.version != 0 && !is_save_helper_clobber(src))) {
                    continue;
                }
                const Reg canon = canonical_reg(src.reg);
                for (u8 ai = 0; ai < args.size() && ai < live_in.size(); ++ai) {
                    if (args[ai] == canon) live_in[ai] = true;
                }
            }
        }
    }

    int highest = -1;
    for (std::size_t i = 0; i < live_in.size(); ++i) {
        if (live_in[i]) highest = static_cast<int>(i);
    }
    return static_cast<u8>(highest + 1);
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

[[nodiscard]] std::string clean_import_name_local(std::string_view name) {
    auto at = name.find('@');
    std::string bare(at == std::string_view::npos ? name : name.substr(0, at));
    if (bare.starts_with("__imp_")) bare.erase(0, 6);
    if (bare.starts_with('_') && !bare.starts_with("__")) bare.erase(0, 1);
    return bare;
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
        return infer_ppc_arity_from_ir(b, target, abi);
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
    // Calls don't mark args as written - caller-saved clobbering happens
    // *after* the call site's argument setup, and we want to count whatever
    // setup landed before the call.
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
                const bool read  = is_dst ? dst_reads  : true;
                const bool write = is_dst ? dst_writes : false;

                if (op.kind == Operand::Kind::Register) {
                    touch(op.reg, read, write);
                } else if (op.kind == Operand::Kind::Memory) {
                    if (op.mem.base  != Reg::None) touch(op.mem.base,  true, false);
                    if (op.mem.index != Reg::None) touch(op.mem.index, true, false);
                }
            }

            if (insn.mnemonic == Mnemonic::Call &&
                insn.num_operands == 1 &&
                insn.operands[0].kind == Operand::Kind::Relative) {
                const Symbol* s = b.import_at_plt(insn.operands[0].rel.target);
                if (s) {
                    if (auto spec = lookup_import_sig(
                            clean_import_name_local(s->name), import_types); spec) {
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

u8 infer_arity(const Binary& b, addr_t target) noexcept {
    return infer_arity(b, target, abi_for(b.format(), b.arch(), b.endian()));
}

}  // namespace ember
