// Idiom recognition and the MSVC security-cookie return rewrite.

#include <algorithm>
#include <cstddef>
#include <optional>
#include <span>
#include <utility>
#include <vector>

#include <spelunk/common/types.hpp>
#include <spelunk/disasm/register.hpp>
#include <spelunk/ir/ir.hpp>
#include <spelunk/ir/ssa.hpp>

#include "passes_internal.hpp"

namespace spelunk::ir_passes {

const IrInst* strip_assigns_to_def(const IrFunction& fn,
                                   const SsaMap<DefLoc>& defs,
                                   IrValue v, int max_hops) {
    for (int i = 0; i < max_hops; ++i) {
        auto k = ssa_key(v);
        if (!k) return nullptr;
        auto it = defs.find(*k);
        if (it == defs.end()) return nullptr;
        const IrInst& d = fn.blocks[it->second.block].insts[it->second.inst];
        if (d.op == IrOp::Assign && d.src_count == 1 &&
            d.srcs[0].type == v.type) {
            v = d.srcs[0];
            continue;
        }
        return &d;
    }
    return nullptr;
}

const IrValue* match_sign_extend_shift(const IrFunction& fn,
                                       const SsaMap<DefLoc>& defs,
                                       const IrValue& v) {
    const IrInst* d = strip_assigns_to_def(fn, defs, v);
    if (!d || d->op != IrOp::Ashr || d->src_count < 2) return nullptr;
    const IrValue& amt = d->srcs[1];
    if (amt.kind != IrValueKind::Imm) return nullptr;
    const unsigned sign_bit = type_bits(d->srcs[0].type) - 1;
    if (static_cast<unsigned>(amt.imm) != sign_bit) return nullptr;
    return &d->srcs[0];
}

const IrValue* match_sign_mask(const IrFunction& fn,
                               const SsaMap<DefLoc>& defs,
                               const IrValue& v) {
    const IrInst* d = strip_assigns_to_def(fn, defs, v);
    if (!d || d->op != IrOp::And || d->src_count < 2) return nullptr;
    for (std::size_t i = 0; i < 2; ++i) {
        if (const IrValue* x = match_sign_extend_shift(fn, defs, d->srcs[i])) {
            const IrValue& other = d->srcs[1 - i];
            if (same_ssa_value(*x, other)) return x;
            auto xk = ssa_key(*x);
            auto ok = ssa_key(other);
            if (xk && ok && *xk == *ok && other.type == x->type) return x;
        }
    }
    return nullptr;
}

std::size_t pass_idiom_recognize(
    IrFunction& fn, AnalysisManager& am,
    std::span<const u32> dirty, std::vector<u32>& touched) {
    const auto& defs = am.defs(fn);
    std::size_t count = 0;

    for_blocks(fn, dirty, [&](u32 bi, IrBlock& bb) {
        const std::size_t before = count;
        std::vector<IdiomRewrite> rewrites;

        for (std::size_t ii = 0; ii < bb.insts.size(); ++ii) {
            const auto& inst = bb.insts[ii];
            if (inst.src_count < 1 || inst.src_count > 3) continue;

            // Pattern 5: Sub(0, x) → Neg(x)
            if (inst.op == IrOp::Sub && inst.src_count == 2) {
                if (inst.srcs[0].kind == IrValueKind::Imm && inst.srcs[0].imm == 0) {
                    IdiomRewrite r;
                    r.insert_before = ii;
                    r.replacement.op          = IrOp::Neg;
                    r.replacement.dst         = inst.dst;
                    r.replacement.srcs[0]     = inst.srcs[1];
                    r.replacement.srcs[1]     = IrValue{};
                    r.replacement.srcs[2]     = IrValue{};
                    r.replacement.src_count   = 1;
                    r.replacement.source_addr = inst.source_addr;
                    rewrites.push_back(std::move(r));
                    ++count;
                    continue;
                }
            }

            // Pattern 2: Add(x, And(Ashr(x, sign_bit), x)) → abs(x)
            if (inst.op == IrOp::Add && inst.src_count == 2) {
                for (std::size_t i = 0; i < 2; ++i) {
                    const IrValue& lhs = inst.srcs[i];
                    const IrValue& rhs = inst.srcs[1 - i];
                    if (const IrValue* x = match_sign_mask(fn, defs, rhs)) {
                        if (same_ssa_value(lhs, *x)) {
                            const IrValue zero = IrValue::make_imm(0, x->type);
                            const IrValue cmp  = IrValue::make_temp(fn.next_temp_id++, IrType::I1);
                            const IrValue neg  = IrValue::make_temp(fn.next_temp_id++, inst.dst.type);

                            IdiomRewrite r;
                            r.insert_before = ii;

                            IrInst ci;
                            ci.op = IrOp::CmpSlt; ci.dst = cmp;
                            ci.srcs[0] = *x; ci.srcs[1] = zero; ci.srcs[2] = IrValue{};
                            ci.src_count = 2; ci.source_addr = inst.source_addr;

                            IrInst ni;
                            ni.op = IrOp::Neg; ni.dst = neg;
                            ni.srcs[0] = *x; ni.srcs[1] = IrValue{}; ni.srcs[2] = IrValue{};
                            ni.src_count = 1; ni.source_addr = inst.source_addr;

                            r.helpers.push_back(std::move(ci));
                            r.helpers.push_back(std::move(ni));

                            r.replacement.op = IrOp::Select; r.replacement.dst = inst.dst;
                            r.replacement.srcs[0] = cmp; r.replacement.srcs[1] = neg;
                            r.replacement.srcs[2] = *x;
                            r.replacement.src_count = 3; r.replacement.source_addr = inst.source_addr;

                            rewrites.push_back(std::move(r));
                            ++count;
                            break;
                        }
                    }
                }
                continue;
            }

            // Pattern 3: Add(Xor(x, Ashr(x, sign_bit)), Ashr(x, sign_bit)) → abs(x)
            if (inst.op == IrOp::Add && inst.src_count == 2) {
                for (std::size_t i = 0; i < 2; ++i) {
                    const IrValue& xor_val   = inst.srcs[i];
                    const IrValue& shift_val = inst.srcs[1 - i];

                    const IrInst* xd = strip_assigns_to_def(fn, defs, xor_val);
                    if (!xd || xd->op != IrOp::Xor || xd->src_count < 2) continue;

                    const IrValue* sx = match_sign_extend_shift(fn, defs, shift_val);
                    if (!sx) continue;

                    bool ok = false;
                    for (std::size_t j = 0; j < 2; ++j) {
                        if (!same_ssa_value(xd->srcs[j], *sx)) continue;
                        const IrValue& xs = xd->srcs[1 - j];
                        if (same_ssa_value(xs, shift_val)) { ok = true; break; }
                        auto sk = ssa_key(shift_val); auto xk = ssa_key(xs);
                        if (sk && xk && *sk == *xk) { ok = true; break; }
                    }
                    if (!ok) continue;

                    const IrValue zero = IrValue::make_imm(0, sx->type);
                    const IrValue cmp  = IrValue::make_temp(fn.next_temp_id++, IrType::I1);
                    const IrValue neg  = IrValue::make_temp(fn.next_temp_id++, inst.dst.type);

                    IdiomRewrite r;
                    r.insert_before = ii;

                    IrInst ci;
                    ci.op = IrOp::CmpSlt; ci.dst = cmp;
                    ci.srcs[0] = *sx; ci.srcs[1] = zero; ci.srcs[2] = IrValue{};
                    ci.src_count = 2; ci.source_addr = inst.source_addr;

                    IrInst ni;
                    ni.op = IrOp::Neg; ni.dst = neg;
                    ni.srcs[0] = *sx; ni.srcs[1] = IrValue{}; ni.srcs[2] = IrValue{};
                    ni.src_count = 1; ni.source_addr = inst.source_addr;

                    r.helpers.push_back(std::move(ci));
                    r.helpers.push_back(std::move(ni));

                    r.replacement.op = IrOp::Select; r.replacement.dst = inst.dst;
                    r.replacement.srcs[0] = cmp; r.replacement.srcs[1] = neg;
                    r.replacement.srcs[2] = *sx;
                    r.replacement.src_count = 3; r.replacement.source_addr = inst.source_addr;

                    rewrites.push_back(std::move(r));
                    ++count;
                    break;
                }
            }
        }

        // Apply rewrites in reverse index order so earlier positions stay valid.
        if (!rewrites.empty()) {
            std::sort(rewrites.begin(), rewrites.end(),
                      [](const IdiomRewrite& a, const IdiomRewrite& b) {
                          return a.insert_before > b.insert_before;
                      });
            for (auto& r : rewrites) {
                auto pos = bb.insts.begin() + static_cast<std::ptrdiff_t>(r.insert_before);
                pos = bb.insts.insert(pos, r.helpers.begin(), r.helpers.end());
                *(pos + static_cast<std::ptrdiff_t>(r.helpers.size())) = std::move(r.replacement);
            }
        }
        if (count != before) touched.push_back(bi);
    });
    return count;
}

// ============================================================================
// MSVC's __security_check_cookie is a compiler helper with a stronger
// convention than an ordinary Win64 call: it preserves the source-level
// return value already placed in RAX. The generic lifter correctly clobbers
// RAX for normal calls, but doing that here makes DCE delete the real return
// producer and leaves `return rax_N` with no definition in pseudo-C.
//
// Recognize the distinctive epilogue argument `saved_cookie ^ rsp`, then
// redirect the post-call RAX clobber back to the last pre-call RAX SSA value.
// When there is no such value, the function is void and the incidental ABI
// return lanes are removed. This runs once before DCE so the producer is
// still present.
std::size_t pass_msvc_security_cookie_return(IrFunction& fn,
                                             AnalysisManager& am) {
    const auto& defs = am.defs(fn);
    const auto definition = [&](const IrValue& value) -> const IrInst* {
        const auto key = ssa_key(value);
        if (!key) return nullptr;
        auto found = defs.find(*key);
        if (found == defs.end()) return nullptr;
        return &fn.blocks[found->second.block].insts[found->second.inst];
    };
    const auto stripped = [&](IrValue value) -> const IrInst* {
        const IrInst* result = definition(value);
        for (int depth = 0;
             result && result->op == IrOp::Assign && result->src_count == 1 &&
             depth < 16; ++depth) {
            result = definition(result->srcs[0]);
        }
        return result;
    };
    const auto rsp_derived = [&](const auto& self, const IrValue& value,
                                 int depth) -> bool {
        if (depth > 12) return false;
        if (value.kind == IrValueKind::Reg &&
            canonical_reg(value.reg) == Reg::Rsp) return true;
        const IrInst* source = stripped(value);
        if (!source || (source->op != IrOp::Add && source->op != IrOp::Sub) ||
            source->src_count < 2) return false;
        return self(self, source->srcs[0], depth + 1) ||
               (source->op == IrOp::Add &&
                self(self, source->srcs[1], depth + 1));
    };
    const auto cookie_argument = [&](const IrValue& value) {
        const IrInst* x = stripped(value);
        if (!x || x->op != IrOp::Xor || x->src_count < 2) return false;
        for (u8 side = 0; side < 2; ++side) {
            if (!rsp_derived(rsp_derived, x->srcs[1 - side], 0)) continue;
            const IrInst* load = stripped(x->srcs[side]);
            if (load && load->op == IrOp::Load && load->src_count >= 1 &&
                rsp_derived(rsp_derived, load->srcs[0], 0)) return true;
        }
        return false;
    };
    const auto substantive_value = [&](const auto& self, const IrValue& value,
                                       int depth) -> bool {
        if (depth > 16) return false;
        if (value.kind == IrValueKind::Imm) return true;
        if (value.kind == IrValueKind::Reg && value.version == 0) return true;
        const IrInst* source = definition(value);
        if (!source || source->op == IrOp::Clobber) return false;
        if (source->op == IrOp::Assign && source->src_count == 1) {
            return self(self, source->srcs[0], depth + 1);
        }
        if (source->op == IrOp::Phi) {
            return std::ranges::any_of(source->phi_operands,
                [&](const IrValue& operand) {
                    return self(self, operand, depth + 1);
                });
        }
        return true;
    };

    std::size_t rewritten = 0;
    for (auto& block : fn.blocks) {
        for (std::size_t call_index = 0;
             call_index < block.insts.size(); ++call_index) {
            IrInst& call = block.insts[call_index];
            if (call.op != IrOp::Call) continue;
            const IrValue* first_arg = nullptr;
            for (std::size_t scan = call_index; scan > 0;) {
                const IrInst& previous = block.insts[--scan];
                if (previous.op == IrOp::Intrinsic &&
                    previous.name == "call.args.1" && previous.src_count >= 1) {
                    first_arg = &previous.srcs[0];
                    break;
                }
                if (previous.op == IrOp::Call ||
                    previous.op == IrOp::CallIndirect) break;
            }
            if (!first_arg || !cookie_argument(*first_arg)) continue;

            std::optional<IrValue> preserved;
            for (std::size_t scan = call_index; scan > 0;) {
                const IrInst& previous = block.insts[--scan];
                if (previous.dst.kind != IrValueKind::Reg ||
                    canonical_reg(previous.dst.reg) != Reg::Rax) continue;
                if (previous.op != IrOp::Clobber &&
                    substantive_value(substantive_value, previous.dst, 0)) {
                    preserved = previous.dst;
                }
                break;
            }

            std::optional<SsaKey> clobber_key;
            for (std::size_t scan = call_index + 1;
                 scan < block.insts.size(); ++scan) {
                const IrInst& clobber = block.insts[scan];
                if (clobber.op != IrOp::Clobber) break;
                if (clobber.dst.kind != IrValueKind::Reg ||
                    canonical_reg(clobber.dst.reg) != Reg::Rax) continue;
                clobber_key = ssa_key(clobber.dst);
                break;
            }
            if (!clobber_key) continue;

            for (auto& use_block : fn.blocks) {
                for (auto& instruction : use_block.insts) {
                    if (instruction.op == IrOp::Return) {
                        bool returns_cookie_clobber = false;
                        for (u8 source = 0; source < instruction.src_count; ++source) {
                            const auto key = ssa_key(instruction.srcs[source]);
                            returns_cookie_clobber |= key && *key == *clobber_key;
                        }
                        if (returns_cookie_clobber) {
                            if (preserved) {
                                instruction.srcs[0] = *preserved;
                                instruction.src_count = 1;
                            } else {
                                instruction.src_count = 0;
                            }
                            ++rewritten;
                            continue;
                        }
                    }
                    if (!preserved) continue;
                    for_each_use(instruction, [&](IrValue& use) {
                        const auto key = ssa_key(use);
                        if (key && *key == *clobber_key) {
                            use = *preserved;
                            ++rewritten;
                        }
                    });
                }
            }
            for (std::size_t scan = call_index; scan > 0;) {
                IrInst& previous = block.insts[--scan];
                if (previous.op == IrOp::Call ||
                    previous.op == IrOp::CallIndirect) break;
                if (previous.op == IrOp::Intrinsic &&
                    (previous.name.starts_with("call.args.") ||
                     previous.name.starts_with("call.fp_args."))) {
                    previous.op = IrOp::Nop;
                    previous.src_count = 0;
                    previous.name.clear();
                    ++rewritten;
                }
            }
            call.op = IrOp::Nop;
            call.src_count = 0;
            call.name.clear();
            ++rewritten;
        }
    }
    return rewritten;
}

}  // namespace spelunk::ir_passes
