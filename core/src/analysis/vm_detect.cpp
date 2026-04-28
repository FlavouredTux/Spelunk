#include <ember/analysis/vm_detect.hpp>

#include <algorithm>
#include <array>
#include <map>
#include <optional>
#include <unordered_set>
#include <utility>

#include <ember/binary/binary.hpp>
#include <ember/binary/symbol.hpp>
#include <ember/common/bytes.hpp>
#include <ember/disasm/instruction.hpp>
#include <ember/disasm/x64_decoder.hpp>
#include <ember/ir/ssa.hpp>  // canonical_reg

namespace ember {

namespace {

// Higher than a typical function size — CFG-walking visits each
// address at most once, but obfuscated VMs may traverse hundreds of
// addresses across multiple basic blocks before hitting the dispatch.
constexpr std::size_t kMaxFunctionInsns = 2048;
constexpr std::size_t kMaxTableEntries  = 1024;
constexpr std::size_t kMinHandlerCount  = 8;
// A reg-load → reg-use window for the index, measured in *real* insns
// (junk-pads are skipped without bumping the counter). The dispatch
// is usually 1-3 insns after the movzx; obfuscators sprinkle non-nop
// noise to push that gap. 16 covers a comfortable amount without
// risking matches against unrelated table jumps elsewhere in a function.
constexpr unsigned    kReuseWindow      = 16;

struct CodeRanges {
    std::vector<std::pair<addr_t, addr_t>> spans;
    [[nodiscard]] bool contains(addr_t a) const noexcept {
        for (const auto& s : spans) if (a >= s.first && a < s.second) return true;
        return false;
    }
};

[[nodiscard]] CodeRanges collect_code_ranges(const Binary& b) {
    CodeRanges r;
    for (const auto& s : b.sections()) {
        if (!s.flags.executable) continue;
        if (s.size == 0) continue;
        r.spans.emplace_back(static_cast<addr_t>(s.vaddr),
                             static_cast<addr_t>(s.vaddr + s.size));
    }
    return r;
}

// Read a u64 from any-section bytes_at. Returns nullopt if the address
// has no backing bytes (e.g. inside a .bss tail).
[[nodiscard]] std::optional<u64>
read_u64_at(const Binary& b, addr_t va) {
    auto span = b.bytes_at(va);
    if (span.size() < 8) return std::nullopt;
    return read_le_at<u64>(span.data());
}

// Most-recent base-register load. ByteFromMem captures the full source
// memory operand so the dispatcher can later report which register
// holds the bytecode pointer (the opcode-load's base register) plus
// any displacement; LeaRipRel captures rip-relative `lea` for table
// base resolution. The ByteFromMem record absorbs the current state
// of its own base register at byte-load time so a far-back constant
// `lea pc, [rip+disp]` survives the trip to dispatch.
struct RegLoad {
    enum class Kind { None, ByteFromMem, LeaRipRel } kind = Kind::None;
    addr_t   at_addr        = 0;       // address of the loading instruction
    unsigned at_age         = 0;       // 1-based instruction count, junk-pads excluded
    addr_t   lea_target     = 0;       // for LeaRipRel: rip + lea_len + disp

    // ByteFromMem extras: source-memory operand + observed pc-advance.
    Reg      bm_dst_orig    = Reg::None;   // un-canonicalised destination (e.g. Eax for movzx eax)
    Reg      bm_base_reg    = Reg::None;   // stored canonical
    i32      bm_base_disp   = 0;
    u8       bm_op_bytes    = 1;       // 1 (byte ptr) or 2 (word ptr)
    addr_t   bm_pc_lea      = 0;       // bytecode VA when pc was set via lea rip-rel
    i32      bm_pc_advance  = 0;       // captured from a later add/inc of bm_base_reg
};

// Real obfuscators (Hyperion, Byfron, VMProtect) sprinkle junk insns
// between the opcode-load and the indirect dispatch to break naïve
// linear-window matchers. Recognise the most common shapes so the
// detector's rolling state survives them: a junk-padded sequence
// neither bumps `age_counter` nor touches the per-register records.
[[nodiscard]] bool is_semantic_nop(const Instruction& insn) noexcept {
    if (insn.mnemonic == Mnemonic::Nop) return true;

    // xchg reg, reg where both operands canonicalise to the same
    // register. Covers the `87 c0` (xchg eax, eax) and friends.
    if (insn.mnemonic == Mnemonic::Xchg && insn.num_operands == 2 &&
        insn.operands[0].kind == Operand::Kind::Register &&
        insn.operands[1].kind == Operand::Kind::Register &&
        canonical_reg(insn.operands[0].reg) ==
            canonical_reg(insn.operands[1].reg)) {
        return true;
    }

    // mov reg, reg with the same canonical register on both sides.
    // The full 64/32/16/8-bit width is irrelevant — the value is
    // unchanged either way (or zero-extended from itself, which
    // happens to be the identity).
    if (insn.mnemonic == Mnemonic::Mov && insn.num_operands == 2 &&
        insn.operands[0].kind == Operand::Kind::Register &&
        insn.operands[1].kind == Operand::Kind::Register &&
        canonical_reg(insn.operands[0].reg) ==
            canonical_reg(insn.operands[1].reg)) {
        return true;
    }

    // jmp imm where the relative target lands on the next instruction.
    // Pure jump-pad — common in Hyperion/Byfron control-flow flatteners.
    if (insn.mnemonic == Mnemonic::Jmp && insn.num_operands == 1 &&
        insn.operands[0].kind == Operand::Kind::Relative &&
        insn.operands[0].rel.target == insn.address + insn.length) {
        return true;
    }

    // lea reg, [reg] / [reg+0] — the no-op lea idiom, sometimes used as
    // a 7-byte "stretchable" nop.
    if (insn.mnemonic == Mnemonic::Lea && insn.num_operands == 2 &&
        insn.operands[0].kind == Operand::Kind::Register &&
        insn.operands[1].kind == Operand::Kind::Memory) {
        const Mem& m = insn.operands[1].mem;
        const bool zero_disp = !m.has_disp || m.disp == 0;
        if (m.base != Reg::None && m.index == Reg::None && zero_disp &&
            canonical_reg(m.base) ==
                canonical_reg(insn.operands[0].reg)) {
            return true;
        }
    }

    // Arithmetic identities: `add/sub/or/xor reg, 0` and `and reg, -1`
    // leave the destination unchanged (flag side effects don't concern
    // the dispatcher pattern). VMProtect-style obfuscators sprinkle
    // these to inflate the linear instruction count between the byte-
    // load and the dispatch.
    if (insn.num_operands == 2 &&
        insn.operands[0].kind == Operand::Kind::Register &&
        insn.operands[1].kind == Operand::Kind::Immediate) {
        const i64 v = insn.operands[1].imm.value;
        switch (insn.mnemonic) {
            case Mnemonic::Add:
            case Mnemonic::Sub:
            case Mnemonic::Or:
            case Mnemonic::Xor:
                if (v == 0) return true;
                break;
            case Mnemonic::And:
                if (v == -1 || static_cast<u64>(v) == ~u64{0}) return true;
                break;
            default:
                break;
        }
    }

    // Conditional branch whose target is the next instruction. The
    // jump goes nowhere either way — pure structural nop. Common
    // obfuscator pad (often paired with a preceding `cmp reg, reg` /
    // `test reg, reg` to fake a "real-looking" conditional).
    if (is_conditional_branch(insn.mnemonic) &&
        insn.num_operands == 1 &&
        insn.operands[0].kind == Operand::Kind::Relative &&
        insn.operands[0].rel.target == insn.address + insn.length) {
        return true;
    }

    // cmp / test of a register against itself — sets fixed flags
    // (cmp/test reg,reg with reg==reg always yields ZF=1, SF=0,
    // CF=0, OF=0) but doesn't write any register the dispatcher
    // walker tracks. The pair `cmp reg, reg; je $+next` is the
    // canonical "fake conditional" pad.
    if ((insn.mnemonic == Mnemonic::Cmp || insn.mnemonic == Mnemonic::Test) &&
        insn.num_operands == 2 &&
        insn.operands[0].kind == Operand::Kind::Register &&
        insn.operands[1].kind == Operand::Kind::Register &&
        canonical_reg(insn.operands[0].reg) ==
            canonical_reg(insn.operands[1].reg)) {
        return true;
    }

    return false;
}

// True if this instruction increments / decrements a single register
// by a constant amount, with no memory operand. Sets `out_reg` and
// `out_delta` on match.
[[nodiscard]] bool decode_const_reg_delta(const Instruction& insn,
                                           Reg& out_reg, i32& out_delta) noexcept {
    if (insn.mnemonic == Mnemonic::Inc &&
        insn.num_operands == 1 &&
        insn.operands[0].kind == Operand::Kind::Register) {
        out_reg   = canonical_reg(insn.operands[0].reg);
        out_delta = 1;
        return true;
    }
    if (insn.mnemonic == Mnemonic::Dec &&
        insn.num_operands == 1 &&
        insn.operands[0].kind == Operand::Kind::Register) {
        out_reg   = canonical_reg(insn.operands[0].reg);
        out_delta = -1;
        return true;
    }
    if ((insn.mnemonic == Mnemonic::Add || insn.mnemonic == Mnemonic::Sub) &&
        insn.num_operands == 2 &&
        insn.operands[0].kind == Operand::Kind::Register &&
        insn.operands[1].kind == Operand::Kind::Immediate) {
        out_reg   = canonical_reg(insn.operands[0].reg);
        out_delta = static_cast<i32>(insn.operands[1].imm.value);
        if (insn.mnemonic == Mnemonic::Sub) out_delta = -out_delta;
        return true;
    }
    return false;
}

}  // namespace

std::string_view handler_kind_name(HandlerKind k) noexcept {
    switch (k) {
        case HandlerKind::Unknown:    return "unknown";
        case HandlerKind::Null:       return "null";
        case HandlerKind::Arith:      return "arith";
        case HandlerKind::Load:       return "load";
        case HandlerKind::Store:      return "store";
        case HandlerKind::Branch:     return "branch";
        case HandlerKind::Call:       return "call";
        case HandlerKind::Return:     return "return";
        case HandlerKind::StackArith: return "stack-arith";
    }
    return "?";
}

namespace {

[[nodiscard]] bool is_arith_family(Mnemonic m) noexcept {
    switch (m) {
        case Mnemonic::Add: case Mnemonic::Sub:
        case Mnemonic::And: case Mnemonic::Or: case Mnemonic::Xor:
        case Mnemonic::Shl: case Mnemonic::Shr: case Mnemonic::Sar:
        case Mnemonic::Neg: case Mnemonic::Not:
        case Mnemonic::Inc: case Mnemonic::Dec:
        case Mnemonic::Mul: case Mnemonic::Div:
            return true;
        default:
            return false;
    }
}

[[nodiscard]] bool is_cmov(Mnemonic m) noexcept {
    switch (m) {
        case Mnemonic::Cmovo: case Mnemonic::Cmovno:
        case Mnemonic::Cmovb: case Mnemonic::Cmovae:
        case Mnemonic::Cmove: case Mnemonic::Cmovne:
        case Mnemonic::Cmovbe: case Mnemonic::Cmova:
        case Mnemonic::Cmovs: case Mnemonic::Cmovns:
        case Mnemonic::Cmovp: case Mnemonic::Cmovnp:
        case Mnemonic::Cmovl: case Mnemonic::Cmovge:
        case Mnemonic::Cmovle: case Mnemonic::Cmovg:
            return true;
        default:
            return false;
    }
}

}  // namespace

// Compact textual form of a memory operand for handler summaries.
// Resolves [rip+disp] to its absolute target so the user sees a
// concrete VA rather than a relative offset they have to add up.
[[nodiscard]] std::string format_mem_short(const Mem& m, addr_t rip_after) {
    std::string out;
    if (m.base == Reg::Rip && m.has_disp) {
        return std::format("[{:#x}]",
            rip_after + static_cast<addr_t>(m.disp));
    }
    out += '[';
    if (m.base != Reg::None) {
        out += reg_name(m.base);
    }
    if (m.index != Reg::None) {
        if (m.base != Reg::None) out += '+';
        out += reg_name(m.index);
        if (m.scale > 1) out += std::format("*{}", m.scale);
    }
    if (m.has_disp && m.disp != 0) {
        if (m.disp > 0) {
            out += std::format("+{:#x}", static_cast<u64>(m.disp));
        } else {
            out += std::format("-{:#x}",
                static_cast<u64>(-m.disp));
        }
    }
    out += ']';
    return out;
}

HandlerClassification
classify_vm_handler(const Binary& b, addr_t handler_entry,
                    addr_t dispatch_addr, Reg pc_register) {
    HandlerClassification out;
    out.entry    = handler_entry;
    out.body_end = handler_entry;

    const X64Decoder dec;

    bool has_ret = false, has_call = false, has_branch = false;
    bool has_store = false, has_load = false, has_arith = false;
    std::size_t body_insns = 0;

    // First-occurrence captures, by kind. Used to populate
    // HandlerClassification::summary at the end. We snapshot just
    // the bits we render so the captured data has no lifetime issues.
    Mnemonic    sig_arith_mn  = Mnemonic::Invalid;
    Operand     sig_arith_op1{};
    Operand     sig_arith_op2{};
    u8          sig_arith_argc = 0;
    Mnemonic    sig_branch_mn = Mnemonic::Invalid;
    Mem         sig_load_mem{};
    addr_t      sig_load_rip  = 0;       bool sig_has_load  = false;
    Mem         sig_store_mem{};
    addr_t      sig_store_rip = 0;       bool sig_has_store = false;
    addr_t      sig_call_tgt  = 0;       bool sig_call_imm  = false;
    const Reg   pc_canon = (pc_register == Reg::None)
                              ? Reg::None
                              : canonical_reg(pc_register);

    constexpr std::size_t kMaxBodyInsns = 64;
    addr_t ip = handler_entry;
    for (std::size_t step = 0; step < kMaxBodyInsns; ++step) {
        if (dispatch_addr != 0 && ip >= dispatch_addr) break;
        auto bytes = b.bytes_at(ip);
        if (bytes.empty()) break;
        auto decoded = dec.decode(bytes, ip);
        if (!decoded) break;
        const Instruction& insn = *decoded;

        // Skip the same junk-pads the dispatcher walker skips so a
        // handler whose only body is `nop / xchg rax, rax` reads as
        // Null instead of Arith.
        if (is_semantic_nop(insn)) {
            ip += insn.length;
            continue;
        }

        // Stack-arith handler: `pop r1; pop r2; <arith> r1, r2; push r1`.
        // The classic vm_stack_<arith> shape — operands materialised on
        // the host stack, computed in place, result re-pushed. Match
        // only on the first body insn so a real arith handler with a
        // stray pop in the middle doesn't misclassify.
        if (body_insns == 0 &&
            insn.mnemonic == Mnemonic::Pop &&
            insn.num_operands == 1 &&
            insn.operands[0].kind == Operand::Kind::Register) {
            auto decode_at = [&](addr_t a) -> std::optional<Instruction> {
                auto bs = b.bytes_at(a);
                if (bs.empty()) return std::nullopt;
                auto d = dec.decode(bs, a);
                if (!d) return std::nullopt;
                return *d;
            };
            const Reg r1 = canonical_reg(insn.operands[0].reg);
            addr_t scan_ip = ip + insn.length;
            auto pop2 = decode_at(scan_ip);
            if (pop2) scan_ip += pop2->length;
            auto arith = pop2 ? decode_at(scan_ip) : std::nullopt;
            if (arith) scan_ip += arith->length;
            auto push1 = arith ? decode_at(scan_ip) : std::nullopt;
            const bool shape_ok =
                pop2 && arith && push1 &&
                pop2->mnemonic == Mnemonic::Pop &&
                pop2->num_operands == 1 &&
                pop2->operands[0].kind == Operand::Kind::Register &&
                is_arith_family(arith->mnemonic) &&
                arith->num_operands == 2 &&
                arith->operands[0].kind == Operand::Kind::Register &&
                arith->operands[1].kind == Operand::Kind::Register &&
                push1->mnemonic == Mnemonic::Push &&
                push1->num_operands == 1 &&
                push1->operands[0].kind == Operand::Kind::Register;
            if (shape_ok) {
                const Reg r2 = canonical_reg(pop2->operands[0].reg);
                const Reg ad = canonical_reg(arith->operands[0].reg);
                const Reg as = canonical_reg(arith->operands[1].reg);
                const Reg pr = canonical_reg(push1->operands[0].reg);
                if (r1 != r2 && ad == r1 && as == r2 && pr == r1) {
                    out.kind     = HandlerKind::StackArith;
                    out.summary  = std::string(mnemonic_name(arith->mnemonic));
                    out.body_end = push1->address + push1->length;
                    out.insn_count = 4;
                    return out;
                }
            }
        }

        // Trailing-dispatch peek: a byte/word-load (movzx) followed
        // within 3 insns by an indirect jmp is the start of a
        // dispatcher's tail (movzx → inc pc → jmp [t+i*8]). Don't
        // count the load + advance + jmp toward the body; classify
        // the actual handler work that ran before them.
        if (insn.mnemonic == Mnemonic::Movzx &&
            insn.num_operands == 2 &&
            insn.operands[0].kind == Operand::Kind::Register &&
            insn.operands[1].kind == Operand::Kind::Memory &&
            (insn.operands[1].mem.size == 1 ||
             insn.operands[1].mem.size == 2)) {
            addr_t scan_ip = ip + insn.length;
            bool   tail    = false;
            for (int k = 0; k < 3; ++k) {
                auto bs = b.bytes_at(scan_ip);
                if (bs.empty()) break;
                auto d = dec.decode(bs, scan_ip);
                if (!d) break;
                if (d->mnemonic == Mnemonic::Jmp &&
                    d->num_operands == 1 &&
                    d->operands[0].kind == Operand::Kind::Memory) {
                    tail = true;
                    break;
                }
                scan_ip += d->length;
            }
            if (tail) {
                out.body_end = ip;
                break;
            }
        }

        if (is_return_like(insn.mnemonic)) {
            has_ret = true;
            out.body_end = ip + insn.length;
            ++body_insns;
            break;
        }

        // Indirect jmp = trailing dispatch (or escape); stop without
        // counting it as part of the body. If the caller passed a
        // dispatch_addr we wouldn't reach this — the ip>= guard above
        // takes us out cleanly.
        if (insn.mnemonic == Mnemonic::Jmp &&
            insn.num_operands == 1 &&
            insn.operands[0].kind == Operand::Kind::Memory) {
            out.body_end = ip;
            break;
        }

        // Direct call imm — classify and stop (caller-save regs are
        // gone past this point so the rest of the body wouldn't be
        // representative anyway).
        if (insn.mnemonic == Mnemonic::Call) {
            has_call = true;
            if (insn.num_operands == 1 &&
                insn.operands[0].kind == Operand::Kind::Relative) {
                sig_call_tgt = insn.operands[0].rel.target;
                sig_call_imm = true;
            }
            out.body_end = ip + insn.length;
            ++body_insns;
            break;
        }

        // Direct unconditional jmp imm: follow to target if in bounds.
        if (insn.mnemonic == Mnemonic::Jmp &&
            insn.num_operands == 1 &&
            insn.operands[0].kind == Operand::Kind::Relative) {
            const addr_t tgt = insn.operands[0].rel.target;
            // Treat "jmp out of the body" as the body's end.
            if (dispatch_addr != 0 && tgt >= dispatch_addr) {
                out.body_end = ip + insn.length;
                break;
            }
            ip = tgt;
            continue;
        }

        if (is_conditional_branch(insn.mnemonic) || is_cmov(insn.mnemonic)) {
            has_branch = true;
            if (sig_branch_mn == Mnemonic::Invalid) sig_branch_mn = insn.mnemonic;
        } else if (insn.mnemonic == Mnemonic::Mov &&
                   insn.num_operands == 2) {
            const auto& dst = insn.operands[0];
            const auto& src = insn.operands[1];
            if (dst.kind == Operand::Kind::Memory) {
                has_store = true;
                if (!sig_has_store) {
                    sig_store_mem = dst.mem;
                    sig_store_rip = ip + insn.length;
                    sig_has_store = true;
                }
            } else if (dst.kind == Operand::Kind::Register &&
                       src.kind == Operand::Kind::Memory) {
                has_load = true;
                if (!sig_has_load) {
                    sig_load_mem = src.mem;
                    sig_load_rip = ip + insn.length;
                    sig_has_load = true;
                }
            }
        } else if (insn.mnemonic == Mnemonic::Movzx ||
                   insn.mnemonic == Mnemonic::Movsx ||
                   insn.mnemonic == Mnemonic::Movsxd) {
            // The byte-load that feeds a dispatch counts as Load if
            // we don't have a dispatch_addr to filter it out — for
            // central VMs (no trailing dispatch), this is correct.
            if (insn.num_operands == 2 &&
                insn.operands[1].kind == Operand::Kind::Memory) {
                has_load = true;
                if (!sig_has_load) {
                    sig_load_mem = insn.operands[1].mem;
                    sig_load_rip = ip + insn.length;
                    sig_has_load = true;
                }
            }
        } else if (is_arith_family(insn.mnemonic)) {
            has_arith = true;
            if (sig_arith_mn == Mnemonic::Invalid) {
                sig_arith_mn   = insn.mnemonic;
                sig_arith_argc = insn.num_operands;
                if (insn.num_operands >= 1) sig_arith_op1 = insn.operands[0];
                if (insn.num_operands >= 2) sig_arith_op2 = insn.operands[1];
            }
        }

        ++body_insns;
        out.body_end = ip + insn.length;
        ip += insn.length;
    }

    out.insn_count = body_insns;
    // Precedence: a handler that ends with ret is conventionally "the
    // vm_ret opcode" — but only when nothing else identifies it. Body
    // work classifications win over Return so that `add rax, rcx; ret`
    // reads as Arith (the meaningful op) rather than Return (the
    // function termination).
    if      (has_branch) out.kind = HandlerKind::Branch;
    else if (has_call)   out.kind = HandlerKind::Call;
    else if (has_store)  out.kind = HandlerKind::Store;
    else if (has_load)   out.kind = HandlerKind::Load;
    else if (has_arith)  out.kind = HandlerKind::Arith;
    else if (has_ret)    out.kind = HandlerKind::Return;
    else                 out.kind = HandlerKind::Null;

    // If a Load/Store memory operand's base matches the VM's
    // pc_register, the access is reading an inline operand from the
    // bytecode stream — semantic signal stronger than the structural
    // "[rdi]" the formatter would print.
    auto is_pc_relative = [&](const Mem& m) {
        return pc_canon != Reg::None && m.base != Reg::None &&
               canonical_reg(m.base) == pc_canon &&
               m.index == Reg::None;
    };
    auto pc_operand_summary = [](const Mem& m) {
        if (!m.has_disp || m.disp == 0) return std::string("operand");
        if (m.disp > 0) {
            return std::format("operand+{:#x}", static_cast<u64>(m.disp));
        }
        return std::format("operand-{:#x}", static_cast<u64>(-m.disp));
    };

    // Per-kind summary detail — populated only for the kind we picked.
    switch (out.kind) {
        case HandlerKind::Arith: {
            if (sig_arith_mn == Mnemonic::Invalid) break;
            std::string mn{mnemonic_name(sig_arith_mn)};
            // xor reg, reg with both operands canonicalising to the
            // same register is the "clear/zero" idiom — render it as
            // such instead of the literal "xor rax".
            if (sig_arith_mn == Mnemonic::Xor && sig_arith_argc == 2 &&
                sig_arith_op1.kind == Operand::Kind::Register &&
                sig_arith_op2.kind == Operand::Kind::Register &&
                canonical_reg(sig_arith_op1.reg) ==
                    canonical_reg(sig_arith_op2.reg)) {
                out.summary = "clear";
                break;
            }
            if (sig_arith_argc == 2) {
                if (sig_arith_op2.kind == Operand::Kind::Immediate) {
                    out.summary = std::format("{} {:#x}", mn,
                        static_cast<u64>(sig_arith_op2.imm.value));
                } else if (sig_arith_op2.kind == Operand::Kind::Register) {
                    out.summary = std::format("{} {}", mn,
                        reg_name(sig_arith_op2.reg));
                } else {
                    out.summary = std::move(mn);
                }
            } else {
                out.summary = std::move(mn);
            }
            break;
        }
        case HandlerKind::Load:
            if (sig_has_load) {
                out.summary = is_pc_relative(sig_load_mem)
                    ? pc_operand_summary(sig_load_mem)
                    : format_mem_short(sig_load_mem, sig_load_rip);
            }
            break;
        case HandlerKind::Store:
            if (sig_has_store) {
                out.summary = is_pc_relative(sig_store_mem)
                    ? pc_operand_summary(sig_store_mem)
                    : format_mem_short(sig_store_mem, sig_store_rip);
            }
            break;
        case HandlerKind::Branch:
            if (sig_branch_mn != Mnemonic::Invalid) {
                out.summary = std::string(mnemonic_name(sig_branch_mn));
            }
            break;
        case HandlerKind::Call:
            if (sig_call_imm) {
                out.summary = std::format("{:#x}", sig_call_tgt);
            }
            break;
        default:
            break;
    }
    return out;
}

std::vector<VmInstance>
group_vm_dispatchers(const std::vector<VmDispatcher>& dispatchers) {
    // Cluster by handler-table base — every dispatcher feeding the
    // same table is the same VM (modulo the central-vs-threaded
    // distinction we apply per-site below).
    std::map<addr_t, VmInstance> by_table;
    for (const auto& d : dispatchers) {
        auto [it, inserted] = by_table.try_emplace(d.table_addr);
        VmInstance& vm = it->second;
        if (inserted) {
            vm.table_addr        = d.table_addr;
            vm.table_entries     = d.table_entries;
            vm.handlers          = d.handlers;
            vm.opcode_index_reg  = d.opcode_index_reg;
            vm.opcode_size_bytes = d.opcode_size_bytes;
            vm.pc_register       = d.pc_register;
            vm.pc_disp           = d.pc_disp;
            vm.pc_advance        = d.pc_advance;
            vm.bytecode_addr     = d.bytecode_addr;
        }
        const bool is_handler =
            std::find(vm.handlers.begin(), vm.handlers.end(),
                      d.function_addr) != vm.handlers.end();
        if (is_handler) {
            vm.threaded_sites.push_back(d);
        } else {
            vm.entry_sites.push_back(d);
        }
    }

    std::vector<VmInstance> out;
    out.reserve(by_table.size());
    for (auto& [_, vm] : by_table) out.push_back(std::move(vm));
    return out;
}

std::vector<VmInstance> analyze_vms(const Binary& b) {
    auto dispatchers = detect_vm_dispatchers(b);
    auto vms = group_vm_dispatchers(dispatchers);

    // Map handler_addr → trailing dispatch_addr for threaded handlers.
    std::map<addr_t, addr_t> threaded_dispatch_at;
    for (const auto& d : dispatchers) {
        threaded_dispatch_at.emplace(d.function_addr, d.dispatch_addr);
    }

    for (auto& vm : vms) {
        vm.handler_classes.reserve(vm.handlers.size());
        for (addr_t h : vm.handlers) {
            addr_t dispatch_at = 0;
            if (auto it = threaded_dispatch_at.find(h);
                it != threaded_dispatch_at.end()) {
                dispatch_at = it->second;
            }
            vm.handler_classes.push_back(
                classify_vm_handler(b, h, dispatch_at, vm.pc_register));
        }
    }
    return vms;
}

std::vector<VmDispatcher> detect_vm_dispatchers(const Binary& b) {
    std::vector<VmDispatcher> out;
    if (b.arch() != Arch::X86_64) return out;

    const X64Decoder dec;
    const auto code = collect_code_ranges(b);
    if (code.spans.empty()) return out;

    // Track which dispatch sites we've already recorded so two paths into
    // the same dispatcher don't show up twice (some jump tables are
    // referenced from both a fallback handler and a re-entry).
    std::unordered_set<addr_t> seen_dispatch;

    for (const auto& sym : b.symbols()) {
        if (sym.is_import) continue;
        if (sym.kind != SymbolKind::Function) continue;
        if (sym.addr == 0) continue;

        // Per-function rolling state: most-recent load on each canonical
        // register. Only writes invalidate; reads are passive.
        std::array<RegLoad, static_cast<std::size_t>(Reg::Count)> reg_loads{};
        unsigned age_counter = 0;

        // CFG-shaped walk: follow direct `jmp imm` to in-code targets so
        // dispatchers split across blocks (movzx in block A, jmp [t+i*8]
        // in block B reached via an unconditional jmp) still match.
        // `visited` keeps a back-jump from looping forever; the rolling
        // register state is carried across the follow without merging,
        // which is fine since the dispatcher pattern lives in a linear
        // chain of blocks even when obfuscators split it.
        std::unordered_set<addr_t> visited;
        addr_t ip = sym.addr;
        for (std::size_t step = 0; step < kMaxFunctionInsns; ++step) {
            if (!visited.insert(ip).second) break;
            auto bytes = b.bytes_at(ip);
            if (bytes.empty()) break;
            auto decoded = dec.decode(bytes, ip);
            if (!decoded) break;
            const Instruction& insn = *decoded;
            // Junk-pad: skip without touching rolling state or the age
            // counter. The byte-load → dispatch window is measured in
            // *real* insns, so an obfuscator stuffing nops/xchg/jmp+1
            // between the load and the jmp doesn't blow the kReuseWindow
            // check.
            if (is_semantic_nop(insn)) {
                ip += insn.length;
                continue;
            }
            // Two-insn semantic-nop: `push reg; pop reg` saves and
            // restores `reg` (modulo flags / rsp side effects). Single-
            // insn is_semantic_nop can't catch this; lookahead one
            // instruction and skip the pair.
            if (insn.mnemonic == Mnemonic::Push &&
                insn.num_operands == 1 &&
                insn.operands[0].kind == Operand::Kind::Register) {
                auto next_bytes = b.bytes_at(ip + insn.length);
                if (!next_bytes.empty()) {
                    auto next_decoded = dec.decode(next_bytes,
                                                    ip + insn.length);
                    if (next_decoded &&
                        next_decoded->mnemonic == Mnemonic::Pop &&
                        next_decoded->num_operands == 1 &&
                        next_decoded->operands[0].kind ==
                            Operand::Kind::Register &&
                        canonical_reg(next_decoded->operands[0].reg) ==
                            canonical_reg(insn.operands[0].reg)) {
                        ip += insn.length +
                              static_cast<addr_t>(next_decoded->length);
                        continue;
                    }
                }
            }
            // VMProtect-style RIP capture: `call $+5; pop reg`.
            // The call pushes the address of the pop (= rip after the
            // call); the pop materialises it into reg. Equivalent to
            // `lea reg, [rip+0]` but without using lea, designed to
            // defeat naive lea-only walkers. Skip the pair and prime
            // a LeaRipRel record on the destination register so the
            // table-base resolution path can still find the dispatch.
            if (insn.mnemonic == Mnemonic::Call &&
                insn.num_operands == 1 &&
                insn.operands[0].kind == Operand::Kind::Relative &&
                insn.operands[0].rel.target ==
                    insn.address + insn.length) {
                auto next_bytes = b.bytes_at(ip + insn.length);
                if (!next_bytes.empty()) {
                    auto next_decoded = dec.decode(next_bytes,
                                                    ip + insn.length);
                    if (next_decoded &&
                        next_decoded->mnemonic == Mnemonic::Pop &&
                        next_decoded->num_operands == 1 &&
                        next_decoded->operands[0].kind ==
                            Operand::Kind::Register) {
                        const Reg dst = canonical_reg(
                            next_decoded->operands[0].reg);
                        RegLoad& rec = reg_loads[
                            static_cast<std::size_t>(dst)];
                        rec = {};
                        rec.kind       = RegLoad::Kind::LeaRipRel;
                        rec.at_addr    = insn.address;
                        rec.at_age     = age_counter + 1;
                        // The popped value is the return address the
                        // call pushed = ip + call.length = address of
                        // the pop instruction itself.
                        rec.lea_target = ip + insn.length;
                        ip += insn.length +
                              static_cast<addr_t>(next_decoded->length);
                        ++age_counter;
                        continue;
                    }
                }
            }
            ++age_counter;

            // Indirect jmp/call → potential dispatch site.
            const bool is_dispatch =
                (insn.mnemonic == Mnemonic::Jmp || insn.mnemonic == Mnemonic::Call)
                && insn.num_operands == 1
                && insn.operands[0].kind == Operand::Kind::Memory;
            if (is_dispatch && !seen_dispatch.contains(insn.address)) {
                const Mem& m = insn.operands[0].mem;
                // Two shapes:
                //   [rip + disp + idx*8]  — `disp` is the table VA delta
                //                           (always present for rip-relative)
                //   [reg + idx*8]         — `reg` was set by an earlier
                //                           rip-relative `lea`; `disp` is
                //                           commonly zero so we don't gate
                //                           on its presence
                const bool rip_form =
                    m.base == Reg::Rip && m.has_disp &&
                    m.scale == 8 && m.index != Reg::None;
                const bool reg_form =
                    m.base != Reg::None && m.base != Reg::Rip &&
                    m.scale == 8 && m.index != Reg::None;
                if (rip_form || reg_form) {
                    const Reg idx_canon = canonical_reg(m.index);
                    const auto& idx_load =
                        reg_loads[static_cast<std::size_t>(idx_canon)];
                    const bool idx_recent_byte_load =
                        idx_load.kind == RegLoad::Kind::ByteFromMem &&
                        (age_counter - idx_load.at_age) <= kReuseWindow;
                    if (idx_recent_byte_load) {
                        std::optional<addr_t> table_va;
                        if (rip_form) {
                            table_va = ip + insn.length +
                                       static_cast<addr_t>(m.disp);
                        } else {
                            const auto& base_load =
                                reg_loads[static_cast<std::size_t>(canonical_reg(m.base))];
                            if (base_load.kind == RegLoad::Kind::LeaRipRel &&
                                (age_counter - base_load.at_age) <= kReuseWindow) {
                                table_va = base_load.lea_target +
                                           (m.has_disp ? static_cast<addr_t>(m.disp) : 0);
                            }
                        }

                        if (table_va) {
                            std::vector<addr_t> handlers;
                            std::unordered_set<addr_t> seen_h;
                            std::size_t walked = 0;
                            for (std::size_t i = 0; i < kMaxTableEntries; ++i) {
                                auto v = read_u64_at(b, *table_va + i * 8);
                                if (!v) break;
                                if (!code.contains(static_cast<addr_t>(*v))) break;
                                ++walked;
                                if (seen_h.insert(static_cast<addr_t>(*v)).second) {
                                    handlers.push_back(static_cast<addr_t>(*v));
                                }
                            }
                            if (handlers.size() >= kMinHandlerCount) {
                                VmDispatcher dsp;
                                dsp.function_addr     = sym.addr;
                                dsp.dispatch_addr     = insn.address;
                                dsp.opcode_load_addr  = idx_load.at_addr;
                                dsp.table_addr        = *table_va;
                                dsp.table_entries     = walked;
                                dsp.handlers          = std::move(handlers);
                                // Use the un-canonicalised destination
                                // so the report shows the encoded width
                                // (e.g. `eax` for `movzx eax, byte ptr`)
                                // rather than the canonical 64-bit form.
                                dsp.opcode_index_reg  = idx_load.bm_dst_orig;
                                dsp.opcode_size_bytes = idx_load.bm_op_bytes;
                                dsp.pc_register       = idx_load.bm_base_reg;
                                dsp.pc_disp           = idx_load.bm_base_disp;
                                dsp.pc_advance        = idx_load.bm_pc_advance;
                                dsp.bytecode_addr     = idx_load.bm_pc_lea;
                                out.push_back(std::move(dsp));
                                seen_dispatch.insert(insn.address);
                            }
                        }
                    }
                }
            }

            // Capture pc-advance: an inc/add/sub of any register that
            // matches a still-active byte-load's base register. Must
            // run BEFORE the rolling-state update below — that step
            // clears the destination register's record, but crucially
            // leaves the byte-load's index-register record alone; we
            // update bm_pc_advance there in place.
            {
                Reg delta_reg = Reg::None;
                i32 delta     = 0;
                if (decode_const_reg_delta(insn, delta_reg, delta)) {
                    for (auto& rl : reg_loads) {
                        if (rl.kind == RegLoad::Kind::ByteFromMem &&
                            rl.bm_base_reg == delta_reg &&
                            rl.bm_pc_advance == 0) {
                            rl.bm_pc_advance = delta;
                        }
                    }
                }
            }

            // Update the rolling state from this instruction's first
            // operand (the destination). Mov / Movzx / Lea / arith all
            // write op[0]; we only model the two shapes the dispatcher
            // pattern depends on.
            if (insn.num_operands >= 1 &&
                insn.operands[0].kind == Operand::Kind::Register) {
                const Reg dst_canon = canonical_reg(insn.operands[0].reg);
                RegLoad& rec = reg_loads[static_cast<std::size_t>(dst_canon)];
                rec = {};   // clear by default — any write invalidates

                const bool is_byte_word_load =
                    insn.mnemonic == Mnemonic::Movzx &&
                    insn.num_operands == 2 &&
                    insn.operands[1].kind == Operand::Kind::Memory &&
                    (insn.operands[1].mem.size == 1 ||
                     insn.operands[1].mem.size == 2);
                if (is_byte_word_load) {
                    const Mem& sm = insn.operands[1].mem;
                    rec.kind         = RegLoad::Kind::ByteFromMem;
                    rec.at_addr      = insn.address;
                    rec.at_age       = age_counter;
                    rec.bm_dst_orig  = insn.operands[0].reg;
                    rec.bm_base_reg  = canonical_reg(sm.base);
                    rec.bm_base_disp = sm.has_disp ? static_cast<i32>(sm.disp) : 0;
                    rec.bm_op_bytes  = static_cast<u8>(sm.size);
                    // Snapshot the current state of the base register —
                    // if the PC was set by a constant `lea pc, [rip+disp]`
                    // ahead of the loop, that's the bytecode VA. The
                    // record persists until the base reg is rewritten,
                    // so an arbitrarily early lea is still recoverable.
                    if (sm.base != Reg::None) {
                        const auto& base_rec = reg_loads[
                            static_cast<std::size_t>(canonical_reg(sm.base))];
                        if (base_rec.kind == RegLoad::Kind::LeaRipRel) {
                            rec.bm_pc_lea = base_rec.lea_target;
                        }
                    }
                } else if (insn.mnemonic == Mnemonic::Lea &&
                           insn.num_operands == 2 &&
                           insn.operands[1].kind == Operand::Kind::Memory &&
                           insn.operands[1].mem.base == Reg::Rip &&
                           insn.operands[1].mem.has_disp) {
                    rec.kind       = RegLoad::Kind::LeaRipRel;
                    rec.at_addr    = insn.address;
                    rec.at_age     = age_counter;
                    rec.lea_target = insn.address + insn.length +
                                     static_cast<addr_t>(insn.operands[1].mem.disp);
                }
            }

            // Hard terminators — nothing past these belongs to the
            // current execution path. int3 covers both deliberate
            // breakpoints and the 0xCC inter-function padding MSVC /
            // gcc / clang emit; without it the linear walk from one
            // function's last insn would tumble into the next function
            // and mis-attribute its dispatcher.
            if (insn.mnemonic == Mnemonic::Ret ||
                insn.mnemonic == Mnemonic::Ud2 ||
                insn.mnemonic == Mnemonic::Hlt ||
                insn.mnemonic == Mnemonic::Int3 ||
                insn.mnemonic == Mnemonic::Int) break;

            // Any call (direct or indirect) invalidates rolling state
            // via Win64 / SysV caller-save semantics — rax / rcx / rdx
            // / r8..r11 are all volatile, which is exactly the
            // dispatcher's working set. Indirect calls were already
            // checked for dispatch shape above; nothing more to do.
            if (insn.mnemonic == Mnemonic::Call) break;

            // Indirect jmp = control transfer with no fallthrough.
            // Already checked for dispatch shape; if the bytes that
            // follow happen to start a new function, that function's
            // own scan will pick them up with the correct attribution.
            if (insn.mnemonic == Mnemonic::Jmp &&
                insn.num_operands == 1 &&
                insn.operands[0].kind == Operand::Kind::Memory) break;

            // Direct unconditional `jmp imm`: follow the target if it
            // resolves into a code section. The previous linear sweep
            // walked past the jmp into whatever bytes followed (often
            // padding / data / another function entirely), which broke
            // detection on any dispatcher whose byte-load and jmp-table
            // straddled a `jmp imm`. Conditional jmps stay non-followed
            // — the path divergence isn't worth the rolling-state-merge
            // complexity for a ~98%-shaped pattern.
            if (insn.mnemonic == Mnemonic::Jmp &&
                insn.num_operands == 1 &&
                insn.operands[0].kind == Operand::Kind::Relative) {
                const addr_t tgt = insn.operands[0].rel.target;
                if (!code.contains(tgt)) break;
                ip = tgt;
                continue;
            }

            ip += insn.length;
        }
    }

    return out;
}

}  // namespace ember
