#include <ember/analysis/vm_detect.hpp>

#include <array>
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
