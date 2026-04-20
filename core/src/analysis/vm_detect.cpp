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

constexpr std::size_t kMaxFunctionInsns = 512;
constexpr std::size_t kMaxTableEntries  = 1024;
constexpr std::size_t kMinHandlerCount  = 8;
// A reg-load → reg-use window. The dispatch is usually 1-3 insns after
// the movzx. Anything wider risks matching unrelated table jumps.
constexpr unsigned    kReuseWindow      = 6;

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

// Track the most-recent base-register loads that the dispatch site might
// use. We only care about `lea reg, [rip + disp]` (table-base materialize)
// and `movzx reg, byte ptr [...]` (opcode load) — these together cover
// virtually every Hyperion / VMProtect-class dispatch shape.
struct RegLoad {
    enum class Kind { None, ByteFromMem, LeaRipRel } kind = Kind::None;
    addr_t   at_addr  = 0;     // address of the loading instruction
    unsigned at_age   = 0;     // how many instructions ago, 1-based
    addr_t   lea_target = 0;   // for LeaRipRel: rip + lea_len + disp
};

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

        addr_t ip = sym.addr;
        for (std::size_t step = 0; step < kMaxFunctionInsns; ++step) {
            auto bytes = b.bytes_at(ip);
            if (bytes.empty()) break;
            auto decoded = dec.decode(bytes, ip);
            if (!decoded) break;
            const Instruction& insn = *decoded;
            ++age_counter;

            // Indirect jmp/call → potential dispatch site.
            const bool is_dispatch =
                (insn.mnemonic == Mnemonic::Jmp || insn.mnemonic == Mnemonic::Call)
                && insn.num_operands == 1
                && insn.operands[0].kind == Operand::Kind::Memory;
            if (is_dispatch && !seen_dispatch.contains(insn.address)) {
                const Mem& m = insn.operands[0].mem;
                if (m.scale == 8 && m.index != Reg::None && m.has_disp) {
                    const Reg idx_canon = canonical_reg(m.index);
                    const auto& idx_load =
                        reg_loads[static_cast<std::size_t>(idx_canon)];
                    const bool idx_recent_byte_load =
                        idx_load.kind == RegLoad::Kind::ByteFromMem &&
                        (age_counter - idx_load.at_age) <= kReuseWindow;
                    if (idx_recent_byte_load) {
                        // Resolve table base. Two shapes accepted:
                        //   [rip + disp + idx*8]  → table = ip + len + disp
                        //   [reg + disp + idx*8]  → table = lea_target(reg) + disp
                        // (a non-zero disp on the latter is rare but legal)
                        std::optional<addr_t> table_va;
                        if (m.base == Reg::Rip) {
                            table_va = ip + insn.length +
                                       static_cast<addr_t>(m.disp);
                        } else if (m.base != Reg::None) {
                            const auto& base_load =
                                reg_loads[static_cast<std::size_t>(canonical_reg(m.base))];
                            if (base_load.kind == RegLoad::Kind::LeaRipRel &&
                                (age_counter - base_load.at_age) <= kReuseWindow) {
                                table_va = base_load.lea_target +
                                           static_cast<addr_t>(m.disp);
                            }
                        }

                        if (table_va) {
                            std::vector<addr_t> handlers;
                            std::unordered_set<addr_t> seen_h;
                            for (std::size_t i = 0; i < kMaxTableEntries; ++i) {
                                auto v = read_u64_at(b, *table_va + i * 8);
                                if (!v) break;
                                if (!code.contains(static_cast<addr_t>(*v))) break;
                                if (seen_h.insert(static_cast<addr_t>(*v)).second) {
                                    handlers.push_back(static_cast<addr_t>(*v));
                                }
                            }
                            if (handlers.size() >= kMinHandlerCount) {
                                out.push_back({sym.addr, insn.address,
                                               *table_va, std::move(handlers)});
                                seen_dispatch.insert(insn.address);
                            }
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

                if (insn.mnemonic == Mnemonic::Movzx &&
                    insn.num_operands == 2 &&
                    insn.operands[1].kind == Operand::Kind::Memory &&
                    insn.operands[1].mem.size == 1) {
                    rec.kind    = RegLoad::Kind::ByteFromMem;
                    rec.at_addr = insn.address;
                    rec.at_age  = age_counter;
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

            // Stop walking past unconditional terminators — anything after
            // a `ret` / `jmp <imm>` / `ud2` is in another basic block (or
            // is data), and the rolling state from this block's prologue
            // doesn't apply to it.
            if (insn.mnemonic == Mnemonic::Ret ||
                insn.mnemonic == Mnemonic::Ud2 ||
                insn.mnemonic == Mnemonic::Hlt) break;
            // Don't break on a matched dispatch; some functions chain
            // multiple dispatchers (e.g. inner+outer interpreters).

            ip += insn.length;
        }
    }

    return out;
}

}  // namespace ember
