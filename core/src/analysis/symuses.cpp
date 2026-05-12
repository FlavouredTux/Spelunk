#include <ember/analysis/symuses.hpp>

#include <algorithm>
#include <map>
#include <unordered_map>
#include <unordered_set>

#include <ember/analysis/data_xrefs.hpp>
#include <ember/analysis/fn_table.hpp>
#include <ember/analysis/pipeline.hpp>
#include <ember/binary/arch.hpp>
#include <ember/binary/elf.hpp>
#include <ember/binary/section.hpp>
#include <ember/common/bytes.hpp>
#include <ember/disasm/instruction.hpp>
#include <ember/disasm/x64_decoder.hpp>

namespace ember::analysis {

namespace {

[[nodiscard]] bool is_stack_reg(Reg r) noexcept {
    return r == Reg::Rsp || r == Reg::Rbp;
}

// Map a Reg to a canonical 64-bit GP index 0..15 (rax..r15) - collapses
// 8/16/32-bit subregister forms to their parent. -1 for non-GP regs.
// Used by the taint walker to track 16 GPs as a u16 bitmask.
[[nodiscard]] int gp64_index(Reg r) noexcept {
    using R = Reg;
    switch (r) {
        case R::Rax: case R::Eax: case R::Ax: case R::Al: case R::Ah:   return 0;
        case R::Rcx: case R::Ecx: case R::Cx: case R::Cl: case R::Ch:   return 1;
        case R::Rdx: case R::Edx: case R::Dx: case R::Dl: case R::Dh:   return 2;
        case R::Rbx: case R::Ebx: case R::Bx: case R::Bl: case R::Bh:   return 3;
        case R::Rsp: case R::Esp: case R::Sp: case R::Spl:              return 4;
        case R::Rbp: case R::Ebp: case R::Bp: case R::Bpl:              return 5;
        case R::Rsi: case R::Esi: case R::Si: case R::Sil:              return 6;
        case R::Rdi: case R::Edi: case R::Di: case R::Dil:              return 7;
        case R::R8:  case R::R8d: case R::R8w: case R::R8b:             return 8;
        case R::R9:  case R::R9d: case R::R9w: case R::R9b:             return 9;
        case R::R10: case R::R10d: case R::R10w: case R::R10b:          return 10;
        case R::R11: case R::R11d: case R::R11w: case R::R11b:          return 11;
        case R::R12: case R::R12d: case R::R12w: case R::R12b:          return 12;
        case R::R13: case R::R13d: case R::R13w: case R::R13b:          return 13;
        case R::R14: case R::R14d: case R::R14w: case R::R14b:          return 14;
        case R::R15: case R::R15d: case R::R15w: case R::R15b:          return 15;
        default: return -1;
    }
}

// True when the register form spans the full 64- or 32-bit width
// (32-bit writes zero-extend the upper half, so they overwrite the
// taint just as a 64-bit write would). 8- and 16-bit writes preserve
// upper bits - taint survives.
[[nodiscard]] bool is_full_width(Reg r) noexcept {
    const auto v = static_cast<unsigned>(r);
    return (v >= static_cast<unsigned>(Reg::Eax) &&
            v <= static_cast<unsigned>(Reg::R15d)) ||
           (v >= static_cast<unsigned>(Reg::Rax) &&
            v <= static_cast<unsigned>(Reg::R15));
}

// True when the mnemonic doesn't touch GP register state in a way the
// taint walker cares about. Push reads its operand, doesn't write a
// GP register; cmp/test are pure compares; leave only touches rbp/rsp;
// nop / fence / etc. are no-ops. Used to skip taint propagation
// without untainting anything.
[[nodiscard]] bool is_taint_neutral(Mnemonic m) noexcept {
    switch (m) {
        case Mnemonic::Cmp:   case Mnemonic::Test:  case Mnemonic::Cmn:
        case Mnemonic::Push:
        case Mnemonic::Nop:   case Mnemonic::Hlt:
        case Mnemonic::Endbr32: case Mnemonic::Endbr64:
        case Mnemonic::Pause:
            return true;
        default:
            return false;
    }
}

[[nodiscard]] bool is_branch_or_ret(Mnemonic m) noexcept {
    switch (m) {
        case Mnemonic::Jmp:  case Mnemonic::Ret:
        case Mnemonic::Jo:   case Mnemonic::Jno: case Mnemonic::Jb:  case Mnemonic::Jae:
        case Mnemonic::Je:   case Mnemonic::Jne: case Mnemonic::Jbe: case Mnemonic::Ja:
        case Mnemonic::Js:   case Mnemonic::Jns: case Mnemonic::Jp:  case Mnemonic::Jnp:
        case Mnemonic::Jl:   case Mnemonic::Jge: case Mnemonic::Jle: case Mnemonic::Jg:
            return true;
        default:
            return false;
    }
}

// System V x86-64 caller-saved (scratch) GP regs, packed as a bitmask
// against gp64_index(). rax / rcx / rdx / rsi / rdi / r8..r11.
constexpr u16 kCallClobberMask =
    (1u<<0) | (1u<<1) | (1u<<2) | (1u<<6) | (1u<<7) |
    (1u<<8) | (1u<<9) | (1u<<10) | (1u<<11);

}  // namespace

Result<SymUses>
collect_symbol_uses(const Binary& b, addr_t table_va, SymUseOptions opts) {
    auto walk = walk_symtable(b, table_va);
    if (!walk) return std::unexpected(walk.error());

    SymUses out;
    out.walk = std::move(*walk);

    // offset → name. Includes the leading empty entry; an offset-0
    // hit is the table_base reference and surfaces walks_full_table.
    std::unordered_map<u64, std::string> offset_to_name;
    offset_to_name.reserve(out.walk.entries.size());
    for (const auto& e : out.walk.entries) {
        offset_to_name[e.offset] = e.text;
    }
    // Map entry VA → name too, for the existing direct-ref path.
    std::map<addr_t, std::string> by_va;
    for (const auto& e : out.walk.entries) {
        by_va[e.va] = e.text;
    }

    const auto    xrefs = compute_data_xrefs(b);
    const FnTable fns(b);

    std::map<addr_t, SymUseRow> rows_by_fn;
    auto touch_fn = [&](addr_t fn_entry, std::string fn_name) -> SymUseRow& {
        auto& row   = rows_by_fn[fn_entry];
        row.fn_addr = fn_entry;
        if (row.fn_name.empty()) row.fn_name = std::move(fn_name);
        return row;
    };

    // ---- Direct path: data_xrefs hits already keyed by entry VA ----
    // Catches the GCC/Clang shape `lea reg, [rip+entry_va]`. Sober's
    // base+offset shape produces no entries here - handled below.
    for (const auto& [target, bucket] : xrefs) {
        auto it = by_va.find(target);
        if (it == by_va.end()) continue;
        for (const auto& x : bucket) {
            const auto* fn = fns.containing(x.from_pc);
            if (!fn) continue;
            auto& row = touch_fn(fn->entry, fn->name);
            row.sites.push_back({x.from_pc, target, it->second});
            if (target == table_va) row.walks_full_table = true;
        }
    }

    // ---- Scope path: per-function instruction scan ----
    // Functions that have access to the table base - either by direct
    // rip-rel reference, or by reading a slot whose value is the base
    // (= the imm64-stored / R_*_RELATIVE shapes that --refs-to-loose
    // already surfaces). Sober's libloader stashes the base in a
    // struct field (`mov rax, [rsi+0x288]`) so the strict path returns
    // zero hits and we miss every consumer. Each scope fn is then
    // re-decoded looking for displacement / immediate operands whose
    // value is an exact entry offset within the table - the shape
    // obfuscated loaders use to compute entry VAs from a pre-loaded
    // base register. Weak filter (exact-offset match) only; false
    // positives are bounded by the rarity of random constants landing
    // exactly on a packed-table boundary.
    std::unordered_set<addr_t>          scope_fns;
    // Per-fn list of base-load callsite VAs (each instruction at which
    // the function obtained the base - directly or via a slot read).
    // Surfaced through SymUseRow::base_load_sites for diagnostics.
    std::unordered_map<addr_t, std::vector<addr_t>> base_loads_by_fn;

    auto admit_xref = [&](const DataXref& x) {
        if (x.kind != DataXrefKind::Read &&
            x.kind != DataXrefKind::Lea  &&
            x.kind != DataXrefKind::CodePtr) return;
        const auto* fn = fns.containing(x.from_pc);
        if (!fn) return;
        scope_fns.insert(fn->entry);
        base_loads_by_fn[fn->entry].push_back(x.from_pc);
    };

    // Direct refs to the table base.
    if (auto it = xrefs.find(table_va); it != xrefs.end()) {
        for (const auto& x : it->second) admit_xref(x);
    }

    // imm64-stored slots: scan every readable section for a qword
    // matching table_va; functions that read the slot RIP-relative
    // are scope candidates. Pointer-aligned only - without that guard
    // a single legitimate slot produces a cluster of byte-shifted
    // false positives at the same location.
    const bool        is_64       = arch_pointer_bits(b.arch()) == 64;
    const std::size_t needle_size = is_64 ? 8u : 4u;
    const u64         needle      = static_cast<u64>(table_va);
    std::vector<addr_t> imm64_slots;
    for (const auto& s : b.sections()) {
        if (!s.flags.readable) continue;
        if (s.data.empty())     continue;
        const std::byte*  p = s.data.data();
        const std::size_t n = s.data.size();
        if (n < needle_size) continue;
        const auto sec_base = static_cast<addr_t>(s.vaddr);
        const std::size_t first_aligned =
            (needle_size - (sec_base % needle_size)) % needle_size;
        for (std::size_t i = first_aligned; i + needle_size <= n;
             i += needle_size) {
            const u64 v = is_64
                ? read_le_at<u64>(p + i)
                : static_cast<u64>(read_le_at<u32>(p + i));
            if (v == needle) imm64_slots.push_back(sec_base + static_cast<addr_t>(i));
        }
    }
    out.scope_imm64_slots = imm64_slots.size();
    for (addr_t slot : imm64_slots) {
        if (auto it = xrefs.find(slot); it != xrefs.end()) {
            for (const auto& x : it->second) admit_xref(x);
        }
    }

    // Relocated slots (ELF only): the qword is zero on disk but the
    // dynamic linker writes table_va in at load time. The on-disk
    // scan above misses these - the relocation table knows the
    // post-load value.
    if (const auto* elf = dynamic_cast<const ElfBinary*>(&b)) {
        const auto reloc_map = elf->relocated_qwords();
        for (const auto& [slot, addend] : reloc_map) {
            if (addend != table_va) continue;
            ++out.scope_relocated_slots;
            if (auto it = xrefs.find(slot); it != xrefs.end()) {
                for (const auto& x : it->second) admit_xref(x);
            }
        }
    }
    out.scope_fn_count = scope_fns.size();

    if (b.arch() == Arch::X86_64 && !scope_fns.empty()) {
        X64Decoder dec;
        const u64 table_size = out.walk.table_size;

        for (addr_t fn_entry : scope_fns) {
            const auto* fn = fns.containing(fn_entry);
            if (!fn) continue;
            auto span = b.bytes_at(fn_entry);
            if (span.empty()) continue;
            const std::size_t limit = fn->end > fn_entry
                ? std::min<std::size_t>(span.size(), fn->end - fn_entry)
                : span.size();

            auto& row = touch_fn(fn_entry, fn->name);
            std::unordered_set<addr_t> base_load_set;
            if (auto bit = base_loads_by_fn.find(fn_entry);
                bit != base_loads_by_fn.end()) {
                auto& v = bit->second;
                std::ranges::sort(v);
                v.erase(std::unique(v.begin(), v.end()), v.end());
                row.base_load_sites = v;
                if (!v.empty()) row.walks_full_table = true;
                for (addr_t s : v) base_load_set.insert(s);
            }

            // Try to record a hit when `cand` falls on an exact entry
            // offset (and isn't the leading empty entry). Returns true
            // on a real hit so the caller can stop scanning further
            // operands of the same instruction.
            auto try_emit = [&](u64 cand, addr_t ip) -> bool {
                if (cand >= table_size) return false;
                auto eit = offset_to_name.find(cand);
                if (eit == offset_to_name.end()) return false;
                if (eit->second.empty()) {
                    row.walks_full_table = true;
                    return false;
                }
                row.sites.push_back({ip, table_va + cand, eit->second});
                return true;
            };

            // Lightweight register taint: bit i set ⇔ GP reg i (rax=0..r15=15)
            // currently holds the table base. Cleared at branches /
            // ret, scratch-clobbered at calls. The walker is local to
            // a basic-block worth of straight-line code.
            u16         taint = 0;
            addr_t      ip    = fn_entry;
            std::size_t off   = 0;

            while (off < limit) {
                auto rem = span.subspan(off, limit - off);
                auto decoded = dec.decode(rem, ip);
                if (!decoded) { ip += 1; off += 1; continue; }
                const auto& insn = *decoded;
                const u8    ilen = insn.length;
                if (ilen == 0) break;

                // Base load: dst reg becomes tainted. The instruction
                // itself isn't a source of any per-offset hit (offset
                // 0 = leading empty), so we don't fall through.
                if (base_load_set.contains(ip) &&
                    insn.num_operands >= 1 &&
                    insn.operands[0].kind == Operand::Kind::Register) {
                    const int dst = gp64_index(insn.operands[0].reg);
                    if (dst >= 0) taint |= static_cast<u16>(1u << dst);
                    row.walks_full_table = true;
                    ip += ilen; off += ilen;
                    continue;
                }

                if (is_branch_or_ret(insn.mnemonic)) {
                    taint = 0;
                    ip += ilen; off += ilen;
                    continue;
                }

                if (insn.mnemonic == Mnemonic::Call) {
                    taint &= static_cast<u16>(~kCallClobberMask);
                    ip += ilen; off += ilen;
                    continue;
                }

                if (is_taint_neutral(insn.mnemonic)) {
                    ip += ilen; off += ilen;
                    continue;
                }

                if (opts.no_taint) {
                    // Diagnostic mode: weak-filter only - emit any
                    // operand IMM / mem.disp matching an exact entry
                    // offset. Same shape as the pre-taint behaviour.
                    bool hit = false;
                    for (u8 j = 0; j < insn.num_operands && !hit; ++j) {
                        const Operand& op = insn.operands[j];
                        std::optional<u64> cand;
                        if (op.kind == Operand::Kind::Memory && op.mem.has_disp) {
                            if (op.mem.base == Reg::Rip) continue;
                            if (op.mem.base == Reg::None &&
                                op.mem.index == Reg::None) continue;
                            if (is_stack_reg(op.mem.base)) continue;
                            if (op.mem.disp < 0) continue;
                            cand = static_cast<u64>(op.mem.disp);
                        } else if (op.kind == Operand::Kind::Immediate) {
                            if (insn.num_operands >= 1 &&
                                insn.operands[0].kind == Operand::Kind::Register &&
                                is_stack_reg(insn.operands[0].reg)) continue;
                            if (op.imm.value < 0) continue;
                            cand = static_cast<u64>(op.imm.value);
                        } else {
                            continue;
                        }
                        if (!cand) continue;
                        hit = try_emit(*cand, ip);
                    }
                    ip += ilen; off += ilen;
                    continue;
                }

                // mov dst_reg, src_reg → propagate taint.
                if (insn.mnemonic == Mnemonic::Mov &&
                    insn.num_operands == 2 &&
                    insn.operands[0].kind == Operand::Kind::Register &&
                    insn.operands[1].kind == Operand::Kind::Register) {
                    const int dst = gp64_index(insn.operands[0].reg);
                    const int src = gp64_index(insn.operands[1].reg);
                    if (dst >= 0) {
                        const bool full = is_full_width(insn.operands[0].reg);
                        const bool src_tainted = src >= 0 &&
                            (taint & static_cast<u16>(1u << src)) != 0;
                        if (src_tainted) {
                            taint |= static_cast<u16>(1u << dst);
                        } else if (full) {
                            taint &= static_cast<u16>(~(1u << dst));
                        }
                    }
                    ip += ilen; off += ilen;
                    continue;
                }

                // add tainted_reg, IMM → emit IMM, keep taint.
                if (insn.mnemonic == Mnemonic::Add &&
                    insn.num_operands == 2 &&
                    insn.operands[0].kind == Operand::Kind::Register &&
                    insn.operands[1].kind == Operand::Kind::Immediate) {
                    const int dst = gp64_index(insn.operands[0].reg);
                    if (dst >= 0 && (taint & static_cast<u16>(1u << dst))) {
                        const i64 v = insn.operands[1].imm.value;
                        if (v >= 0) try_emit(static_cast<u64>(v), ip);
                    }
                    ip += ilen; off += ilen;
                    continue;
                }

                // lea dst, [tainted_base + disp] → emit disp; lea
                // always writes dst, so untaint dst (the result is a
                // pointer INTO the table, not the base).
                if (insn.mnemonic == Mnemonic::Lea &&
                    insn.num_operands == 2 &&
                    insn.operands[0].kind == Operand::Kind::Register &&
                    insn.operands[1].kind == Operand::Kind::Memory &&
                    insn.operands[1].mem.has_disp) {
                    const auto& m = insn.operands[1].mem;
                    if (m.base != Reg::Rip && m.index == Reg::None) {
                        const int base = gp64_index(m.base);
                        if (base >= 0 &&
                            (taint & static_cast<u16>(1u << base)) &&
                            m.disp >= 0) {
                            try_emit(static_cast<u64>(m.disp), ip);
                        }
                    }
                    const int dst = gp64_index(insn.operands[0].reg);
                    if (dst >= 0 && is_full_width(insn.operands[0].reg)) {
                        taint &= static_cast<u16>(~(1u << dst));
                    }
                    ip += ilen; off += ilen;
                    continue;
                }

                // Fallback: any other instruction whose operand 0 is
                // a full-width GP reg overwrites whatever was in it
                // (mov reg,mem / mov reg,imm / pop / xor reg,reg /
                // sub / and / or / shl / mul / etc.). Untaint dst.
                if (insn.num_operands >= 1 &&
                    insn.operands[0].kind == Operand::Kind::Register) {
                    const int dst = gp64_index(insn.operands[0].reg);
                    if (dst >= 0 && is_full_width(insn.operands[0].reg)) {
                        taint &= static_cast<u16>(~(1u << dst));
                    }
                }

                ip += ilen; off += ilen;
            }
        }
    }

    out.rows.reserve(rows_by_fn.size());
    for (auto& [_, row] : rows_by_fn) {
        std::ranges::sort(row.sites, [](const auto& l, const auto& r) noexcept {
            if (l.callsite != r.callsite) return l.callsite < r.callsite;
            return l.string_va < r.string_va;
        });
        // De-dupe identical (callsite, string_va) pairs - a single
        // instruction with two equivalent operand slots referencing
        // the same entry.
        row.sites.erase(std::unique(row.sites.begin(), row.sites.end(),
            [](const auto& l, const auto& r) noexcept {
                return l.callsite == r.callsite && l.string_va == r.string_va;
            }), row.sites.end());
        out.rows.push_back(std::move(row));
    }

    auto unique_count = [](const SymUseRow& row) {
        std::unordered_set<std::string_view> seen;
        for (const auto& s : row.sites) seen.insert(s.name);
        return seen.size();
    };
    std::ranges::sort(out.rows, [&](const auto& l, const auto& r) noexcept {
        const auto ul = unique_count(l);
        const auto ur = unique_count(r);
        if (ul != ur) return ul > ur;
        return l.fn_addr < r.fn_addr;
    });
    return out;
}

}  // namespace ember::analysis
