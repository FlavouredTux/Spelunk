#include <spelunk/analysis/cfg_builder.hpp>

#include <algorithm>
#include <expected>
#include <format>
#include <string>
#include <unordered_set>
#include <utility>

#include <spelunk/analysis/eh_frame.hpp>
#include <spelunk/analysis/pe_unwind.hpp>
#include <spelunk/analysis/pipeline.hpp>
#include <spelunk/binary/symbol.hpp>
#include <spelunk/common/error.hpp>

#include "cfg_builder_internal.hpp"

namespace spelunk {

void CfgBuilder::ensure_unwind_ranges_() const {
    if (unwind_ranges_init_) return;
    unwind_ranges_init_ = true;

    auto note = [&](addr_t begin, u64 len) {
        if (len == 0) return;
        auto [it, inserted] = unwind_ranges_.try_emplace(begin, len);
        if (!inserted && len > it->second) it->second = len;
    };
    for (const auto& e : enumerate_fde_extents(binary_)) {
        note(e.pc_begin, e.pc_range);
    }
    for (const auto& e : enumerate_compact_unwind_extents(binary_)) {
        note(e.pc_begin, e.pc_range);
    }
    for (const auto& e : parse_pe_pdata(binary_)) {
        if (e.end > e.begin) note(e.begin, e.end - e.begin);
    }
}

void CfgBuilder::ensure_known_entries_() const {
    if (known_entries_init_) return;
    known_entries_init_ = true;
    for (const auto& s : binary_.symbols()) {
        if (s.is_import) continue;
        if (s.kind != SymbolKind::Function) continue;
        if (s.addr == 0) continue;
        known_entries_.insert(s.addr);
    }
    // Discovered functions on stripped binaries - without these every
    // tail-call jmp on a stripped target looks like an intra-function
    // branch, and the caller side of `--refs-to <fn>` comes back empty
    // for tail-call-only callers (very common Lua / VM dispatch shape).
    // Cheap mode skips the recursive call-graph compute.
    for (const auto& fn : enumerate_functions(binary_, EnumerateMode::Cheap)) {
        known_entries_.insert(fn.addr);
    }
}

void CfgBuilder::seed_known_entries(std::unordered_set<addr_t> entries) const {
    known_entries_ = std::move(entries);
    known_entries_init_ = true;
}

bool CfgBuilder::is_function_entry(addr_t target) const noexcept {
    ensure_known_entries_();
    if (known_entries_.contains(target)) return true;
    return binary_.import_at_plt(target) != nullptr;
}

Result<Function>
CfgBuilder::build(addr_t entry, std::string name) const {
    if (binary_.bytes_at(entry).empty()) {
        return std::unexpected(Error::out_of_bounds(std::format(
            "cfg: no mapped bytes at entry {:#x}", entry)));
    }

    ensure_known_entries_();

    // A sized symbol is authoritative about ownership of its interior range.
    // Prologue/call-target discovery can still propose an address inside that
    // range (shared epilogues are especially branch-heavy), but treating that
    // interior label as a function entry turns every branch to it into a fake
    // tail call. Keep genuine entries outside the owner while allowing all
    // of its internal blocks to participate in this CFG.
    addr_t owned_end = entry;
    for (const Symbol& symbol : binary_.symbols()) {
        if (symbol.is_import || symbol.kind != SymbolKind::Function ||
            symbol.addr != entry || symbol.size == 0) {
            continue;
        }
        owned_end = std::max(owned_end, symbol.addr + symbol.size);
    }
    cfg_builder_detail::WalkState ws;
    cfg_builder_detail::walk_from(
        binary_, decoder_, ws, entry, known_entries_, entry, owned_end);

    if (ws.insns.empty()) {
        return std::unexpected(Error::invalid_format(std::format(
            "cfg: failed to decode any instructions at {:#x}", entry)));
    }

    // Iteratively discover jump-table switches: each indirect jmp may reveal
    // case-target blocks that need walking, and those blocks can themselves
    // contain more switches. Bounded to avoid pathological runaway.
    for (int iter = 0; iter < 8; ++iter) {
        bool added_work = false;
        for (const auto& [ip, insn] : ws.insns) {
            if (insn.mnemonic != Mnemonic::Jmp) continue;
            if (ws.tables.contains(ip)) continue;
            if (insn.num_operands != 1) continue;
            const auto& op = insn.operands[0];
            // Only consider "indirect" forms - register or rip-based memory.
            if (op.kind == Operand::Kind::Relative) continue;

            auto table = cfg_builder_detail::detect_jump_table(binary_, ws, ip);
            if (!table) continue;

            for (addr_t t : table->targets) {
                if (ws.leaders.insert(t).second) {
                    cfg_builder_detail::walk_from(
                        binary_, decoder_, ws, t, known_entries_, entry, owned_end);
                    added_work = true;
                }
            }
            if (table->default_tgt) {
                if (ws.leaders.insert(*table->default_tgt).second) {
                    cfg_builder_detail::walk_from(
                        binary_, decoder_, ws, *table->default_tgt,
                        known_entries_, entry, owned_end);
                    added_work = true;
                }
            }
            ws.tables.emplace(ip, std::move(*table));
        }
        if (!added_work) break;
    }

    Function fn;
    fn.start        = entry;
    fn.name         = std::move(name);
    fn.call_targets = std::move(ws.calls);

    cfg_builder_detail::partition(binary_, ws, fn);
    cfg_builder_detail::compute_predecessors(fn);

    // CFG-walk can't reach cleanup/landing-pad tails that the compiler
    // emitted past a noreturn call - there's no branch leading into them
    // from entry. The exception tables know the true function length,
    // so use them to extend fn.end when they report more than we walked.
    if (extend_unwind_ranges_) {
        ensure_unwind_ranges_();
        if (auto it = unwind_ranges_.find(entry); it != unwind_ranges_.end()) {
            const addr_t fde_end = entry + it->second;
            if (fde_end > fn.end) fn.end = fde_end;
        }
    }

    return fn;
}

}  // namespace spelunk
