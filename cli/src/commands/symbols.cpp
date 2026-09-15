// Symbol tables, name resolution, references and trace edges.

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <format>
#include <fstream>
#include <iterator>
#include <limits>
#include <map>
#include <optional>
#include <print>
#include <set>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_set>
#include <utility>
#include <vector>

#include <spelunk/analysis/data_xrefs.hpp>
#include <spelunk/analysis/identify.hpp>
#include <spelunk/analysis/pipeline.hpp>
#include <spelunk/analysis/symresolve.hpp>
#include <spelunk/analysis/symtable.hpp>
#include <spelunk/analysis/symuses.hpp>
#include <spelunk/binary/arch.hpp>
#include <spelunk/binary/binary.hpp>
#include <spelunk/binary/format.hpp>
#include <spelunk/common/bytes.hpp>
#include <spelunk/common/timing.hpp>
#include <spelunk/common/types.hpp>

#include "../args.hpp"
#include "../builders.hpp"
#include "../subcommands.hpp"
#include "../util.hpp"
#include "common.hpp"

namespace spelunk::cli {

namespace {

// One row of refs-to output. Both TSV and JSON formatters consume this
// shape; JSON mode exposes `slot` / `fn_name` /
// `fn_offset` as proper fields instead of having to grep them out of
// `(kind via 0xSLOT)  ; fn+0xN`.
struct RefRow {
    addr_t                   from_pc   = 0;
    addr_t                   target    = 0;
    std::string              kind;       // "direct" / "code-ptr" / "lea" / "imm64-stored" / "relocated" / "runtime-slot"
    std::optional<addr_t>    slot;       // populated for imm64-stored / relocated
    std::optional<std::string> fn_name;
    std::optional<u64>       fn_offset;
};

[[nodiscard]] bool refs_access_allows(const Args& args, DataXrefKind k) noexcept {
    if (args.refs_access.empty() || args.refs_access == "all") return true;
    if (args.refs_access == "read") return k == DataXrefKind::Read;
    if (args.refs_access == "write") return k == DataXrefKind::Write;
    if (args.refs_access == "lea") return k == DataXrefKind::Lea;
    if (args.refs_access == "code-ptr") return k == DataXrefKind::CodePtr;
    return true;
}

[[nodiscard]] bool refs_access_needs_call_edges(const Args& args) noexcept {
    return args.refs_access.empty() || args.refs_access == "all" ||
           args.refs_access == "call" || args.refs_access == "direct";
}

[[nodiscard]] std::string
format_ref_rows_tsv(std::span<const RefRow> rows,
                    const Binary* b = nullptr,
                    bool verbose = false) {
    std::string out;
    for (const auto& r : rows) {
        std::string ctx;
        if (r.fn_name) {
            ctx = std::format("  ; {}+{:#x}", *r.fn_name, r.fn_offset.value_or(0));
        }
        std::string detail;
        if (verbose && b != nullptr) {
            if (r.slot) {
                const auto sec = section_name_containing(*b, *r.slot);
                if (!sec.empty()) {
                    detail += std::format("  ; slot-section {}", sec);
                }
            }
            if (r.kind == "direct") {
                detail += "  ; site not cached (showing caller entry)";
            }
            if (const auto insn = first_disasm_line_at(*b, r.from_pc);
                !insn.empty()) {
                detail += std::format("  ; site {}", insn);
            }
        }
        if (r.slot) {
            out += std::format("{:#x} -> {:#x}  ({} via {:#x}){}{}\n",
                               r.from_pc, r.target, r.kind, *r.slot, ctx, detail);
        } else {
            out += std::format("{:#x} -> {:#x}  ({}){}{}\n",
                               r.from_pc, r.target, r.kind, ctx, detail);
        }
    }
    return out;
}

[[nodiscard]] std::string format_ref_rows_json(std::span<const RefRow> rows) {
    std::string out = "[";
    bool first = true;
    for (const auto& r : rows) {
        if (!first) out += ',';
        first = false;
        out += std::format(
            "{{\"from\":\"{:#x}\",\"target\":\"{:#x}\",\"kind\":\"{}\"",
            r.from_pc, r.target, r.kind);
        if (r.slot) {
            out += std::format(",\"slot\":\"{:#x}\"", *r.slot);
        }
        if (r.fn_name) {
            out += std::format(",\"fn\":\"{}\",\"fn_offset\":\"{:#x}\"",
                               json_escape(*r.fn_name),
                               r.fn_offset.value_or(0));
        }
        out += "}";
    }
    out += "]\n";
    return out;
}

[[nodiscard]] std::optional<addr_t>
raw_regions_runtime_base(const Binary& b) noexcept {
    if (b.format() != Format::RawRegions) return std::nullopt;
    std::optional<addr_t> out;
    for (const auto& s : b.sections()) {
        if (!s.flags.allocated || s.size == 0) continue;
        if (!out || s.vaddr < *out) out = s.vaddr;
    }
    return out;
}

[[nodiscard]] std::vector<addr_t>
refs_to_target_candidates(const Binary& b, addr_t va) {
    std::vector<addr_t> out{va};
    if (!address_is_mapped(b, va)) {
        if (auto base = raw_regions_runtime_base(b); base &&
            va <= std::numeric_limits<addr_t>::max() - *base) {
            const addr_t slid = *base + va;
            if (address_is_mapped(b, slid)) out.push_back(slid);
        }
    }
    return out;
}

void retarget_ref_rows(std::span<RefRow> rows, addr_t target) {
    for (auto& r : rows) r.target = target;
}

// Internal helper: gather the standard --refs-to rows (direct callers
// from the cached call-graph plus CodePtr/Lea events from
// compute_data_xrefs) for a single target VA. Both run_refs_to and
// run_refs_to_loose use this; loose mode appends extra `imm64-stored`
// / `relocated` rows on top.
[[nodiscard]] std::vector<RefRow>
gather_refs_to_rows(const Args& args, const Binary& b, addr_t va) {
    ScopedTimer total_timer("refs_to.gather");
    std::vector<RefRow> out;
    if (refs_access_needs_call_edges(args)) {
        for (addr_t from : compute_callers_to_fast(b, va)) {
            RefRow row;
            row.from_pc = from;
            row.target  = va;
            row.kind    = "direct";
            if (auto cf = containing_function(b, row.from_pc); cf) {
                row.fn_name   = cf->name;
                row.fn_offset = cf->offset_within;
            }
            out.push_back(std::move(row));
        }
    }

    for (const auto& r : compute_data_xrefs_to(b, va)) {
        if (args.refs_access.empty()) {
            if (r.kind != DataXrefKind::CodePtr &&
                r.kind != DataXrefKind::Lea) continue;
        } else if (!refs_access_allows(args, r.kind)) {
            continue;
        }
        RefRow row;
        row.from_pc = r.from_pc;
        row.target  = va;
        row.kind    = std::string(data_xref_kind_name(r.kind));
        if (auto cf = containing_function(b, r.from_pc); cf) {
            row.fn_name   = cf->name;
            row.fn_offset = cf->offset_within;
        }
        out.push_back(std::move(row));
    }
    return out;
}

// Parse a comma-separated list of category names. Returns the input
// unchanged when empty. Whitespace is trimmed; empty tokens dropped.
[[nodiscard]] std::vector<std::string>
split_filter_arg(std::string_view raw) {
    std::vector<std::string> out;
    std::size_t i = 0;
    while (i < raw.size()) {
        std::size_t j = raw.find(',', i);
        if (j == std::string_view::npos) j = raw.size();
        std::size_t a = i, b = j;
        while (a < b && std::isspace(static_cast<unsigned char>(raw[a]))) ++a;
        while (b > a && std::isspace(static_cast<unsigned char>(raw[b - 1]))) --b;
        if (b > a) out.emplace_back(raw.substr(a, b - a));
        i = j + 1;
    }
    return out;
}

// Render a callsite VA as `<containing_fn>+0xN`, falling back to the
// raw VA when nothing covers it. Looking up `containing_function` per
// site re-enumerates fns each time, but the volume here is bounded by
// the per-row callsite cap so it's not the hot path.
[[nodiscard]] std::string
render_callsite(const Binary& b, addr_t va) {
    if (auto cf = containing_function(b, va); cf) {
        return std::format("{}+{:#x}", cf->name, cf->offset_within);
    }
    return std::format("{:#x}", va);
}

int run_refs_to_loose_impl(const Args& args, const Binary& b) {
    // Heavier sibling of --refs-to. Beyond the cached call-graph
    // xrefs and CodePtr/Lea events surfaced by compose_refs_to_output,
    // this also walks every readable section for the literal target
    // VA stored as an 8-byte (or 4-byte on 32-bit) value, then folds
    // in the per-function references to those slots - recovering the
    // fn-pointer-only case where the target is reached as
    // `lea rax, [rip+disp_to_table]; mov rbx, [rax+N]; call rbx`
    // and there is no static call edge to the target itself.
    //
    // Confidence tagging in the row body lets downstream tooling
    // weight follow-ups: `code-ptr` / `lea` rows are static-evidence
    // strong; `imm64-stored` rows are circumstantial - the function
    // reads from a slot whose value matches the target, but the read
    // hasn't been chased to a call.
    auto va = resolve_flag_target(b, args, args.refs_to_loose);
    if (!va) return EXIT_FAILURE;  // resolver reported the reason

    std::vector<RefRow> rows;
    const auto targets = refs_to_target_candidates(b, *va);
    const std::span<const addr_t> search_targets = targets.size() > 1
        ? std::span<const addr_t>(targets).subspan(1)
        : std::span<const addr_t>(targets);
    if (targets.size() > 1) {
        std::println(stderr,
            "spelunk: --refs-to-loose: treating {:#x} as raw-region offset; runtime target {:#x}",
            *va, targets.back());
    }
    const bool raw_data_first = b.format() == Format::RawRegions;
    if (!raw_data_first) {
        for (addr_t target_va : search_targets) {
            auto more = gather_refs_to_rows(args, b, target_va);
            retarget_ref_rows(more, *va);
            rows.insert(rows.end(),
                        std::make_move_iterator(more.begin()),
                        std::make_move_iterator(more.end()));
        }
    }

    // Constant-pool scan: every readable section. Function-pointer
    // tables live in .rodata / .data / .data.rel.ro, sometimes inside
    // an .init_array ctor's frame. Bounded by total readable bytes -
    // a 100MB binary's data sections are the dominant cost.
    std::vector<addr_t> slot_addrs;
    const bool is_64 = arch_pointer_bits(b.arch()) == 64;
    const std::size_t needle_size = is_64 ? 8u : 4u;
    // Only scan at pointer-aligned slot VAs (8-byte for 64-bit pointers,
    // 4-byte for 32-bit). Without this guard, a single legitimate
    // function-pointer slot whose value contains the target's bytes
    // produces a cluster of byte-shifted false positives at the same
    // location - every bit-shift coincidentally matching the lower
    // 8 bytes of the next slot. Function-pointer tables are
    // pointer-aligned by linker convention; the rare unaligned case
    // is not worth the noise.
    for (addr_t target_va : search_targets) {
        std::vector<addr_t> target_slots;
        for (const auto& s : b.sections()) {
            if (!s.flags.readable) continue;
            if (s.data.empty()) continue;
            const std::byte* p = s.data.data();
            const std::size_t n = s.data.size();
            if (n < needle_size) continue;
            const auto sec_base = static_cast<addr_t>(s.vaddr);
            // Step the cursor up to the first aligned slot VA inside this
            // section, then advance by `needle_size` from there.
            const std::size_t first_aligned =
                (needle_size - (sec_base % needle_size)) % needle_size;
            for (std::size_t i = first_aligned; i + needle_size <= n;
                 i += needle_size) {
                const u64 v = is_64
                    ? read_le_at<u64>(p + i)
                    : static_cast<u64>(read_le_at<u32>(p + i));
                if (v == static_cast<u64>(target_va)) {
                    target_slots.push_back(sec_base + static_cast<addr_t>(i));
                }
            }
        }
        slot_addrs.insert(slot_addrs.end(), target_slots.begin(), target_slots.end());
    }

    // De-dupe against direct rows so `--refs-to-loose` stays a strict
    // superset without re-listing the same from_pc twice.
    std::set<addr_t> already_emitted;
    for (const auto& r : rows) already_emitted.insert(r.from_pc);

    if (raw_data_first) {
        for (addr_t slot : slot_addrs) {
            if (!already_emitted.insert(slot).second) continue;
            RefRow row;
            row.from_pc = slot;
            row.target  = *va;
            row.kind    = "runtime-slot";
            row.slot    = slot;
            rows.push_back(std::move(row));
        }
    }

    std::optional<std::map<addr_t, std::vector<DataXref>>> local_data_xrefs;
    const auto& dx = [&]() -> const std::map<addr_t, std::vector<DataXref>>& {
        if (raw_data_first) {
            local_data_xrefs = std::map<addr_t, std::vector<DataXref>>{};
            return *local_data_xrefs;
        }
        local_data_xrefs = compute_data_xrefs(b);
        return *local_data_xrefs;
    }();

    auto emit_slot_readers = [&](addr_t slot, std::string_view tag) {
        if (auto it = dx.find(slot); it != dx.end()) {
            for (const auto& xr : it->second) {
                if (xr.kind != DataXrefKind::Read &&
                    xr.kind != DataXrefKind::Lea) continue;
                if (!already_emitted.insert(xr.from_pc).second) continue;
                RefRow row;
                row.from_pc = xr.from_pc;
                row.target  = *va;
                row.kind    = std::string(tag);
                row.slot    = slot;
                if (auto cf = containing_function(b, xr.from_pc); cf) {
                    row.fn_name   = cf->name;
                    row.fn_offset = cf->offset_within;
                }
                rows.push_back(std::move(row));
            }
        }
    };
    if (!raw_data_first) {
        for (addr_t slot : slot_addrs) emit_slot_readers(slot, "imm64-stored");
    }

    // Relocation-driven slots: loader-patched qwords whose post-load
    // target is known from format metadata. This catches ELF RELATIVE
    // slots and PE DIR64 base-relocation slots.
    std::size_t reloc_slot_count = 0;
    std::optional<std::map<addr_t, u64>> local_relocated_qwords;
    const auto& reloc_map = [&]() -> const std::map<addr_t, u64>& {
        local_relocated_qwords = b.relocated_qwords();
        return *local_relocated_qwords;
    }();
    for (const auto& [slot, addend] : reloc_map) {
        if (std::ranges::find(search_targets, addend) == search_targets.end()) continue;
        ++reloc_slot_count;
        emit_slot_readers(slot, "relocated");
    }

    const std::string out = args.json
        ? format_ref_rows_json(rows)
        : format_ref_rows_tsv(rows, &b, args.verbose);
    std::fwrite(out.data(), 1, out.size(), stdout);
    if (rows.empty()) {
        std::println(stderr, "spelunk: --refs-to-loose: 0 references found "
                             "({} static slot{}, {} relocated slot{}, 0 readers)",
                     slot_addrs.size(),
                     slot_addrs.size() == 1 ? "" : "s",
                     reloc_slot_count,
                     reloc_slot_count == 1 ? "" : "s");
    }
    return EXIT_SUCCESS;
}

}  // namespace

void load_trace_edges(const Args& args, const Binary& b) {
    // Indirect-edge trace must seed the oracle BEFORE any analysis runs
    // - the CFG builder consults it lazily but the result gets cached
    // in IR caches downstream, so late-loading wouldn't take effect on
    // subsequent passes.
    std::ifstream tf(args.trace_path);
    if (!tf) {
        std::println(stderr, "spelunk: cannot open trace '{}'", args.trace_path);
        return;
    }
    auto parse_hex = [](std::string_view s, addr_t& out) {
        if (s.starts_with("0x") || s.starts_with("0X")) s.remove_prefix(2);
        u64 v = 0;
        auto r = std::from_chars(s.data(), s.data() + s.size(), v, 16);
        if (r.ec != std::errc{} || r.ptr != s.data() + s.size()) return false;
        out = static_cast<addr_t>(v);
        return true;
    };
    std::string line;
    std::size_t loaded_edges = 0, loaded_qwords = 0, line_no = 0;
    while (std::getline(tf, line)) {
        ++line_no;
        std::string_view sv = line;
        while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.front()))) {
            sv.remove_prefix(1);
        }
        if (sv.empty() || sv.front() == '#') continue;

        std::istringstream toks{std::string(sv)};
        std::string a, b_tok, c;
        toks >> a >> b_tok >> c;
        addr_t from = 0, to = 0;
        if ((a == "qword" || a == "global" || a == "object" || a == "vptr") &&
            !b_tok.empty() && !c.empty()) {
            if (!parse_hex(b_tok, from) || !parse_hex(c, to)) {
                std::println(stderr,
                    "spelunk: trace '{}' line {}: bad runtime qword fact",
                    args.trace_path, line_no);
                continue;
            }
            b.record_runtime_qword(from, to);
            ++loaded_qwords;
            continue;
        }
        if ((a == "indirect" || a == "edge") && !b_tok.empty() && !c.empty()) {
            a = std::move(b_tok);
            b_tok = std::move(c);
        }
        if (!parse_hex(a, from) || !parse_hex(b_tok, to)) {
            std::println(stderr,
                "spelunk: trace '{}' line {}: expected `from to`, `indirect from to`, `qword addr value`, or `object addr vtable`",
                args.trace_path, line_no);
            continue;
        }
        b.record_indirect_edge(from, to);
        ++loaded_edges;
    }
    std::println(stderr, "spelunk: loaded {} indirect edge(s), {} runtime qword fact(s) from '{}'",
                 loaded_edges, loaded_qwords, args.trace_path);
}

int run_symtable(const Args& args, const Binary& b) {
    auto va = parse_cli_addr(args.symtable);
    if (!va) {
        std::println(stderr, "spelunk: --symtable: bad address '{}'", args.symtable);
        return EXIT_FAILURE;
    }
    auto walk = analysis::walk_symtable(b, *va);
    if (!walk) {
        std::println(stderr, "spelunk: --symtable: {}", walk.error().message);
        return EXIT_FAILURE;
    }

    // Per-entry TSV: VA \t offset \t length \t string. Display column
    // truncates at 256 chars + "…"; the length column always reports
    // the true byte length.
    constexpr std::size_t kDisplayCap = 256;
    for (const auto& e : walk->entries) {
        if (e.length > kDisplayCap) {
            std::print("{:#x}\t{:#x}\t{}\t",
                       e.va, e.offset, e.length);
            std::fwrite(e.text.data(), 1, kDisplayCap, stdout);
            std::print("…\n");
        } else {
            std::println("{:#x}\t{:#x}\t{}\t{}",
                         e.va, e.offset, e.length, e.text);
        }
    }
    std::println("# total: {} strings, table_size {:#x} bytes, ends @ {:#x} ({})",
                 walk->entries.size(), walk->table_size, walk->end_va,
                 analysis::symtable_termination_name(walk->terminated_by));

    // Bonus: keyword-bucketed view. Skipped when nothing matches -
    // keeps the output clean for tables that aren't dlsym targets.
    const auto cats = analysis::categorize_symtable(*walk);
    if (!cats.empty()) {
        std::println("# categories:");
        std::size_t pad = 0;
        for (const auto& c : cats) pad = std::max(pad, c.name.size());
        for (const auto& c : cats) {
            std::print("#   {:<{}}  ", c.name, pad);
            for (std::size_t i = 0; i < c.hits.size(); ++i) {
                if (i) std::print(", ");
                std::print("{}", c.hits[i]);
            }
            std::print("\n");
        }
    }
    return EXIT_SUCCESS;
}

int run_symresolve(const Args& args, const Binary& b) {
    auto va = parse_cli_addr(args.symresolve);
    if (!va) {
        std::println(stderr, "spelunk: --symresolve: bad address '{}'", args.symresolve);
        return EXIT_FAILURE;
    }
    auto res = analysis::resolve_symtable(b, *va);
    if (!res) {
        std::println(stderr, "spelunk: --symresolve: {}", res.error().message);
        return EXIT_FAILURE;
    }

    // Build the filter set (category buckets → membership-by-name) once.
    // The filter rejects unknown category names early so a typo doesn't
    // silently degrade to "show everything".
    std::vector<std::string> wanted_cats = split_filter_arg(args.category_filter);
    std::unordered_set<std::string_view> wanted_names;
    bool have_filter = !wanted_cats.empty();
    if (have_filter) {
        const auto cats = analysis::categorize_symtable(res->walk);
        for (const auto& want : wanted_cats) {
            for (const auto& c : cats) {
                if (c.name == want) {
                    for (auto h : c.hits) wanted_names.insert(h);
                }
            }
        }
    }

    if (!res->resolvers.empty()) {
        std::string list;
        for (std::size_t i = 0; i < res->resolvers.size(); ++i) {
            const auto& r = res->resolvers[i];
            if (i) list += ", ";
            list += std::format("{} ({} slots @ {:#x})",
                                r.fn_name.empty() ? "<unnamed>" : r.fn_name,
                                r.slots, r.base_va);
        }
        std::println(stderr, "spelunk: --symresolve: resolver(s) = {}", list);
    } else {
        std::println(stderr,
            "spelunk: --symresolve: no resolver function found for table at "
            "{:#x} - falling back to string table only", *va);
    }
    {
        const std::size_t total    = res->non_empty_count;
        const std::size_t resolved = res->resolved_count;
        const double pct = total == 0 ? 0.0
                                       : (100.0 * static_cast<double>(resolved)
                                                  / static_cast<double>(total));
        std::println(stderr,
            "spelunk: --symresolve: coverage: {}/{} slots resolved ({:.1f}%)",
            resolved, total, pct);
        if (total != 0 && pct < 50.0) {
            std::println(stderr,
                "spelunk: --symresolve: tip: try --symuses {:#x} for the "
                "lazy/per-function dispatch pattern", *va);
        }
    }

    std::println("idx\tstr_va\tsymbol\tfnptr_va\tn_callsites\ttop_callsites");
    const std::size_t cap = static_cast<std::size_t>(args.symresolve_max_callsites);
    for (const auto& r : res->rows) {
        if (have_filter && !wanted_names.contains(r.name)) continue;

        const std::string fnptr_col = r.fnptr_va
            ? std::format("{:#x}", *r.fnptr_va)
            : std::string{"-"};

        std::string sites_col;
        if (r.callsites.empty()) {
            sites_col = "-";
        } else {
            const std::size_t shown = (cap == 0)
                ? r.callsites.size()
                : std::min(cap, r.callsites.size());
            for (std::size_t i = 0; i < shown; ++i) {
                if (i) sites_col += ", ";
                sites_col += render_callsite(b, r.callsites[i]);
            }
            if (shown < r.callsites.size()) sites_col += ", ...";
        }

        std::println("{}\t{:#x}\t{}\t{}\t{}\t{}",
                     r.index, r.string_va, r.name,
                     fnptr_col, r.callsites.size(), sites_col);
    }
    return EXIT_SUCCESS;
}

int run_symuses(const Args& args, const Binary& b) {
    auto va = parse_cli_addr(args.symuses);
    if (!va) {
        std::println(stderr, "spelunk: --symuses: bad address '{}'", args.symuses);
        return EXIT_FAILURE;
    }
    analysis::SymUseOptions opts;
    opts.no_taint = args.symuses_no_taint;
    auto uses = analysis::collect_symbol_uses(b, *va, opts);
    if (!uses) {
        std::println(stderr, "spelunk: --symuses: {}", uses.error().message);
        return EXIT_FAILURE;
    }

    // Filter set: when --filter is given, only sites whose symbol
    // falls in any requested category bucket count toward n_uses or
    // appear in the symbols column. Empty filter = unrestricted.
    std::unordered_set<std::string_view> wanted_names;
    const bool have_filter = !args.category_filter.empty();
    if (have_filter) {
        const auto cats = analysis::categorize_symtable(uses->walk);
        for (const auto& want : split_filter_arg(args.category_filter)) {
            for (const auto& c : cats) {
                if (c.name == want) {
                    for (auto h : c.hits) wanted_names.insert(h);
                }
            }
        }
    }

    // Scope summary: which paths admitted candidate functions. Always
    // surfaced - operators reading the TSV need to know whether the
    // analysis even had a non-empty scope to scan, since "0 rows"
    // could mean "no consumers exist" or "the scope detector found
    // nothing to feed the per-fn pass".
    std::println(stderr,
        "spelunk: --symuses: scope: {} candidate function{} "
        "({} imm64-stored slot{}, {} relocated slot{})",
        uses->scope_fn_count, uses->scope_fn_count == 1 ? "" : "s",
        uses->scope_imm64_slots, uses->scope_imm64_slots == 1 ? "" : "s",
        uses->scope_relocated_slots, uses->scope_relocated_slots == 1 ? "" : "s");

    if (args.verbose) {
        // Per-fn diag: surfaces base-load count, raw IMM matches, and
        // unique-entry count. The sub-counts let an operator catch
        // the case where some scope candidate is producing no hits
        // because its body uses a different indirection than the
        // weak-filter exact-offset match.
        for (const auto& row : uses->rows) {
            if (row.base_load_sites.empty()) continue;
            std::unordered_set<std::string_view> uniq;
            for (const auto& s : row.sites) uniq.insert(s.name);
            std::println(stderr,
                "spelunk: --symuses:   {}: {} base-load{}, "
                "{} IMM match{} -> {} unique entr{}",
                row.fn_name.empty()
                    ? std::format("{:#x}", row.fn_addr)
                    : row.fn_name,
                row.base_load_sites.size(),
                row.base_load_sites.size() == 1 ? "" : "s",
                row.sites.size(),
                row.sites.size() == 1 ? "" : "es",
                uniq.size(),
                uniq.size() == 1 ? "y" : "ies");
        }
    }

    auto site_passes = [&](const analysis::SymUseSite& s) noexcept {
        if (s.name.empty()) return false;   // leading-empty entry: handled separately
        if (have_filter && !wanted_names.contains(s.name)) return false;
        return true;
    };

    if (args.verbose) {
        std::println("fn_va\tcallsite\tsymbol");
        for (const auto& row : uses->rows) {
            // Verbose mode emits every site individually. Table-walker
            // rows still surface their per-site refs to the leading
            // empty entry - render those as "<table_base>" so an
            // operator can see the walk-shape without confusing it
            // with a real symbol.
            for (const auto& s : row.sites) {
                if (s.name.empty()) {
                    if (have_filter) continue;
                    std::println("{:#x}\t{}+{:#x}\t<table_base>",
                                 row.fn_addr, row.fn_name,
                                 s.callsite - row.fn_addr);
                    continue;
                }
                if (!site_passes(s)) continue;
                std::println("{:#x}\t{}+{:#x}\t{}",
                             row.fn_addr, row.fn_name,
                             s.callsite - row.fn_addr, s.name);
            }
        }
        return EXIT_SUCCESS;
    }

    std::println("fn_va\tn_uses\tsymbols");
    for (const auto& row : uses->rows) {
        // Dedupe symbol names in walk-order - preserves the order in
        // which the function first touched each symbol, which is the
        // shape an operator wants when scanning a long row.
        std::vector<std::string_view> names_in_order;
        std::unordered_set<std::string_view> seen;
        std::size_t passing_uses = 0;
        for (const auto& s : row.sites) {
            if (!site_passes(s)) continue;
            ++passing_uses;
            if (seen.insert(s.name).second) names_in_order.push_back(s.name);
        }

        // No specific symbol hits but the function loaded the table
        // base - that's the table-walker shape (looping the table by
        // index rather than by constant offset). Emit a single
        // placeholder row, gated by --min-uses on the lea-to-base
        // count. Filtering is suppressed since there's no per-symbol
        // signal to match against.
        if (passing_uses == 0 && row.walks_full_table && !have_filter) {
            const std::size_t n = row.sites.empty() ? 1 : row.sites.size();
            if (n < args.symuses_min_uses) continue;
            std::println("{:#x}\t{}\t<full_table_walker>", row.fn_addr, n);
            continue;
        }

        if (passing_uses < args.symuses_min_uses) continue;
        if (passing_uses == 0 && !args.symuses_show_empty) continue;

        std::string symbols_col;
        for (std::size_t i = 0; i < names_in_order.size(); ++i) {
            if (i) symbols_col += ", ";
            symbols_col += names_in_order[i];
        }
        if (symbols_col.empty()) symbols_col = "-";

        std::println("{:#x}\t{}\t{}", row.fn_addr, passing_uses, symbols_col);
    }
    return EXIT_SUCCESS;
}

int run_refs_to(const Args& args, const Binary& b) {
    auto va = resolve_flag_target(b, args, args.refs_to);
    if (!va) return EXIT_FAILURE;  // resolver reported the reason
    // An unmapped VA can only ever yield zero rows, and silently
    // returning them would be indistinguishable from "mapped but no
    // callers" - call it out as a failure instead. A mapped target
    // with zero rows stays a valid empty result (exit 0) so scripts
    // piping the output keep working; it just gets a stderr note.
    if (b.bytes_at(*va).empty()) {
        std::println(stderr,
                     "spelunk: --refs-to: {:#x} is not in any mapped section",
                     *va);
        return EXIT_FAILURE;
    }
    const auto rows = gather_refs_to_rows(args, b, *va);
    const std::string out = args.json
        ? format_ref_rows_json(rows)
        : format_ref_rows_tsv(rows, &b, args.verbose);
    std::fwrite(out.data(), 1, out.size(), stdout);
    if (rows.empty()) {
        std::println(stderr, "spelunk: --refs-to: 0 references found ({:#x})", *va);
    }
    return EXIT_SUCCESS;
}

int run_refs_to_loose(const Args& args, const Binary& b) {
    return run_refs_to_loose_impl(args, b);
}

}  // namespace spelunk::cli
