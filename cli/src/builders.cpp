#include "builders.hpp"

#include <algorithm>
#include <cstdio>
#include <format>
#include <limits>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include <ember/analysis/arity.hpp>
#include <ember/analysis/data_xrefs.hpp>
#include <ember/analysis/objc.hpp>
#include <ember/analysis/pipeline.hpp>
#include <ember/analysis/rtti.hpp>
#include <ember/analysis/strings.hpp>
#include <ember/analysis/int3_resolver.hpp>
#include <ember/analysis/vtables.hpp>
#include <ember/binary/binary.hpp>
#include <ember/binary/symbol.hpp>
#include <ember/common/timing.hpp>
#include <ember/disasm/register.hpp>

#include "util.hpp"

namespace ember::cli {

std::string build_strings_output(const Binary& b) {
    // Format: "addr|escaped-text|xref1,xref2,..."  (addrs in hex, no 0x prefix)
    std::string out;
    for (const auto& e : scan_strings(b)) {
        std::string xrefs;
        for (std::size_t i = 0; i < e.xrefs.size(); ++i) {
            if (i > 0) xrefs += ",";
            xrefs += std::format("{:x}", e.xrefs[i]);
        }
        out += std::format("{:x}|{}|{}\n", e.addr, escape_for_line(e.text), xrefs);
    }
    return out;
}

std::string build_xrefs_output(const Binary& b) {
    ScopedTimer total_timer("xrefs.total");
    std::vector<CallEdge> edges;
    {
        ScopedTimer t("xrefs.call_graph");
        edges = compute_call_graph(b, {}, CallGraphMode::Fast);
    }
    if (timing_enabled()) {
        std::fprintf(stderr, "[timing] xrefs.edges: %zu\n", edges.size());
    }

    // Keep --xrefs cheap: callers mostly need a stable edge list, not a
    // graph-layout pass. The old topo-ish formatter built several maps and
    // sets over the whole edge list after the scan had already done the
    // useful work. Sorting pairs directly is dramatically lighter on large
    // binaries and daemon/agent loops.
    {
        ScopedTimer t("xrefs.sort_dedupe");
        std::ranges::sort(edges, {}, [](const CallEdge& e) {
            return std::pair{e.caller, e.callee};
        });
        edges.erase(std::unique(edges.begin(), edges.end(),
            [](const CallEdge& lhs, const CallEdge& rhs) {
                return lhs.caller == rhs.caller && lhs.callee == rhs.callee;
            }), edges.end());
    }

    std::string out;
    {
        ScopedTimer t("xrefs.format");
        out.reserve(edges.size() * 32);
        for (const auto& e : edges) {
            out += std::format("{:#x} -> {:#x}\n", e.caller, e.callee);
        }
    }
    return out;
}

std::string build_data_xrefs_output(const Binary& b, bool json) {
    const auto xrefs = compute_data_xrefs(b);
    std::string out;
    if (!json) {
        for (const auto& [target, refs] : xrefs) {
            for (const auto& r : refs) {
                out += std::format("{:x}\t{:x}\t{}\n",
                                   target, r.from_pc, data_xref_kind_name(r.kind));
            }
        }
        return out;
    }
    out = "[";
    bool first_t = true;
    for (const auto& [target, refs] : xrefs) {
        if (!first_t) out += ',';
        first_t = false;
        out += std::format("{{\"target\":\"{:#x}\",\"refs\":[", target);
        bool first_r = true;
        for (const auto& r : refs) {
            if (!first_r) out += ',';
            first_r = false;
            out += std::format("{{\"site\":\"{:#x}\",\"kind\":\"{}\"}}",
                               r.from_pc, data_xref_kind_name(r.kind));
        }
        out += "]}";
    }
    out += "]\n";
    return out;
}

std::string build_arities_output(const Binary& b) {
    std::string out;
    for (const auto& fn : enumerate_functions(b, EnumerateMode::Auto)) {
        if (b.import_at_plt(fn.addr)) continue;
        out += std::format("{:#x} {}\n", fn.addr, infer_arity(b, fn.addr));
    }
    return out;
}

// TSV: <addr_hex>\t<size_hex>\t<kind>\t<name>. `kind` is "symbol" for a
// defined function symbol or "sub" for a CFG-discovered entry. Missing sizes
// are estimated from the gap to the next function (or section boundary) so
// downstream tools still work with sparse or stripped symbol metadata.
std::string build_functions_output(const Binary& b, bool full_analysis) {
    std::string out;
    const auto mode = full_analysis ? EnumerateMode::Full : EnumerateMode::Auto;
    for (const auto& fn : enumerate_functions(b, mode)) {
        out += std::format("{:#018x}\t{:#x}\t{}\t{}\n",
                           fn.addr, fn.size, discovered_kind_name(fn.kind), fn.name);
    }
    return out;
}

// TSV: <imp-hex>\t<[+-]>\t<class>\t<selector>\t<decoded-signature>
std::string build_objc_names_output(const Binary& b) {
    std::string out;
    for (const auto& m : parse_objc_methods(b)) {
        out += std::format("{:x}\t{}\t{}\t{}\t{}\n",
                           m.imp, m.is_class ? '+' : '-',
                           m.cls, m.selector, decode_objc_type(m.type_encoding));
    }
    return out;
}

// One block per protocol, each line: `protocol\t[+-][!?]\tselector\tsignature`.
// `!` marks required, `?` marks optional.
std::string build_objc_protocols_output(const Binary& b) {
    std::string out;
    auto emit = [&](const ObjcProtocol& p, const std::vector<ObjcMethod>& ml,
                    char tag, char req) {
        for (const auto& m : ml) {
            out += std::format("{}\t{}{}\t{}\t{}\n",
                               p.name, tag, req, m.selector,
                               decode_objc_type(m.type_encoding));
        }
    };
    for (const auto& p : parse_objc_protocols(b)) {
        emit(p, p.required_instance, '-', '!');
        emit(p, p.required_class,    '+', '!');
        emit(p, p.optional_instance, '-', '?');
        emit(p, p.optional_class,    '+', '?');
    }
    return out;
}

// Itanium C++ RTTI: one row per (class, vfn_idx, imp_addr); meta row per
// class with vtable address + method count.
std::string build_rtti_output(const Binary& b) {
    std::string out;
    for (const auto& c : parse_itanium_rtti(b)) {
        out += std::format("class\t{:x}\t{:x}\t{}\t{}\t{}\n",
                           c.typeinfo, c.vtable, c.methods.size(),
                           c.demangled_name, c.mangled_name);
        for (std::size_t i = 0; i < c.methods.size(); ++i) {
            out += std::format("vfn\t{:x}\t{}\t{}::vfn_{}\n",
                               c.methods[i], i, c.demangled_name, i);
        }
    }
    return out;
}

std::string build_vtables_output(const Binary& b) {
    std::string out;
    const addr_t width = arch_pointer_bits(b.arch()) == 32 ? 4 : 8;
    for (const auto& vt : discover_runtime_vtables(b)) {
        out += std::format("vtable\t{:#x}\t{}\n", vt.vaddr, vt.methods.size());
        for (std::size_t i = 0; i < vt.methods.size(); ++i) {
            out += std::format("slot\t{:#x}\t{:#x}\t{}\n",
                               vt.vaddr + static_cast<addr_t>(i) * width,
                               vt.methods[i], i);
        }
    }
    return out;
}

std::string build_vtable_at_output(const Binary& b, addr_t va, u64 limit) {
    const addr_t width = arch_pointer_bits(b.arch()) == 32 ? 4 : 8;
    const auto vtables = discover_runtime_vtables(b);

    const RuntimeVtable* best = nullptr;
    std::size_t best_index = 0;
    addr_t best_distance = std::numeric_limits<addr_t>::max();

    for (const auto& vt : vtables) {
        if (vt.methods.empty()) continue;
        const addr_t begin = vt.vaddr;
        const addr_t end = vt.vaddr + static_cast<addr_t>(vt.methods.size()) * width;

        std::size_t index = 0;
        addr_t distance = 0;
        if (va >= begin && va < end) {
            index = static_cast<std::size_t>((va - begin) / width);
        } else {
            const addr_t before = begin >= 2 * width ? begin - 2 * width : begin;
            const addr_t after = end + 2 * width;
            if (va < before || va > after) continue;
            if (va < begin) {
                distance = begin - va;
                index = 0;
            } else {
                distance = va - end;
                index = vt.methods.size() - 1;
            }
        }

        if (!best || distance < best_distance) {
            best = &vt;
            best_index = index;
            best_distance = distance;
        }
    }

    if (!best) {
        return std::format("(no runtime vtable containing/near {:#x})\n", va);
    }

    std::size_t first = 0;
    std::size_t last = best->methods.size();
    if (limit != 0 && best->methods.size() > limit) {
        const std::size_t cap = static_cast<std::size_t>(limit);
        const std::size_t half = cap / 2;
        first = best_index > half ? best_index - half : 0;
        last = std::min(best->methods.size(), first + cap);
        if (last - first < cap && last == best->methods.size()) {
            first = best->methods.size() > cap ? best->methods.size() - cap : 0;
        }
    }

    std::string out;
    out += std::format("vtable\t{:#x}\t{}\tquery={:#x}\tindex={}\n",
                       best->vaddr, best->methods.size(), va, best_index);
    if (first != 0) {
        out += std::format("...\t{} slots before\n", first);
    }
    for (std::size_t i = first; i < last; ++i) {
        out += std::format("slot\t{:#x}\t{:#x}\t{}\n",
                           best->vaddr + static_cast<addr_t>(i) * width,
                           best->methods[i], i);
    }
    if (last != best->methods.size()) {
        out += std::format("...\t{} slots after\n", best->methods.size() - last);
    }
    return out;
}

std::string build_int3_resolve_output(const Binary& b) {
    auto fn_label = [&](addr_t va) -> std::string {
        for (const auto& s : b.symbols()) {
            if (s.is_import) continue;
            if (s.kind != SymbolKind::Function) continue;
            if (s.addr == va && !s.name.empty()) return s.name;
        }
        return std::format("sub_{:x}", va);
    };

    std::string out;
    auto results = resolve_embedded_int3s(b);
    if (results.empty()) {
        out = "(no embedded int3 bytes found)\n";
        return out;
    }

    out += std::format("embedded int3 sites: {}\n", results.size());
    out += "\n";

    // Group by kind for a summary header.
    std::unordered_map<Int3Kind, std::size_t> by_kind;
    for (const auto& r : results) ++by_kind[r.kind];
    out += "summary by kind:\n";
    for (auto [kind, count] : by_kind) {
        out += std::format("  {:12s} {}\n", int3_kind_name(kind), count);
    }
    out += "\n";

    // Per-site detail.
    for (const auto& r : results) {
        out += std::format("{:#x}  {:14s}", r.addr, int3_kind_name(r.kind));
        if (r.kind == Int3Kind::StubbedBranch && r.predicate) {
            out += std::format("[{}] ", branch_predicate_name(*r.predicate));
        }
        if (r.containing_fn != 0) {
            out += std::format("  in {}+{:#x}",
                               fn_label(r.containing_fn), r.fn_offset);
        } else {
            out += "  (outside any function)";
        }
        if (!r.note.empty()) {
            out += std::format("  - {}", r.note);
        }
        out += "\n";
    }
    return out;
}

}  // namespace ember::cli
