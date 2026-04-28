#include "builders.hpp"

#include <algorithm>
#include <format>
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
#include <ember/analysis/vm_detect.hpp>
#include <ember/binary/binary.hpp>
#include <ember/binary/symbol.hpp>
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
    // Order edges so leaves come first and the rough `main`-ward
    // hierarchy reads top-down. Topological sort (Kahn's algorithm) over
    // the caller graph; cycles fall through in arbitrary order at the tail.
    const auto edges = compute_call_graph(b);
    std::unordered_map<addr_t, std::vector<addr_t>> succs;
    std::unordered_map<addr_t, std::size_t> indeg;
    std::set<addr_t> nodes;
    for (const auto& e : edges) {
        succs[e.caller].push_back(e.callee);
        indeg[e.callee] += 1;
        if (!indeg.contains(e.caller)) indeg[e.caller] += 0;
        nodes.insert(e.caller);
        nodes.insert(e.callee);
    }
    // Kahn: nodes with zero in-degree (never called) emit first. Matches
    // reader habit — main at top, helpers below.
    std::vector<addr_t> order;
    std::vector<addr_t> ready;
    for (addr_t n : nodes) if (indeg[n] == 0) ready.push_back(n);
    std::ranges::sort(ready);  // deterministic on ties
    while (!ready.empty()) {
        const auto v = ready.back();
        ready.pop_back();
        order.push_back(v);
        auto it = succs.find(v);
        if (it == succs.end()) continue;
        for (addr_t w : it->second) {
            if (--indeg[w] == 0) ready.push_back(w);
        }
    }
    // Append remaining nodes (those on cycles) in addr order.
    std::set<addr_t> emitted(order.begin(), order.end());
    for (addr_t n : nodes) if (!emitted.contains(n)) order.push_back(n);

    // Group edges by caller in topo order, sort each group by callee for
    // stability within a caller.
    std::unordered_map<addr_t, std::vector<addr_t>> by_caller;
    for (const auto& e : edges) by_caller[e.caller].push_back(e.callee);
    for (auto& [_, v] : by_caller) std::ranges::sort(v);

    std::string out;
    for (addr_t caller : order) {
        auto it = by_caller.find(caller);
        if (it == by_caller.end()) continue;
        for (addr_t callee : it->second) {
            out += std::format("{:#x} -> {:#x}\n", caller, callee);
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
    for (const auto& s : b.symbols()) {
        if (s.is_import) continue;
        if (s.kind != SymbolKind::Function) continue;
        if (s.size == 0 || s.name.empty()) continue;
        out += std::format("{:#x} {}\n", s.addr, infer_arity(b, s.addr));
    }
    return out;
}

// TSV: <addr_hex>\t<size_hex>\t<kind>\t<name>. `kind` is "symbol" for a
// defined function symbol or "sub" for an entry that only appeared as a
// call target during CFG walking. Size is 0 for `sub` rows.
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

// One block per VM (handler-table cluster). Lists the table + anatomy
// once and breaks the per-site rows into entry sites (central /
// external dispatchers) and threaded sites (handler tail-dispatches),
// so a 16-handler threaded VM reads as one VM with 16 slots instead
// of 16 disconnected dispatchers.
std::string build_vm_detect_output(const Binary& b) {
    auto fn_label = [&](addr_t va) -> std::string {
        for (const auto& s : b.symbols()) {
            if (s.is_import) continue;
            if (s.kind != SymbolKind::Function) continue;
            if (s.addr == va && !s.name.empty()) return s.name;
        }
        return std::format("sub_{:x}", va);
    };

    constexpr std::size_t kHandlersPerLine = 4;
    constexpr std::size_t kHandlersShown   = 16;

    std::string out;
    std::size_t idx = 0;
    for (const auto& vm : group_vm_dispatchers(detect_vm_dispatchers(b))) {
        if (idx > 0) out += "\n";
        out += std::format("vm #{}\n", idx + 1);
        out += std::format("  handler table:   {:#x}  ({} entries, {} unique)\n",
                           vm.table_addr, vm.table_entries, vm.handlers.size());
        out += std::format("  opcode register: {}  ({}-byte opcode)\n",
                           reg_name(vm.opcode_index_reg),
                           static_cast<unsigned>(vm.opcode_size_bytes));
        out += std::format("  pc register:     {}\n",
                           vm.pc_register == Reg::None
                               ? std::string_view{"unknown"}
                               : reg_name(vm.pc_register));
        if (vm.pc_disp != 0) {
            out += std::format("  pc disp:         {:#x}\n",
                               static_cast<u64>(static_cast<i64>(vm.pc_disp)));
        }
        if (vm.pc_advance != 0) {
            const char sign = vm.pc_advance > 0 ? '+' : '-';
            out += std::format("  pc advance:      {}{}\n",
                               sign,
                               vm.pc_advance > 0 ? vm.pc_advance : -vm.pc_advance);
        } else {
            out += "  pc advance:      (unobserved — may live inside handlers)\n";
        }
        if (vm.bytecode_addr != 0) {
            out += std::format("  bytecode:        {:#x}  (constant via lea rip+disp)\n",
                               vm.bytecode_addr);
        } else {
            out += "  bytecode:        (runtime / caller-supplied)\n";
        }

        auto emit_sites = [&](std::string_view header,
                              const std::vector<VmDispatcher>& sites) {
            if (sites.empty()) return;
            out += std::format("  {} ({}):\n", header, sites.size());
            for (const auto& d : sites) {
                out += std::format("    {} → dispatch {:#x} (load {:#x})\n",
                                   fn_label(d.function_addr),
                                   d.dispatch_addr, d.opcode_load_addr);
            }
        };
        emit_sites("entry sites",    vm.entry_sites);
        emit_sites("threaded sites", vm.threaded_sites);

        const std::size_t shown = std::min(vm.handlers.size(), kHandlersShown);
        out += std::format("  handlers ({} shown):\n", shown);
        for (std::size_t i = 0; i < shown; ++i) {
            if (i % kHandlersPerLine == 0) out += "   ";
            out += std::format(" {:#x}", vm.handlers[i]);
            if (i + 1 == shown || (i + 1) % kHandlersPerLine == 0) out += "\n";
        }
        if (vm.handlers.size() > shown) {
            out += std::format("    ... +{} more\n", vm.handlers.size() - shown);
        }
        ++idx;
    }
    return out;
}

}  // namespace ember::cli
