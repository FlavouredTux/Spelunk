// Graphics API usage report.

#include <algorithm>
#include <cstdio>
#include <format>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <ember/analysis/graphics.hpp>
#include <ember/binary/binary.hpp>
#include <ember/common/types.hpp>

#include "builders.hpp"
#include "builders_internal.hpp"
#include "util.hpp"

namespace ember::cli::builders {

namespace {

[[nodiscard]] bool matches_graphics_summary(const GraphicsBackendSummary& s,
                                            const GraphicsOutputFilter& filter) {
    if (!backend_matches(s.backend, filter)) return false;
    // Domain/API filters narrow per-row evidence. Keeping backend totals in
    // that mode reads like filtered counts, so omit summaries instead.
    return filter.domain.empty() && filter.api.empty() &&
           filter.extension.empty() && filter.category.empty() &&
           filter.role.empty() && !filter.function;
}

[[nodiscard]] bool matches_graphics_api(const GraphicsApiFact& a,
                                        const GraphicsOutputFilter& filter) {
    if (!backend_matches(a.backend, filter)) return false;
    if (!vector_contains_ci(a.domains, filter.domain)) return false;
    if (!vector_contains_ci(a.extensions, filter.extension)) return false;
    if (!vector_contains_ci(a.categories, filter.category)) return false;
    if (filter.function && !vector_contains_addr(a.functions, *filter.function)) return false;
    return filter.api.empty() || contains_ci(a.api_name, filter.api) ||
           vector_contains_substring_ci(a.variants, filter.api);
}

[[nodiscard]] bool matches_graphics_extension(const GraphicsExtensionFact& e,
                                              const GraphicsOutputFilter& filter) {
    if (!backend_matches(e.backend, filter)) return false;
    if (!filter.extension.empty() && !equals_ci(e.extension, filter.extension)) return false;
    if (!vector_contains_ci(e.domains, filter.domain)) return false;
    if (!vector_contains_ci(e.categories, filter.category)) return false;
    if (filter.function && !vector_contains_addr(e.functions, *filter.function)) return false;
    if (filter.api.empty()) return true;
    return vector_contains_substring_ci(e.apis, filter.api) ||
           vector_contains_substring_ci(e.variants, filter.api);
}

[[nodiscard]] bool matches_graphics_function(const GraphicsFunctionFact& f,
                                             const GraphicsOutputFilter& filter) {
    if (!backend_matches(f.backend, filter)) return false;
    if (!vector_contains_ci(f.domains, filter.domain)) return false;
    if (!vector_contains_ci(f.extensions, filter.extension)) return false;
    if (!filter.category.empty() &&
        !vector_contains_ci(f.categories, filter.category) &&
        !equals_ci(f.role, filter.category)) return false;
    if (!filter.role.empty() && !equals_ci(f.role, filter.role)) return false;
    if (filter.function && f.function != *filter.function) return false;
    if (filter.api.empty()) return true;
    return std::ranges::any_of(f.evidence, [&](const std::string& e) {
        return contains_ci(e, filter.api);
    });
}

[[nodiscard]] bool matches_graphics_symbol(const GraphicsSymbolFact& s,
                                           const GraphicsOutputFilter& filter) {
    if (!backend_matches(s.backend, filter)) return false;
    if (!filter.domain.empty() && !equals_ci(s.domain, filter.domain)) return false;
    if (!filter.extension.empty() && !equals_ci(s.api_extension, filter.extension)) return false;
    if (!filter.category.empty() && !equals_ci(s.category, filter.category)) return false;
    if (filter.function && s.addr != *filter.function) return false;
    if (filter.api.empty()) return true;
    return contains_ci(s.api_name, filter.api) ||
           contains_ci(s.canonical_api_name, filter.api) ||
           contains_ci(s.name, filter.api);
}

[[nodiscard]] bool matches_graphics_string(const GraphicsStringFact& s,
                                           const GraphicsOutputFilter& filter) {
    if (!backend_matches(s.backend, filter)) return false;
    if (!filter.domain.empty() && !equals_ci(s.domain, filter.domain)) return false;
    if (!filter.extension.empty() && !equals_ci(s.api_extension, filter.extension)) return false;
    if (!filter.category.empty() && !equals_ci(s.category, filter.category)) return false;
    if (filter.function && !vector_contains_addr(s.functions, *filter.function)) return false;
    if (filter.api.empty()) return true;
    return contains_ci(s.api_name, filter.api) ||
           contains_ci(s.canonical_api_name, filter.api) ||
           contains_ci(s.text, filter.api);
}

}  // namespace

}  // namespace ember::cli::builders

namespace ember::cli {

using namespace builders;

std::string build_graphics_output(const Binary& b, bool json,
                                  const GraphicsOutputFilter& filter) {
    const auto g = analyze_graphics_surface(b);
    std::string out;
    std::map<GraphicsBackend, std::set<addr_t>> role_functions;
    const bool role_active = !filter.role.empty();
    if (role_active) {
        for (const auto& f : g.functions) {
            if (equals_ci(f.role, filter.role)) role_functions[f.backend].insert(f.function);
        }
    }
    const auto summaries = filtered_ptrs(g.summaries, [&](const auto& row) {
        return row_type_matches(filter, "summary") &&
               matches_graphics_summary(row, filter);
    });
    const auto apis = filtered_ptrs(g.apis, [&](const auto& row) {
        return row_type_matches(filter, "api") &&
               matches_graphics_api(row, filter) &&
               row_in_role_scope(row.functions, row.backend, role_active, role_functions);
    });
    const auto extensions = filtered_ptrs(g.extensions, [&](const auto& row) {
        return row_type_matches(filter, "extension") &&
               matches_graphics_extension(row, filter) &&
               row_in_role_scope(row.functions, row.backend, role_active, role_functions);
    });
    const auto functions = filtered_ptrs(g.functions, [&](const auto& row) {
        return row_type_matches(filter, "function") &&
               matches_graphics_function(row, filter);
    });
    const auto symbols = filtered_ptrs(g.symbols, [&](const auto& row) {
        std::vector<addr_t> symbol_functions;
        if (row.addr != 0) symbol_functions.push_back(row.addr);
        return row_type_matches(filter, "symbol") &&
               matches_graphics_symbol(row, filter) &&
               row_in_role_scope(symbol_functions, row.backend, role_active, role_functions);
    });
    const auto strings = filtered_ptrs(g.strings, [&](const auto& row) {
        return row_type_matches(filter, "string") &&
               matches_graphics_string(row, filter) &&
               row_in_role_scope(row.functions, row.backend, role_active, role_functions);
    });

    auto join_plain = [](const std::vector<std::string>& values) {
        std::string joined;
        for (std::size_t i = 0; i < values.size(); ++i) {
            if (i > 0) joined += ",";
            joined += escape_for_line(values[i]);
        }
        return joined;
    };
    auto join_evidence = [](const std::vector<std::string>& evidence) {
        std::string joined;
        for (std::size_t i = 0; i < evidence.size(); ++i) {
            if (i > 0) joined += " || ";
            joined += escape_for_line(evidence[i]);
        }
        return joined;
    };
    auto join_xrefs = [](const std::vector<addr_t>& xrefs) {
        std::string joined;
        for (std::size_t i = 0; i < xrefs.size(); ++i) {
            if (i > 0) joined += ",";
            joined += std::format("{:#x}", xrefs[i]);
        }
        return joined;
    };
    auto json_string_array = [](const std::vector<std::string>& values) {
        std::string joined = "[";
        for (std::size_t i = 0; i < values.size(); ++i) {
            if (i > 0) joined += ",";
            joined += std::format("\"{}\"", json_escape(values[i]));
        }
        joined += "]";
        return joined;
    };
    auto json_addr_array = [](const std::vector<addr_t>& values) {
        std::string joined = "[";
        for (std::size_t i = 0; i < values.size(); ++i) {
            if (i > 0) joined += ",";
            joined += std::format("\"{:#x}\"", values[i]);
        }
        joined += "]";
        return joined;
    };

    if (json) {
        out += "{\"summaries\":[";
        for (std::size_t i = 0; i < summaries.size(); ++i) {
            if (i > 0) out += ",";
            const auto& s = *summaries[i];
            out += std::format(
                "{{\"backend\":\"{}\",\"strings\":{},\"symbols\":{},\"functions\":{},"
                "\"api_names\":{},\"domains\":{},\"evidence\":{}}}",
                graphics_backend_name(s.backend), s.string_count, s.symbol_count,
                s.function_count, s.api_name_count, json_string_array(s.domains),
                json_string_array(s.evidence));
        }
        out += "],\"apis\":[";
        for (std::size_t i = 0; i < apis.size(); ++i) {
            if (i > 0) out += ",";
            const auto& a = *apis[i];
            out += std::format(
                "{{\"backend\":\"{}\",\"api\":\"{}\",\"variants\":{},"
                "\"extensions\":{},\"domains\":{},\"categories\":{},"
                "\"strings\":{},\"symbols\":{},\"xrefs\":{},"
                "\"functions\":{},\"string_addrs\":{},\"xref_addrs\":{},"
                "\"function_addrs\":{},\"symbol_names\":{}}}",
                graphics_backend_name(a.backend), json_escape(a.api_name),
                json_string_array(a.variants), json_string_array(a.extensions),
                json_string_array(a.domains), json_string_array(a.categories),
                a.string_count, a.symbol_count, a.xref_count, a.function_count,
                json_addr_array(a.strings), json_addr_array(a.xrefs),
                json_addr_array(a.functions), json_string_array(a.symbols));
        }
        out += "],\"extensions\":[";
        for (std::size_t i = 0; i < extensions.size(); ++i) {
            if (i > 0) out += ",";
            const auto& e = *extensions[i];
            out += std::format(
                "{{\"backend\":\"{}\",\"extension\":\"{}\",\"apis\":{},"
                "\"variants\":{},\"domains\":{},\"categories\":{},"
                "\"api_count\":{},\"variant_count\":{},\"strings\":{},"
                "\"symbols\":{},\"xrefs\":{},\"functions\":{},"
                "\"string_addrs\":{},\"xref_addrs\":{},\"function_addrs\":{},"
                "\"symbol_names\":{}}}",
                graphics_backend_name(e.backend), json_escape(e.extension),
                json_string_array(e.apis), json_string_array(e.variants),
                json_string_array(e.domains), json_string_array(e.categories),
                e.api_count, e.variant_count, e.string_count, e.symbol_count,
                e.xref_count, e.function_count, json_addr_array(e.strings),
                json_addr_array(e.xrefs), json_addr_array(e.functions),
                json_string_array(e.symbols));
        }
        out += "],\"functions\":[";
        for (std::size_t i = 0; i < functions.size(); ++i) {
            if (i > 0) out += ",";
            const auto& f = *functions[i];
            out += std::format(
                "{{\"backend\":\"{}\",\"role\":\"{}\",\"addr\":\"{:#x}\","
                "\"strings\":{},\"symbols\":{},\"api_names\":{},"
                "\"extensions\":{},\"categories\":{},\"domains\":{},\"evidence\":{}}}",
                graphics_backend_name(f.backend), json_escape(f.role), f.function,
                f.string_count, f.symbol_count, f.api_name_count,
                json_string_array(f.extensions), json_string_array(f.categories),
                json_string_array(f.domains), json_string_array(f.evidence));
        }
        out += "],\"symbols\":[";
        for (std::size_t i = 0; i < symbols.size(); ++i) {
            if (i > 0) out += ",";
            const auto& s = *symbols[i];
            out += std::format(
                "{{\"backend\":\"{}\",\"category\":\"{}\",\"domain\":\"{}\","
                "\"addr\":\"{:#x}\",\"got\":\"{:#x}\",\"api\":\"{}\","
                "\"canonical_api\":\"{}\",\"extension\":\"{}\","
                "\"linkage\":\"{}\",\"name\":\"{}\"}}",
                graphics_backend_name(s.backend), json_escape(s.category),
                json_escape(s.domain), s.addr, s.got_addr, json_escape(s.api_name),
                json_escape(s.canonical_api_name), json_escape(s.api_extension),
                json_escape(s.linkage), json_escape(s.name));
        }
        out += "],\"strings\":[";
        for (std::size_t i = 0; i < strings.size(); ++i) {
            if (i > 0) out += ",";
            const auto& s = *strings[i];
            out += std::format(
                "{{\"backend\":\"{}\",\"category\":\"{}\",\"domain\":\"{}\","
                "\"addr\":\"{:#x}\",\"api\":\"{}\",\"canonical_api\":\"{}\","
                "\"extension\":\"{}\",\"xrefs\":{},\"functions\":{},\"text\":\"{}\"}}",
                graphics_backend_name(s.backend), json_escape(s.category),
                json_escape(s.domain), s.addr, json_escape(s.api_name),
                json_escape(s.canonical_api_name), json_escape(s.api_extension),
                json_addr_array(s.xrefs), json_addr_array(s.functions),
                json_escape(s.text));
        }
        out += "]}\n";
        return out;
    }

    for (const auto* sp : summaries) {
        const auto& s = *sp;
        out += std::format("summary\t{}\tstrings={}\tsymbols={}\tfunctions={}\tapi_names={}\tdomains={}\t{}\n",
                           graphics_backend_name(s.backend), s.string_count,
                           s.symbol_count, s.function_count, s.api_name_count,
                           join_plain(s.domains),
                           join_evidence(s.evidence));
    }
    for (const auto* ap : apis) {
        const auto& a = *ap;
        out += std::format(
            "api\t{}\t{}\tvariants={}\textensions={}\tdomains={}\tcategories={}\tstrings={}\tsymbols={}\txrefs={}\tfunctions={}\tstring_addrs={}\txref_addrs={}\tfunction_addrs={}\tsymbol_names={}\n",
            graphics_backend_name(a.backend), escape_for_line(a.api_name),
            join_plain(a.variants), join_plain(a.extensions),
            join_plain(a.domains), join_plain(a.categories), a.string_count,
            a.symbol_count, a.xref_count, a.function_count, join_xrefs(a.strings),
            join_xrefs(a.xrefs), join_xrefs(a.functions), join_plain(a.symbols));
    }
    for (const auto* ep : extensions) {
        const auto& e = *ep;
        out += std::format(
            "extension\t{}\t{}\tapis={}\tvariants={}\tstrings={}\tsymbols={}\txrefs={}\tfunctions={}\tdomains={}\tcategories={}\tapi_names={}\tvariant_names={}\tstring_addrs={}\txref_addrs={}\tfunction_addrs={}\tsymbol_names={}\n",
            graphics_backend_name(e.backend), escape_for_line(e.extension),
            e.api_count, e.variant_count, e.string_count, e.symbol_count,
            e.xref_count, e.function_count, join_plain(e.domains),
            join_plain(e.categories), join_plain(e.apis), join_plain(e.variants),
            join_xrefs(e.strings), join_xrefs(e.xrefs), join_xrefs(e.functions),
            join_plain(e.symbols));
    }
    for (const auto* fp : functions) {
        const auto& f = *fp;
        out += std::format("function\t{}\t{}\t{:#x}\tstrings={}\tsymbols={}\tapi_names={}\textensions={}\tcategories={}\tdomains={}\t{}\n",
                           graphics_backend_name(f.backend), f.role, f.function,
                           f.string_count, f.symbol_count, f.api_name_count,
                           join_plain(f.extensions), join_plain(f.categories),
                           join_plain(f.domains),
                           join_evidence(f.evidence));
    }
    for (const auto* sp : symbols) {
        const auto& s = *sp;
        out += std::format("symbol\t{}\t{}\t{}\t{:#x}\tgot={:#x}\tapi={}\tlinkage={}\t{}\n",
                           graphics_backend_name(s.backend), s.category, s.domain,
                           s.addr, s.got_addr,
                           s.api_name.empty() ? "-" : escape_for_line(s.api_name),
                           escape_for_line(s.linkage),
                           s.canonical_api_name.empty()
                               ? escape_for_line(s.name)
                               : std::format("{}\tcanonical={}\text={}",
                                             escape_for_line(s.name),
                                             escape_for_line(s.canonical_api_name),
                                             s.api_extension.empty() ? "-" : escape_for_line(s.api_extension)));
    }
    for (const auto* sp : strings) {
        const auto& s = *sp;
        out += std::format("string\t{}\t{}\t{}\t{:#x}\tapi={}\txrefs={}\tfunctions={}\t{}\n",
                           graphics_backend_name(s.backend), s.category, s.domain, s.addr,
                           s.api_name.empty() ? "-" : escape_for_line(s.api_name),
                           join_xrefs(s.xrefs), join_xrefs(s.functions),
                           s.canonical_api_name.empty()
                               ? escape_for_line(s.text)
                               : std::format("canonical={}\text={}\t{}",
                                             escape_for_line(s.canonical_api_name),
                                             s.api_extension.empty() ? "-" : escape_for_line(s.api_extension),
                                             escape_for_line(s.text)));
    }
    return out;
}

}  // namespace ember::cli
