// App-surface report filtering, rendering and output dispatch.

#include <algorithm>
#include <cctype>
#include <format>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <spelunk/analysis/app_surface.hpp>
#include <spelunk/analysis/graphics.hpp>
#include <spelunk/binary/binary.hpp>
#include <spelunk/common/types.hpp>

#include "builders.hpp"
#include "builders_internal.hpp"
#include "builders_surfaces_internal.hpp"
#include "util.hpp"

namespace spelunk::cli::builders {

namespace {

[[nodiscard]] std::string lower_ascii(std::string_view text) {
    std::string out(text);
    for (char& c : out) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return out;
}

[[nodiscard]] bool surface_summary_wanted(const SurfaceOutputFilter& filter) {
    return filter.row_type.empty() || equals_ci(filter.row_type, "summary") ||
           equals_ci(filter.row_type, "all");
}

[[nodiscard]] bool surface_function_wanted(const SurfaceOutputFilter& filter) {
    return equals_ci(filter.row_type, "function") || equals_ci(filter.row_type, "all");
}

[[nodiscard]] bool surface_evidence_wanted(const SurfaceOutputFilter& filter) {
    return equals_ci(filter.row_type, "evidence") || equals_ci(filter.row_type, "all");
}

[[nodiscard]] bool surface_category_wanted(const SurfaceOutputFilter& filter) {
    return equals_ci(filter.row_type, "category") || equals_ci(filter.row_type, "all");
}

[[nodiscard]] bool surface_artifact_wanted(const SurfaceOutputFilter& filter) {
    return equals_ci(filter.row_type, "artifact") || equals_ci(filter.row_type, "all");
}

[[nodiscard]] bool surface_owner_wanted(const SurfaceOutputFilter& filter) {
    return equals_ci(filter.row_type, "owner") || equals_ci(filter.row_type, "all");
}

[[nodiscard]] bool surface_descriptor_wanted(const SurfaceOutputFilter& filter) {
    return equals_ci(filter.row_type, "descriptor") || equals_ci(filter.row_type, "all");
}

[[nodiscard]] bool surface_name_matches(std::string_view subsystem,
                                        const SurfaceOutputFilter& filter) {
    return filter.subsystem.empty() || equals_ci(subsystem, filter.subsystem);
}

[[nodiscard]] bool surface_category_matches(const std::vector<std::string>& categories,
                                            const SurfaceOutputFilter& filter) {
    return filter.category.empty() || vector_contains_ci(categories, filter.category);
}

[[nodiscard]] bool matches_surface_summary(const AppSurfaceSummary& s,
                                           const SurfaceOutputFilter& filter) {
    if (!surface_summary_wanted(filter)) return false;
    if (!filter.owner.empty()) return false;
    if (!surface_name_matches(s.subsystem, filter)) return false;
    if (!surface_category_matches(s.categories, filter)) return false;
    return filter.kind.empty() && !filter.function;
}

[[nodiscard]] bool matches_surface_function(const AppSurfaceFunction& f,
                                            const SurfaceOutputFilter& filter) {
    if (!surface_function_wanted(filter)) return false;
    if (!filter.owner.empty()) return false;
    if (!surface_name_matches(f.subsystem, filter)) return false;
    if (!surface_category_matches(f.categories, filter)) return false;
    if (filter.function && f.function != *filter.function) return false;
    return filter.kind.empty();
}

[[nodiscard]] bool matches_surface_evidence(const AppSurfaceEvidence& e,
                                            const SurfaceOutputFilter& filter) {
    if (!surface_evidence_wanted(filter)) return false;
    if (!surface_name_matches(e.subsystem, filter)) return false;
    if (!filter.kind.empty() && !equals_ci(e.kind, filter.kind)) return false;
    if (!filter.category.empty() && !equals_ci(e.category, filter.category)) return false;
    if (filter.function && !vector_contains_addr(e.functions, *filter.function)) return false;
    return true;
}

[[nodiscard]] bool matches_surface_evidence_scope(const AppSurfaceEvidence& e,
                                                  const SurfaceOutputFilter& filter) {
    if (!surface_name_matches(e.subsystem, filter)) return false;
    if (!filter.kind.empty() && !equals_ci(e.kind, filter.kind)) return false;
    if (!filter.category.empty() && !equals_ci(e.category, filter.category)) return false;
    if (filter.function && !vector_contains_addr(e.functions, *filter.function)) return false;
    return true;
}

[[nodiscard]] bool surface_owner_matches(const AppSurfaceEvidence& evidence,
                                         const SurfaceOutputFilter& filter) {
    if (filter.owner.empty()) return true;
    if (!equals_ci(evidence.kind, "reflection_descriptor")) return false;
    const auto fields = parse_reflection_descriptor_fields(evidence.text);
    return fields && equals_ci(fields->owner, filter.owner);
}

[[nodiscard]] std::vector<const AppSurfaceEvidence*>
filter_surface_owner_evidence(std::vector<const AppSurfaceEvidence*> evidence,
                              const SurfaceOutputFilter& filter) {
    if (filter.owner.empty()) return evidence;
    std::erase_if(evidence, [&](const AppSurfaceEvidence* row) {
        return row == nullptr || !surface_owner_matches(*row, filter);
    });
    return evidence;
}

}  // namespace

bool contains_ci(std::string_view haystack, std::string_view needle) {
    if (needle.empty()) return true;
    return lower_ascii(haystack).find(lower_ascii(needle)) != std::string::npos;
}

bool equals_ci(std::string_view lhs, std::string_view rhs) {
    return lower_ascii(lhs) == lower_ascii(rhs);
}

bool vector_contains_ci(const std::vector<std::string>& values,
                                      std::string_view needle) {
    if (needle.empty()) return true;
    return std::ranges::any_of(values, [&](const std::string& value) {
        return equals_ci(value, needle);
    });
}

bool vector_contains_substring_ci(const std::vector<std::string>& values,
                                                std::string_view needle) {
    if (needle.empty()) return true;
    return std::ranges::any_of(values, [&](const std::string& value) {
        return contains_ci(value, needle);
    });
}

bool vector_contains_addr(const std::vector<addr_t>& values, addr_t needle) {
    return std::ranges::find(values, needle) != values.end();
}

bool row_in_role_scope(const std::vector<addr_t>& functions,
                                     GraphicsBackend backend,
                                     bool role_active,
                                     const std::map<GraphicsBackend, std::set<addr_t>>& role_functions) {
    if (!role_active) return true;
    const auto it = role_functions.find(backend);
    if (it == role_functions.end() || it->second.empty()) return false;
    return std::ranges::any_of(functions, [&](addr_t fn) {
        return it->second.contains(fn);
    });
}

bool backend_matches(GraphicsBackend backend,
                                   const GraphicsOutputFilter& filter) {
    return filter.backend.empty() ||
           equals_ci(graphics_backend_name(backend), filter.backend);
}

bool row_type_matches(const GraphicsOutputFilter& filter,
                                    std::string_view row_type) {
    return filter.row_type.empty() || equals_ci(filter.row_type, row_type);
}

}  // namespace spelunk::cli::builders

namespace spelunk::cli {

using namespace builders;

[[nodiscard]] std::string format_surfaces_output(const AppSurfaceAnalysis& analysis,
                                                 bool json,
                                                 const SurfaceOutputFilter& filter) {
    const auto summaries = filtered_ptrs(analysis.summaries, [&](const auto& row) {
        return matches_surface_summary(row, filter);
    });
    const auto functions = filtered_ptrs(analysis.functions, [&](const auto& row) {
        return matches_surface_function(row, filter);
    });
    auto category_evidence = filtered_ptrs(analysis.evidence, [&](const auto& row) {
        return matches_surface_evidence_scope(row, filter);
    });
    category_evidence = filter_surface_owner_evidence(std::move(category_evidence), filter);
    const auto categories = surface_category_wanted(filter)
        ? build_surface_category_rows(category_evidence)
        : std::vector<SurfaceCategoryRow>{};
    const auto owners = surface_owner_wanted(filter)
        ? build_surface_owner_rows(category_evidence)
        : std::vector<SurfaceOwnerRow>{};
    const auto descriptors = surface_descriptor_wanted(filter)
        ? build_surface_descriptor_rows(category_evidence)
        : std::vector<SurfaceDescriptorRow>{};
    const auto artifacts = surface_artifact_wanted(filter)
        ? build_surface_artifact_rows(category_evidence)
        : std::vector<SurfaceArtifactRow>{};
    auto evidence = filtered_ptrs(analysis.evidence, [&](const auto& row) {
        return matches_surface_evidence(row, filter);
    });
    evidence = filter_surface_owner_evidence(std::move(evidence), filter);

    auto join_plain = [](const std::vector<std::string>& values) {
        std::string joined;
        for (std::size_t i = 0; i < values.size(); ++i) {
            if (i > 0) joined += ",";
            joined += escape_for_line(values[i]);
        }
        return joined;
    };
    auto join_evidence = [](const std::vector<std::string>& values) {
        std::string joined;
        for (std::size_t i = 0; i < values.size(); ++i) {
            if (i > 0) joined += " || ";
            joined += escape_for_line(values[i]);
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

    std::string out;
    if (json) {
        out += "{\"summaries\":[";
        for (std::size_t i = 0; i < summaries.size(); ++i) {
            if (i > 0) out += ",";
            const auto& s = *summaries[i];
            out += std::format(
                "{{\"subsystem\":\"{}\",\"strings\":{},\"symbols\":{},"
                "\"artifacts\":{},\"objc_methods\":{},\"rtti_classes\":{},\"log_categories\":{},"
                "\"functions\":{},\"categories\":{},\"evidence\":{}}}",
                json_escape(s.subsystem), s.string_count, s.symbol_count, s.artifact_count,
                s.objc_method_count, s.rtti_class_count, s.log_category_count,
                s.function_count, json_string_array(s.categories),
                json_string_array(s.evidence));
        }
        out += "],\"functions\":[";
        for (std::size_t i = 0; i < functions.size(); ++i) {
            if (i > 0) out += ",";
            const auto& f = *functions[i];
            out += std::format(
                "{{\"subsystem\":\"{}\",\"addr\":\"{:#x}\",\"evidence\":{},"
                "\"categories\":{},\"examples\":{}}}",
                json_escape(f.subsystem), f.function, f.evidence_count,
                json_string_array(f.categories), json_string_array(f.evidence));
        }
        out += "],\"categories\":[";
        for (std::size_t i = 0; i < categories.size(); ++i) {
            if (i > 0) out += ",";
            const auto& c = categories[i];
            out += std::format(
                "{{\"subsystem\":\"{}\",\"category\":\"{}\",\"evidence\":{},"
                "\"strings\":{},\"artifacts\":{},\"symbols\":{},\"objc_methods\":{},"
                "\"rtti_classes\":{},\"log_categories\":{},\"functions\":{},"
                "\"kinds\":{},\"examples\":{}}}",
                json_escape(c.subsystem), json_escape(c.category), c.evidence_count,
                c.string_count, c.artifact_count, c.symbol_count,
                c.objc_method_count, c.rtti_class_count, c.log_category_count,
                c.function_count, json_string_array(c.kinds),
                json_string_array(c.examples));
        }
        out += "],\"owners\":[";
        for (std::size_t i = 0; i < owners.size(); ++i) {
            if (i > 0) out += ",";
            const auto& o = owners[i];
            out += std::format(
                "{{\"subsystem\":\"{}\",\"owner\":\"{}\",\"descriptors\":{},"
                "\"bound_functions\":{},\"yield_functions\":{},\"properties\":{},"
                "\"events\":{},\"remote_events\":{},\"enums\":{},\"types\":{},"
                "\"other\":{},\"functions\":{},\"categories\":{},\"arities\":{},"
                "\"examples\":{}}}",
                json_escape(o.subsystem), json_escape(o.owner), o.descriptor_count,
                o.bound_function_count, o.yield_function_count, o.property_count,
                o.event_count, o.remote_event_count, o.enum_count, o.type_count,
                o.other_count, o.function_count, json_string_array(o.categories),
                json_string_array(o.arities), json_string_array(o.examples));
        }
        out += "],\"descriptors\":[";
        for (std::size_t i = 0; i < descriptors.size(); ++i) {
            if (i > 0) out += ",";
            const auto& d = descriptors[i];
            out += std::format(
                "{{\"subsystem\":\"{}\",\"owner\":\"{}\",\"kind\":\"{}\","
                "\"category\":\"{}\",\"arity\":\"{}\",\"addr\":\"{:#x}\","
                "\"signature\":\"{}\",\"xrefs\":{},\"functions\":{},\"type\":\"{}\"}}",
                json_escape(d.subsystem), json_escape(d.owner),
                json_escape(d.descriptor_kind), json_escape(d.category),
                json_escape(d.arity), d.addr, json_escape(d.signature),
                json_addr_array(d.xrefs), json_addr_array(d.functions),
                json_escape(d.type));
        }
        out += "],\"artifacts\":[";
        for (std::size_t i = 0; i < artifacts.size(); ++i) {
            if (i > 0) out += ",";
            const auto& a = artifacts[i];
            out += std::format(
                "{{\"path\":\"{}\",\"matches\":{},\"subsystems\":{},\"categories\":{}}}",
                json_escape(a.path), a.match_count, json_string_array(a.subsystems),
                json_string_array(a.categories));
        }
        out += "],\"evidence\":[";
        for (std::size_t i = 0; i < evidence.size(); ++i) {
            if (i > 0) out += ",";
            const auto& e = *evidence[i];
            out += std::format(
                "{{\"subsystem\":\"{}\",\"kind\":\"{}\",\"category\":\"{}\","
                "\"addr\":\"{:#x}\",\"xrefs\":{},\"functions\":{},\"text\":\"{}\"}}",
                json_escape(e.subsystem), json_escape(e.kind),
                json_escape(e.category), e.addr, json_addr_array(e.xrefs),
                json_addr_array(e.functions), json_escape(e.text));
        }
        out += "]}\n";
        return out;
    }

    for (const auto* sp : summaries) {
        const auto& s = *sp;
        out += std::format(
            "summary\t{}\tstrings={}\tartifacts={}\tsymbols={}\tobjc_methods={}\trtti_classes={}\tlog_categories={}\tfunctions={}\tcategories={}\t{}\n",
            escape_for_line(s.subsystem), s.string_count, s.artifact_count, s.symbol_count,
            s.objc_method_count, s.rtti_class_count, s.log_category_count,
            s.function_count, join_plain(s.categories), join_evidence(s.evidence));
    }
    for (const auto* fp : functions) {
        const auto& f = *fp;
        out += std::format(
            "function\t{}\t{:#x}\tevidence={}\tcategories={}\t{}\n",
            escape_for_line(f.subsystem), f.function, f.evidence_count,
            join_plain(f.categories), join_evidence(f.evidence));
    }
    for (const auto& c : categories) {
        out += std::format(
            "category\t{}\t{}\tevidence={}\tstrings={}\tartifacts={}\tsymbols={}\tobjc_methods={}\trtti_classes={}\tlog_categories={}\tfunctions={}\tkinds={}\t{}\n",
            escape_for_line(c.subsystem), escape_for_line(c.category),
            c.evidence_count, c.string_count, c.artifact_count, c.symbol_count,
            c.objc_method_count, c.rtti_class_count, c.log_category_count,
            c.function_count, join_plain(c.kinds), join_evidence(c.examples));
    }
    for (const auto& o : owners) {
        out += std::format(
            "owner\t{}\t{}\tdescriptors={}\tbound_functions={}\tyield_functions={}\tproperties={}\tevents={}\tremote_events={}\tenums={}\ttypes={}\tother={}\tfunctions={}\tarities={}\tcategories={}\t{}\n",
            escape_for_line(o.subsystem), escape_for_line(o.owner),
            o.descriptor_count, o.bound_function_count, o.yield_function_count,
            o.property_count, o.event_count, o.remote_event_count, o.enum_count,
            o.type_count, o.other_count, o.function_count, join_plain(o.arities),
            join_plain(o.categories), join_evidence(o.examples));
    }
    for (const auto& d : descriptors) {
        out += std::format(
            "descriptor\t{}\t{}\t{}\t{}\t{:#x}\targc={}\tsig={}\txrefs={}\tfunctions={}\t{}\n",
            escape_for_line(d.subsystem), escape_for_line(d.owner),
            escape_for_line(d.descriptor_kind), escape_for_line(d.category),
            d.addr, escape_for_line(d.arity), escape_for_line(d.signature),
            join_xrefs(d.xrefs), join_xrefs(d.functions), escape_for_line(d.type));
    }
    for (const auto& a : artifacts) {
        out += std::format(
            "artifact\t{}\tmatches={}\tsubsystems={}\tcategories={}\n",
            escape_for_line(a.path), a.match_count,
            join_plain(a.subsystems), join_plain(a.categories));
    }
    for (const auto* ep : evidence) {
        const auto& e = *ep;
        out += std::format(
            "evidence\t{}\t{}\t{}\t{:#x}\txrefs={}\tfunctions={}\t{}\n",
            escape_for_line(e.subsystem), escape_for_line(e.kind),
            escape_for_line(e.category), e.addr, join_xrefs(e.xrefs),
            join_xrefs(e.functions), escape_for_line(e.text));
    }
    return out;
}

std::string build_surfaces_output(const Binary& b, bool json,
                                  const SurfaceOutputFilter& filter) {
    const bool reflection_only =
        equals_ci(filter.subsystem, "reflection_metadata") &&
        (filter.kind.empty() || equals_ci(filter.kind, "reflection_descriptor"));
    const bool artifact_rows_only =
        equals_ci(filter.row_type, "artifact") &&
        filter.owner.empty() &&
        (filter.kind.empty() || equals_ci(filter.kind, "bundle_file"));
    const bool artifacts_only = !filter.function &&
                                filter.owner.empty() &&
                                (artifact_rows_only ||
                                 (equals_ci(filter.kind, "bundle_file") &&
                                  (equals_ci(filter.row_type, "evidence") ||
                                   equals_ci(filter.row_type, "category") ||
                                   equals_ci(filter.row_type, "all"))));
    if (artifacts_only) {
        return build_surface_artifacts_output(filter.artifacts, json, filter);
    }

    AppSurfaceOptions options;
    options.artifact_strings = filter.artifacts;
    options.reflection_only = reflection_only;
    const auto analysis = analyze_app_surfaces(b, options);
    return format_surfaces_output(analysis, json, filter);
}

std::string build_surface_artifacts_output(const std::vector<std::string>& artifacts,
                                           bool json,
                                           const SurfaceOutputFilter& filter) {
    const auto analysis = analyze_app_surface_artifacts(artifacts);
    return format_surfaces_output(analysis, json, filter);
}

}  // namespace spelunk::cli
