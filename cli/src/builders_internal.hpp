#pragma once

// Filter predicates and row types shared by the output builders. Private
// to the builders*.cpp translation units.

#include <map>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include <ember/analysis/graphics.hpp>
#include <ember/common/types.hpp>

#include "builders.hpp"

namespace ember::cli::builders {

[[nodiscard]] bool contains_ci(std::string_view haystack, std::string_view needle);

[[nodiscard]] bool equals_ci(std::string_view lhs, std::string_view rhs);

[[nodiscard]] bool vector_contains_ci(const std::vector<std::string>& values,
                                      std::string_view needle);

[[nodiscard]] bool vector_contains_substring_ci(const std::vector<std::string>& values,
                                                std::string_view needle);

[[nodiscard]] bool vector_contains_addr(const std::vector<addr_t>& values, addr_t needle);

[[nodiscard]] bool row_in_role_scope(const std::vector<addr_t>& functions,
                                     GraphicsBackend backend,
                                     bool role_active,
                                     const std::map<GraphicsBackend, std::set<addr_t>>& role_functions);

[[nodiscard]] bool backend_matches(GraphicsBackend backend,
                                   const GraphicsOutputFilter& filter);

[[nodiscard]] bool row_type_matches(const GraphicsOutputFilter& filter,
                                    std::string_view row_type);

template <class T, class Pred>
[[nodiscard]] std::vector<const T*> filtered_ptrs(const std::vector<T>& rows, Pred pred) {
    std::vector<const T*> out;
    out.reserve(rows.size());
    for (const auto& row : rows) {
        if (pred(row)) out.push_back(&row);
    }
    return out;
}

}  // namespace ember::cli::builders
