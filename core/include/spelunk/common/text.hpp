#pragma once

#include <cctype>
#include <string_view>

namespace spelunk {

// Strip leading and trailing whitespace as classified by std::isspace.
[[nodiscard]] inline std::string_view trim_space(std::string_view s) noexcept {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) {
        s.remove_prefix(1);
    }
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) {
        s.remove_suffix(1);
    }
    return s;
}

// Parse the locale-independent decimal grammar used for confidence values and
// clamp successful results to [0, 1]. `out` is unchanged on failure.
[[nodiscard]] bool
parse_float_clamped(std::string_view s, float& out) noexcept;

}  // namespace spelunk
