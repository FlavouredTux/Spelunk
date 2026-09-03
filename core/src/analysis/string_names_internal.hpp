#pragma once

// Helpers shared by the string-based function-name inference units.

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace ember::string_names {

[[nodiscard]] bool is_ident_char(char c) noexcept;

[[nodiscard]] std::string sanitize_name(std::string_view s);

[[nodiscard]] std::string_view trim_ascii(std::string_view s) noexcept;

[[nodiscard]] bool has_c_signature_type_cue(std::string_view prefix) noexcept;

[[nodiscard]] bool is_bad_plain_function_name(std::string_view name) noexcept;

[[nodiscard]] std::optional<std::string> operator_suffix_token(std::string_view text,
                                                               std::size_t pos);

[[nodiscard]] std::string normalize_operator_name(std::string_view name);

[[nodiscard]] std::optional<std::string>
c_pretty_function_name(std::string_view text);

[[nodiscard]] std::optional<std::string>
itanium_embedded_function_name_prefix(std::string_view text);

[[nodiscard]] std::optional<std::string>
role_identifier_anchor_name(std::string_view text);

[[nodiscard]] bool is_graphics_api_ident(std::string_view tok) noexcept;

[[nodiscard]] std::optional<std::string>
graphics_api_name_from_string(std::string_view text);

[[nodiscard]] std::optional<std::string>
script_vm_anchor_name_from_string(std::string_view text);

[[nodiscard]] std::optional<std::string>
engine_feature_anchor_name(std::string_view text);

[[nodiscard]] std::optional<std::string>
graphics_phrase_name_from_string(std::string_view text);

}  // namespace ember::string_names
