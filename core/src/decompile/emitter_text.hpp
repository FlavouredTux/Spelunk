#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <spelunk/common/types.hpp>

namespace spelunk::emit {

// Mask literals and comments with spaces, preserving offsets and newlines.
[[nodiscard]] std::string code_only_text(std::string_view text);

[[nodiscard]] std::string_view trim_line_view(std::string_view line) noexcept;
[[nodiscard]] bool is_bb_label_line(std::string_view line) noexcept;
[[nodiscard]] bool line_semantically_empty(std::string_view line) noexcept;
[[nodiscard]] bool c_ident_char(char c) noexcept;
[[nodiscard]] bool text_contains_identifier(std::string_view text,
                                            std::string_view name) noexcept;
[[nodiscard]] bool text_contains_identifier_in_code(std::string_view text,
                                                    std::string_view name) noexcept;
[[nodiscard]] bool line_declares_identifier(std::string_view line,
                                            std::string_view name);
[[nodiscard]] bool text_declares_identifier(std::string_view text,
                                            std::string_view name);
// Replace code tokens only; preserve strings and comments verbatim.
[[nodiscard]] std::string replace_identifier(std::string_view text,
                                             std::string_view old_name,
                                             std::string_view new_name);
// SSA temporaries are useful internally, but `t57` carries no meaning in the
// final decompilation. Give materialized PPC values stable, type-oriented
// names. The numeric suffix is retained only when more than one value of the
// same role is simultaneously live in the rendered function.
[[nodiscard]] std::string rename_ppc_temporaries(std::string text);
[[nodiscard]] std::string fix_ppc_offset_pointer_declarations(std::string text);
// Count statements that subscript or shift-index through an untyped
// pointer. A parameter or declaration spelled `void* name` makes any
// later `name[...]` invalid C - deliberate RE guidance in a listing,
// but worth flagging since everything else around it compiles.
// Casts like `((T*)p)[i]` are already valid and never match.
[[nodiscard]] std::size_t count_untyped_pointer_index_sites(
    const std::string& text);
[[nodiscard]] std::string compact_ppc_type_names(std::string text);
[[nodiscard]] std::string collapse_ppc_field_copy_runs(const std::string& text);
[[nodiscard]] bool line_starts_empty_if(std::string_view line) noexcept;
[[nodiscard]] std::string lower_first_ascii(std::string s);
[[nodiscard]] std::string sanitize_ident(std::string_view s,
                                         std::string_view fallback);
[[nodiscard]] std::vector<std::string>
objc_selector_arg_names(std::string_view selector);
[[nodiscard]] std::string objc_block_literal_name(addr_t literal);
[[nodiscard]] std::string objc_block_invoke_name(addr_t invoke);
[[nodiscard]] std::string block_param_type(std::string_view ty);
[[nodiscard]] bool line_is_close_brace(std::string_view line) noexcept;
[[nodiscard]] bool line_is_else_open(std::string_view line) noexcept;
[[nodiscard]] std::string strip_outer_parens(std::string_view s);
[[nodiscard]] std::string invert_condition_text(std::string_view cond);
[[nodiscard]] std::optional<std::string>
inverted_if_line(std::string_view line);
[[nodiscard]] std::string collapse_empty_then_else_blocks(std::string_view text);
[[nodiscard]] std::string strip_label_only_if_blocks(std::string_view text);

}  // namespace spelunk::emit
