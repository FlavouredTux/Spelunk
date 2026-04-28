#pragma once

#include <optional>
#include <string_view>

#include <ember/common/types.hpp>
#include <ember/ir/ir.hpp>

namespace ember::detail {

[[nodiscard]] std::optional<u8>
variadic_format_index(std::string_view name) noexcept;

[[nodiscard]] u8
count_printf_specifiers(std::string_view fmt) noexcept;

[[nodiscard]] std::optional<u8>
libc_arity_by_name(std::string_view name) noexcept;

[[nodiscard]] bool
import_returns_void(std::string_view name) noexcept;

[[nodiscard]] bool
libc_arg_is_charp(std::string_view name, u8 arg_idx_1) noexcept;

[[nodiscard]] std::string_view
c_type_name(IrType t) noexcept;

}  // namespace ember::detail
