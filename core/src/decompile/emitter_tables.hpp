#pragma once

#include <optional>
#include <string_view>
#include <string>
#include <vector>

#include <spelunk/common/types.hpp>
#include <spelunk/ir/ir.hpp>

namespace spelunk::emit {

[[nodiscard]] std::optional<u8>
variadic_format_index(std::string_view name) noexcept;

[[nodiscard]] u8
count_printf_specifiers(std::string_view fmt) noexcept;

[[nodiscard]] std::vector<std::string>
printf_argument_types(std::string_view fmt);

[[nodiscard]] std::optional<u8>
libc_arity_by_name(std::string_view name) noexcept;

[[nodiscard]] bool
import_returns_void(std::string_view name) noexcept;

[[nodiscard]] std::string_view
c_type_name(IrType t) noexcept;

}  // namespace spelunk::emit
