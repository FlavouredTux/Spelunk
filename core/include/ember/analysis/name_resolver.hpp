#pragma once

#include <optional>
#include <string>

#include <ember/common/types.hpp>

namespace ember {

class Binary;

enum class ResolvedNameKind {
    Function,
    Object,
    Import,
    Got,
};

struct ResolvedName {
    std::string      name;
    addr_t           base = 0;
    addr_t           addr = 0;
    ResolvedNameKind kind = ResolvedNameKind::Function;
};

[[nodiscard]] std::optional<ResolvedName>
resolve_address_name(const Binary& b, addr_t addr);

[[nodiscard]] std::string
format_address_comment(const ResolvedName& r);

[[nodiscard]] std::string
format_address_expr(const ResolvedName& r);

}  // namespace ember
