#pragma once

#include <optional>
#include <string>
#include <string_view>

#include <ember/common/types.hpp>

namespace ember::cli {

// Parse a hex address from the command line. Accepts `0x…`, `0X…`,
// `sub_…`, or plain hex (requires a-f/A-F letter to disambiguate from
// decimal-looking names). Nullopt on malformed input.
[[nodiscard]] std::optional<addr_t> parse_cli_addr(std::string_view s);

// Minimal JSON string-escape — emits a tight, machine-readable form.
[[nodiscard]] std::string json_escape(std::string_view s);

// Escape non-printables and the `|` separator so the strings TSV is
// safely tokenizable downstream (e.g. by the UI).
[[nodiscard]] std::string escape_for_line(std::string_view s);

}  // namespace ember::cli
