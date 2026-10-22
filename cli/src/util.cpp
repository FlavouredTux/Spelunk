#include "util.hpp"

#include <charconv>
#include <cctype>
#include <cerrno>
#include <cmath>
#include <cstdlib>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>

#include <spelunk/common/types.hpp>

namespace spelunk::cli {

std::optional<addr_t> parse_cli_addr(std::string_view s) {
    if (s.starts_with("sub_"))                            s.remove_prefix(4);
    else if (s.starts_with("0x") || s.starts_with("0X"))  s.remove_prefix(2);
    if (s.empty() || s.size() > 16) return std::nullopt;
    for (char c : s) {
        const bool ok = (c >= '0' && c <= '9') ||
                        (c >= 'a' && c <= 'f') ||
                        (c >= 'A' && c <= 'F');
        if (!ok) return std::nullopt;
    }
    u64 v = 0;
    auto r = std::from_chars(s.data(), s.data() + s.size(), v, 16);
    if (r.ec != std::errc{}) return std::nullopt;
    return static_cast<addr_t>(v);
}

std::optional<double> parse_cli_double(std::string_view s) {
    // Not std::from_chars: Apple's libc++ gates its floating-point overload
    // behind macOS 26. strtod reads the "C" locale here (nothing calls
    // setlocale); the checks keep from_chars' strict, decimal-only syntax.
    if (s.empty() || s.front() == '+' || std::isspace(static_cast<unsigned char>(s.front())) ||
        s.find_first_of("xX") != std::string_view::npos) {
        return std::nullopt;
    }
    const std::string text(s);
    char* end = nullptr;
    errno = 0;
    const double value = std::strtod(text.c_str(), &end);
    if (errno == ERANGE || end != text.c_str() + text.size() || !std::isfinite(value)) {
        return std::nullopt;
    }
    return value;
}

std::string json_escape(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 2);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    out += std::format("\\u{:04x}", static_cast<unsigned>(c));
                } else {
                    out += c;
                }
        }
    }
    return out;
}

std::string escape_for_line(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 2);
    for (char c : s) {
        const auto uc = static_cast<unsigned char>(c);
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            case '|':  out += "\\|";  break;
            default:
                if (uc < 0x20 || uc > 0x7e) {
                    out += std::format("\\x{:02x}", uc);
                } else {
                    out += c;
                }
        }
    }
    return out;
}

}  // namespace spelunk::cli
