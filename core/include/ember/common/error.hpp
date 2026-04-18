#pragma once

#include <expected>
#include <string>
#include <string_view>
#include <utility>

namespace ember {

enum class ErrorKind {
    Io,
    InvalidFormat,
    UnsupportedFormat,
    OutOfBounds,
    Truncated,
    NotImplemented,
};

struct Error {
    ErrorKind   kind;
    std::string message;

    static Error io(std::string m)             { return {ErrorKind::Io, std::move(m)}; }
    static Error invalid_format(std::string m) { return {ErrorKind::InvalidFormat, std::move(m)}; }
    static Error unsupported(std::string m)    { return {ErrorKind::UnsupportedFormat, std::move(m)}; }
    static Error out_of_bounds(std::string m)  { return {ErrorKind::OutOfBounds, std::move(m)}; }
    static Error truncated(std::string m)      { return {ErrorKind::Truncated, std::move(m)}; }
    static Error not_implemented(std::string m){ return {ErrorKind::NotImplemented, std::move(m)}; }

    [[nodiscard]] constexpr std::string_view kind_name() const noexcept {
        switch (kind) {
            case ErrorKind::Io:                return "io";
            case ErrorKind::InvalidFormat:     return "invalid-format";
            case ErrorKind::UnsupportedFormat: return "unsupported";
            case ErrorKind::OutOfBounds:       return "out-of-bounds";
            case ErrorKind::Truncated:         return "truncated";
            case ErrorKind::NotImplemented:    return "not-implemented";
        }
        return "unknown";
    }
};

template <typename T>
using Result = std::expected<T, Error>;

}  // namespace ember
