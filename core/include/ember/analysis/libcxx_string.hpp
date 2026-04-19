#pragma once

#include <optional>
#include <string>

#include <ember/binary/binary.hpp>
#include <ember/common/types.hpp>

namespace ember {

// Decode a libc++ std::string object stored at `va` and return its contents.
// Handles both the short-string (inline 22 chars) and long-string
// (heap-allocated) layouts used by Apple's libc++ ABI 1 (no alt-layout).
// Returns nullopt when the bytes at `va` don't look like a valid string
// object (non-ASCII, impossible size, unreadable data pointer).
[[nodiscard]] std::optional<std::string>
decode_libcxx_string(const Binary& b, addr_t va);

}  // namespace ember
