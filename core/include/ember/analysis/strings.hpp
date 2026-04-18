#pragma once

#include <string>
#include <vector>

#include <ember/binary/binary.hpp>
#include <ember/common/types.hpp>

namespace ember {

struct StringEntry {
    addr_t              addr   = 0;
    std::string         text;           // raw contents (unescaped, printable ASCII only)
    std::vector<addr_t> xrefs;          // instruction addresses referencing this string
};

// Scan all non-executable, readable sections for printable NUL-terminated ASCII
// strings of length >= 4. For each string, walk all defined (non-import) function
// symbols and record instructions whose operands reference the string's address
// (either as Relative targets or as Memory/Immediate absolute addresses).
[[nodiscard]] std::vector<StringEntry> scan_strings(const Binary& b);

}  // namespace ember
