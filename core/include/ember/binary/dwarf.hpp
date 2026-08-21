#pragma once

#include <map>
#include <string>

#include <ember/common/annotations.hpp>
#include <ember/common/types.hpp>

namespace ember {

class Binary;

struct DwarfFunctionInfo {
    std::string name;
    FunctionSig signature;
    u64 size = 0;
};

// Best-effort DWARF v4/v5 .debug_info reader. It intentionally focuses on
// source-level subprogram names and signature type chains; malformed or
// unsupported DIEs are skipped without making the containing binary unloadable.
[[nodiscard]] std::map<addr_t, DwarfFunctionInfo>
parse_dwarf_functions(const Binary& binary);

}  // namespace ember
