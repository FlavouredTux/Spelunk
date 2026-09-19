#pragma once

#include <map>
#include <string>

#include <spelunk/common/annotations.hpp>
#include <spelunk/common/types.hpp>

namespace spelunk {

class Binary;

struct DwarfFunctionInfo {
    std::string name;
    FunctionSig signature;
    u64 size = 0;
};

// Best-effort DWARF v4/v5 .debug_info reader. It intentionally focuses on
// subprogram signatures, callback typedefs and constant-offset struct fields; malformed or
// unsupported DIEs are skipped without making the containing binary unloadable.
[[nodiscard]] std::map<addr_t, DwarfFunctionInfo>
parse_dwarf_functions(const Binary& binary, Annotations* types = nullptr);

}  // namespace spelunk
