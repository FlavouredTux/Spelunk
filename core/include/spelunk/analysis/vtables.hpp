#pragma once

#include <vector>

#include <spelunk/binary/binary.hpp>
#include <spelunk/common/types.hpp>

namespace spelunk {

struct RuntimeVtable {
    addr_t              vaddr = 0;
    std::vector<addr_t> methods;
};

// Find pointer-dense tables in readable, non-executable memory whose slots
// point into executable memory. This intentionally does not require RTTI, so
// it works on loaded Android / PIE dumps where .data.rel.ro already contains
// runtime-relocated function pointers.
[[nodiscard]] std::vector<RuntimeVtable>
discover_runtime_vtables(const Binary& b);

}  // namespace spelunk
