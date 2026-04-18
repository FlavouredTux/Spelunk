#pragma once

#include <cstddef>
#include <span>
#include <string>

#include <ember/common/types.hpp>

namespace ember {

struct SectionFlags {
    bool readable   : 1 = false;
    bool writable   : 1 = false;
    bool executable : 1 = false;
    bool allocated  : 1 = false;
};

struct Section {
    std::string  name;
    addr_t       vaddr       = 0;
    offset_t     file_offset = 0;
    u64          size        = 0;
    SectionFlags flags       = {};
    std::span<const std::byte> data = {};
};

}  // namespace ember
