#pragma once

#include <cstddef>
#include <span>
#include <string>
#include <vector>

#include <spelunk/common/types.hpp>

namespace spelunk::macho {

// Bind records collected from the LC_DYLD_INFO opcode stream or from the
// modern LC_DYLD_CHAINED_FIXUPS format. Both converge on (slot vaddr,
// imported-symbol name); ordinal, addend, and type do not affect rendering.
struct BindRec {
    addr_t vaddr;
    std::string name;
};

struct ExportRec {
    addr_t vaddr;
    std::string name;
};

// One LC_SEGMENT_64 processed by the loader, used while resolving virtual
// addresses referenced by dyld metadata.
struct SegInfo {
    addr_t vmaddr;
    u64    vmsize;
    u64    fileoff;
    u64    filesize;
    std::string name;
};

[[nodiscard]] u64 read_uleb128(const std::byte*& p,
                               const std::byte* end) noexcept;

[[nodiscard]] u64 macho_image_base(std::span<const SegInfo> segs) noexcept;

void parse_bind_stream(std::span<const std::byte> bytes,
                       std::span<const SegInfo> segs,
                       std::vector<BindRec>& out,
                       bool is_lazy);

void parse_export_trie(std::span<const std::byte> data,
                       u64 image_base,
                       std::vector<ExportRec>& out);

void parse_chained_fixups(std::span<const std::byte> data,
                          std::span<const SegInfo> segs,
                          std::span<std::byte> image,
                          std::vector<BindRec>& out);

}  // namespace spelunk::macho
