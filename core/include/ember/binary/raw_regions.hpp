#pragma once

#include <cstddef>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include <ember/binary/binary.hpp>
#include <ember/common/error.hpp>

namespace ember {

// Loader for hand-rolled memory dumps: a manifest file plus a set of
// raw region `.bin` files. Used by Scylla-style scrape workflows where
// pages were dumped out of a process without a minidump container.
//
// Manifest format — one record per non-blank, non-`#` line:
//
//     <vaddr-hex>  <size-hex>  <flags>  <file-relative-to-manifest>
//
// `flags` is a 3-character permission bitmap matching the section-flag
// renderer (`r--`, `r-x`, `rw-`, `rwx`, ...). Whitespace is one or more
// spaces or tabs.
//
// Example regions.txt:
//     # text + rdata scraped from a running process at 0x140000000
//     0x140000000  0x00400000  r-x  text.bin
//     0x140400000  0x00100000  rw-  rdata.bin
//
// Triggered by `ember --regions PATH/regions.txt`. Bypasses the
// magic-byte loader dispatch in load_binary().
class RawRegionsBinary final : public Binary {
public:
    [[nodiscard]] static Result<std::unique_ptr<RawRegionsBinary>>
    load_from_manifest(const std::filesystem::path& manifest);

    // Convenience for the common single-region case: a runtime memory
    // dump of one contiguous range with no manifest overhead. The
    // resulting binary has one rwx section starting at `base_va`.
    // Triggered by `ember --raw-bytes PATH --base-va 0xVA`.
    [[nodiscard]] static Result<std::unique_ptr<RawRegionsBinary>>
    load_from_raw_bytes(const std::filesystem::path& file, addr_t base_va);

    [[nodiscard]] Format format() const noexcept override { return Format::RawRegions; }
    [[nodiscard]] Arch   arch() const noexcept   override { return Arch::X86_64; }
    [[nodiscard]] Endian endian() const noexcept override { return Endian::Little; }
    [[nodiscard]] addr_t entry_point() const noexcept override { return 0; }

    [[nodiscard]] std::span<const Section> sections() const noexcept override { return sections_; }
    [[nodiscard]] std::span<const Symbol>  symbols() const noexcept  override { return symbols_; }
protected:
    [[nodiscard]] std::vector<Symbol>& mutable_symbols() noexcept override { return symbols_; }
public:
    [[nodiscard]] std::span<const std::byte> image() const noexcept  override { return buffer_; }

    [[nodiscard]] std::span<const std::byte>
    bytes_at(addr_t vaddr) const noexcept override;

private:
    RawRegionsBinary() = default;

    struct Range {
        addr_t      vaddr    = 0;
        u64         size     = 0;
        std::size_t file_off = 0;   // offset into buffer_
        SectionFlags flags   = {};
    };

    // All region bytes concatenated; per-Range file_off indexes into this.
    std::vector<std::byte> buffer_;
    std::vector<Range>     ranges_;
    std::vector<Section>   sections_;
    std::vector<Symbol>    symbols_;   // empty; user supplies via annotations
};

}  // namespace ember
