#pragma once

#include <cstddef>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include <ember/binary/binary.hpp>
#include <ember/common/error.hpp>

namespace ember {

// Loader for Microsoft minidump (.dmp) files. The minidump captures a
// snapshot of a running process — its mapped pages, loaded modules,
// thread contexts, exception state. For static analysis we only consume:
//
//   * SystemInfoStream  (7) — CPU arch.
//   * Memory64ListStream (9) preferred, else MemoryListStream (5) — the
//     mapped pages, indexed by VA. These drive bytes_at().
//   * MemoryInfoListStream (16) optional — page protection flags.
//   * ModuleListStream  (4) — loaded modules (A2 will recover symbols
//     from their in-memory PE headers).
//
// All other streams are ignored. Phase A1 covers everything except the
// per-module symbol recovery, which is A2.
class MinidumpBinary final : public Binary {
public:
    [[nodiscard]] static Result<std::unique_ptr<MinidumpBinary>>
    load_from_buffer(std::vector<std::byte> buffer);

    [[nodiscard]] Format format() const noexcept override { return Format::Minidump; }
    [[nodiscard]] Arch   arch() const noexcept   override { return arch_; }
    [[nodiscard]] Endian endian() const noexcept override { return Endian::Little; }
    [[nodiscard]] addr_t entry_point() const noexcept override { return entry_; }

    [[nodiscard]] std::span<const Section> sections() const noexcept override { return sections_; }
    [[nodiscard]] std::span<const Symbol>  symbols() const noexcept  override { return symbols_; }
    [[nodiscard]] std::span<const std::byte> image() const noexcept  override { return buffer_; }

    // Override the default sections() walk: minidumps can contain
    // hundreds of memory ranges and we have a sorted index for O(log N)
    // lookup. Empty span when `vaddr` is outside every dumped range.
    [[nodiscard]] std::span<const std::byte>
    bytes_at(addr_t vaddr) const noexcept override;

private:
    explicit MinidumpBinary(std::vector<std::byte> buffer) noexcept
        : buffer_(std::move(buffer)) {}

    [[nodiscard]] Result<void> parse();

    // One mapped memory range from Memory{,64}ListStream. `file_off` is
    // the absolute offset into `buffer_` where the range's bytes live.
    struct Range {
        addr_t       vaddr    = 0;
        u64          size     = 0;
        std::size_t  file_off = 0;
        SectionFlags flags    = {};   // from MemoryInfoListStream when present
    };

    std::vector<std::byte> buffer_;
    Arch                   arch_  = Arch::Unknown;
    addr_t                 entry_ = 0;
    std::vector<Range>     ranges_;     // sorted by vaddr; non-overlapping
    std::vector<Section>   sections_;   // mirrors ranges_, one Section each
    std::vector<Symbol>    symbols_;    // empty in A1; A2 fills this
};

}  // namespace ember
