#pragma once

#include <cstddef>
#include <memory>
#include <span>
#include <vector>

#include <ember/binary/binary.hpp>
#include <ember/common/error.hpp>

namespace ember {

// One ELF PT_LOAD segment: a contiguous region of the process image that
// the loader will map. `data` is the file-backed portion (first `filesz`
// bytes); the `memsz - filesz` tail is zero-initialized at runtime and has
// no file bytes.
struct LoadSegment {
    addr_t                      vaddr  = 0;
    u64                         memsz  = 0;
    u64                         filesz = 0;
    bool                        readable   = false;
    bool                        writable   = false;
    bool                        executable = false;
    std::span<const std::byte>  data;   // subspan of image() of length filesz
};

class ElfBinary final : public Binary {
public:
    [[nodiscard]] static Result<std::unique_ptr<ElfBinary>>
    load_from_buffer(std::vector<std::byte> buffer);

    [[nodiscard]] Format format() const noexcept override { return Format::Elf; }
    [[nodiscard]] Arch   arch() const noexcept   override { return arch_;  }
    [[nodiscard]] addr_t entry_point() const noexcept override { return entry_; }

    [[nodiscard]] std::span<const Section> sections() const noexcept override { return sections_; }
    [[nodiscard]] std::span<const Symbol>  symbols() const noexcept  override { return symbols_;  }
    [[nodiscard]] std::span<const std::byte> image() const noexcept  override { return buffer_;   }

    [[nodiscard]] std::span<const LoadSegment> segments() const noexcept { return segments_; }

    // Prefer PT_LOAD segments when resolving virtual addresses to bytes.
    // Falls back to section-table lookup if the file has no program header
    // table. This means a sectionless (stripped-headers) binary still maps
    // correctly as long as it carries a phdr, which every executable ELF does.
    [[nodiscard]] std::span<const std::byte>
    bytes_at(addr_t vaddr) const noexcept override {
        for (const auto& seg : segments_) {
            if (vaddr < seg.vaddr) continue;
            const u64 off = vaddr - seg.vaddr;
            if (off >= seg.memsz) continue;
            if (off >= seg.filesz) return {};  // in BSS tail — no file bytes
            if (seg.data.empty()) continue;
            return seg.data.subspan(static_cast<std::size_t>(off));
        }
        // Fallback: section-table-driven (covers relocatable .o files that
        // have section headers but no program headers).
        return Binary::bytes_at(vaddr);
    }

private:
    explicit ElfBinary(std::vector<std::byte> buffer) noexcept
        : buffer_(std::move(buffer)) {}

    [[nodiscard]] Result<void> parse();

    std::vector<std::byte>    buffer_;
    Arch                      arch_  = Arch::Unknown;
    addr_t                    entry_ = 0;
    std::vector<Section>      sections_;
    std::vector<Symbol>       symbols_;
    std::vector<LoadSegment>  segments_;
};

}  // namespace ember
