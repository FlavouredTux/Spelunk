#pragma once

#include <cstddef>
#include <memory>
#include <span>
#include <vector>

#include <ember/binary/binary.hpp>
#include <ember/binary/elf.hpp>  // for LoadSegment
#include <ember/common/error.hpp>

namespace ember {

class MachOBinary final : public Binary {
public:
    [[nodiscard]] static Result<std::unique_ptr<MachOBinary>>
    load_from_buffer(std::vector<std::byte> buffer);

    [[nodiscard]] Format format() const noexcept override { return Format::MachO; }
    [[nodiscard]] Arch   arch() const noexcept   override { return arch_;  }
    [[nodiscard]] addr_t entry_point() const noexcept override { return entry_; }

    [[nodiscard]] std::span<const Section> sections() const noexcept override { return sections_; }
    [[nodiscard]] std::span<const Symbol>  symbols() const noexcept  override { return symbols_;  }
    [[nodiscard]] std::span<const std::byte> image() const noexcept  override { return buffer_;   }

    [[nodiscard]] std::span<const LoadSegment> segments() const noexcept { return segments_; }

    [[nodiscard]] std::span<const std::byte>
    bytes_at(addr_t vaddr) const noexcept override {
        for (const auto& seg : segments_) {
            if (vaddr < seg.vaddr) continue;
            const u64 off = vaddr - seg.vaddr;
            if (off >= seg.memsz) continue;
            if (off >= seg.filesz) return {};
            if (seg.data.empty()) continue;
            return seg.data.subspan(static_cast<std::size_t>(off));
        }
        return Binary::bytes_at(vaddr);
    }

private:
    explicit MachOBinary(std::vector<std::byte> buffer) noexcept
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
