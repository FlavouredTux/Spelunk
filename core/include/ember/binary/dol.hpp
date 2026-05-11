#pragma once

#include <cstddef>
#include <filesystem>
#include <memory>
#include <span>
#include <vector>

#include <ember/binary/binary.hpp>
#include <ember/common/error.hpp>

namespace ember {

class DolBinary final : public Binary {
public:
    [[nodiscard]] static Result<std::unique_ptr<DolBinary>>
    load_from_buffer(std::vector<std::byte> buffer);

    [[nodiscard]] Result<std::size_t> attach_map_from_path(const std::filesystem::path& path);

    [[nodiscard]] Format format() const noexcept override { return Format::Dol; }
    [[nodiscard]] Arch arch() const noexcept override { return Arch::Ppc32; }
    [[nodiscard]] Endian endian() const noexcept override { return Endian::Big; }
    [[nodiscard]] addr_t entry_point() const noexcept override { return entry_; }
    [[nodiscard]] addr_t preferred_load_base() const noexcept override { return load_base_; }
    [[nodiscard]] addr_t mapped_size() const noexcept override { return mapped_size_; }

    [[nodiscard]] std::span<const Section> sections() const noexcept override { return sections_; }
    [[nodiscard]] std::span<const Symbol> symbols() const noexcept override { return symbols_; }
    [[nodiscard]] std::span<const std::byte> image() const noexcept override { return buffer_; }

protected:
    [[nodiscard]] std::vector<Symbol>& mutable_symbols() noexcept override { return symbols_; }

private:
    explicit DolBinary(std::vector<std::byte> buffer) : buffer_(std::move(buffer)) {}

    [[nodiscard]] Result<void> parse();
    void sort_and_dedupe_symbols();

    std::vector<std::byte> buffer_;
    addr_t entry_ = 0;
    addr_t load_base_ = 0;
    addr_t mapped_size_ = 0;
    std::vector<Section> sections_;
    std::vector<Symbol> symbols_;
};

[[nodiscard]] bool looks_like_dol_path(const std::filesystem::path& path,
                                       std::span<const std::byte> bytes) noexcept;

}  // namespace ember
