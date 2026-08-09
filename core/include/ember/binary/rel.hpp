#pragma once

#include <filesystem>
#include <memory>
#include <span>
#include <vector>

#include <ember/binary/binary.hpp>
#include <ember/common/error.hpp>

namespace ember {

// Nintendo GameCube/Wii REL module. REL files have no fixed load address or
// symbol table: sections receive a deterministic synthetic layout and the
// compact import streams provide the relocation edges.
class RelBinary final : public Binary {
public:
    [[nodiscard]] static Result<std::unique_ptr<RelBinary>>
    load_from_buffer(std::vector<std::byte> buffer);

    // DTK REL symbols use section-relative addresses (for example
    // `.text:0x1234`), unlike main-DOL symbol files whose values are VAs.
    [[nodiscard]] Result<std::size_t> attach_dtk_symbols_from_path(
        const std::filesystem::path& path);

    [[nodiscard]] Format format() const noexcept override { return Format::Rel; }
    [[nodiscard]] Arch arch() const noexcept override { return Arch::Ppc32; }
    [[nodiscard]] Endian endian() const noexcept override { return Endian::Big; }
    [[nodiscard]] addr_t entry_point() const noexcept override { return entry_; }
    [[nodiscard]] addr_t preferred_load_base() const noexcept override { return load_base_; }
    [[nodiscard]] addr_t mapped_size() const noexcept override { return mapped_size_; }

    [[nodiscard]] std::span<const Section> sections() const noexcept override {
        return sections_;
    }
    [[nodiscard]] std::span<const Symbol> symbols() const noexcept override {
        return symbols_;
    }
    [[nodiscard]] std::span<const Relocation> relocations() const noexcept override {
        return relocations_;
    }
    [[nodiscard]] std::span<const std::byte> image() const noexcept override {
        return buffer_;
    }

    [[nodiscard]] u32 module_id() const noexcept { return module_id_; }
    [[nodiscard]] u32 version() const noexcept { return version_; }

protected:
    [[nodiscard]] std::vector<Symbol>& mutable_symbols() noexcept override {
        return symbols_;
    }

private:
    explicit RelBinary(std::vector<std::byte> buffer) : buffer_(std::move(buffer)) {}

    [[nodiscard]] Result<void> parse();
    [[nodiscard]] Result<void> parse_relocations(u32 rel_offset, u32 imp_offset,
                                                  u32 imp_size, u32 fix_size);
    void add_known_function(std::string name, u8 section, u32 offset);
    void sort_and_dedupe_symbols();

    std::vector<std::byte> buffer_;
    addr_t entry_ = 0;
    addr_t load_base_ = 0;
    addr_t mapped_size_ = 0;
    u32 module_id_ = 0;
    u32 version_ = 0;
    std::vector<Section> sections_;
    std::vector<Symbol> symbols_;
    std::vector<Relocation> relocations_;
    std::vector<addr_t> section_bases_;
    std::vector<u32> section_offsets_;
    std::vector<u32> section_sizes_;
    std::vector<bool> section_executable_;
};

[[nodiscard]] bool looks_like_rel_path(const std::filesystem::path& path,
                                       std::span<const std::byte> bytes) noexcept;

}  // namespace ember
