#pragma once

#include <filesystem>
#include <memory>
#include <span>
#include <vector>

#include <spelunk/binary/binary.hpp>
#include <spelunk/common/error.hpp>

namespace spelunk {

inline constexpr addr_t kDefaultRelLoadBase = 0x80500000;

class RelBinary;
struct RelLinkModule;
[[nodiscard]] Result<std::size_t>
link_rel_modules(std::span<RelLinkModule> modules, const Binary* main_dol);

// Nintendo GameCube/Wii REL module. REL files have no fixed load address or
// symbol table: sections receive a deterministic synthetic layout and the
// compact import streams provide the relocation edges.
class RelBinary final : public Binary {
public:
    [[nodiscard]] static Result<std::unique_ptr<RelBinary>>
    load_from_buffer(std::vector<std::byte> buffer,
                     addr_t synthetic_base = kDefaultRelLoadBase);

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

    // Map the coordinates stored in an import relocation into this module's
    // synthetic address space. Empty and out-of-range sections are rejected.
    [[nodiscard]] std::optional<addr_t>
    section_address(u32 section, u32 offset) const noexcept;

    // Keep a linked DOL/REL alive and expose its mapped sections and defined
    // symbols through this analysis view. The selected REL remains the entry
    // module, while direct analysis can follow or target peer addresses.
    void adopt_linked_binary(std::unique_ptr<Binary> binary,
                             std::string_view module_name);

protected:
    [[nodiscard]] std::vector<Symbol>& mutable_symbols() noexcept override {
        return symbols_;
    }

private:
    explicit RelBinary(std::vector<std::byte> buffer, addr_t synthetic_base)
        : buffer_(std::move(buffer)), synthetic_base_(synthetic_base) {}

    [[nodiscard]] Result<void> parse();
    [[nodiscard]] Result<void> parse_relocations(u32 rel_offset, u32 imp_offset,
                                                  u32 imp_size,
                                                  u32 fixed_boundary);
    [[nodiscard]] Result<bool> apply_relocation(Relocation& relocation,
                                                 addr_t target);
    void add_known_function(std::string name, u8 section, u32 offset);
    void sort_and_dedupe_symbols();

    friend Result<std::size_t>
    link_rel_modules(std::span<RelLinkModule> modules, const Binary* main_dol);

    std::vector<std::byte> buffer_;
    addr_t synthetic_base_ = kDefaultRelLoadBase;
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
    std::vector<std::unique_ptr<Binary>> linked_binaries_;
};

// A mutable REL participating in one link context. `name` is the DTK module
// name and is retained for diagnostics; symbol maps on each binary provide
// the source-level names used for resolved calls and globals.
struct RelLinkModule {
    RelBinary* binary = nullptr;
    std::string_view name;
};

// Resolve every module-to-module edge in-place. Self and main-DOL relocations
// have already been applied by the individual loader; this pass supplies peer
// section addresses, improves DOL names, and rejects duplicate module IDs.
[[nodiscard]] Result<std::size_t>
link_rel_modules(std::span<RelLinkModule> modules,
                 const Binary* main_dol = nullptr);

[[nodiscard]] bool looks_like_rel_path(const std::filesystem::path& path,
                                       std::span<const std::byte> bytes) noexcept;

}  // namespace spelunk
