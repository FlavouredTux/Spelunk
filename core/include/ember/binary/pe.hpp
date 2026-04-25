#pragma once

#include <cstddef>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <ember/binary/binary.hpp>
#include <ember/binary/pe_view.hpp>
#include <ember/common/error.hpp>

namespace ember {

class PeBinary final : public Binary {
public:
    [[nodiscard]] static Result<std::unique_ptr<PeBinary>>
    load_from_buffer(std::vector<std::byte> buffer);

    [[nodiscard]] Format format() const noexcept override { return Format::Pe; }
    [[nodiscard]] Arch   arch() const noexcept   override { return arch_;  }
    [[nodiscard]] Endian endian() const noexcept override { return Endian::Little; }
    [[nodiscard]] addr_t entry_point() const noexcept override { return entry_; }

    [[nodiscard]] std::span<const Section> sections() const noexcept override { return sections_; }
    [[nodiscard]] std::span<const Symbol>  symbols() const noexcept  override { return symbols_;  }
    [[nodiscard]] std::span<const std::byte> image() const noexcept  override { return buffer_;   }

    // Preferred load address from the optional header. Section vaddrs are
    // stored as absolute VAs (image_base + RVA) so downstream code doesn't
    // have to know about the offset, but the PDATA parser (phase 3) and
    // MSVC RTTI walker (phase 5) need to convert RVAs they read from
    // on-disk structures back to absolute VAs.
    [[nodiscard]] addr_t image_base() const noexcept { return image_base_; }

    // Optional header data directory entries. Fields carry RVAs — callers
    // add image_base() to get absolute VAs. Index with the standard
    // IMAGE_DIRECTORY_ENTRY_* constants (EXPORT=0, IMPORT=1, EXCEPTION=3,
    // etc.). Size zero → directory absent.
    using DataDirectory = pe::DataDirectory;
    [[nodiscard]] std::span<const DataDirectory>
    data_directories() const noexcept { return data_dirs_; }

private:
    explicit PeBinary(std::vector<std::byte> buffer) noexcept
        : buffer_(std::move(buffer)) {}

    [[nodiscard]] Result<void> parse();

    struct ParsedHeaders {
        std::size_t coff_off;          // file offset of IMAGE_FILE_HEADER
        std::size_t opt_off;           // file offset of IMAGE_OPTIONAL_HEADER64
        std::size_t sec_tab_off;       // file offset of the section table
        u16         num_sections;
        u16         opt_size;
        u32         num_rva_and_sizes;
        u64         image_base;
        u32         entry_rva;
    };
    [[nodiscard]] Result<ParsedHeaders> parse_headers();
    [[nodiscard]] Result<void>          parse_sections(const ParsedHeaders& h);
    [[nodiscard]] Result<void>          validate_entry_rva() const;
    // Walks IMAGE_DIRECTORY_ENTRY_IMPORT. Populates is_import=true
    // Symbols with got_addr set to the IAT slot VA. got_to_name carries
    // the slot-VA → import-name mapping used by scan_iat_thunks.
    [[nodiscard]] Result<void>
    parse_imports(std::unordered_map<addr_t, std::string>& got_to_name);
    // Walks IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT. Same INT/IAT shape as
    // IMPORT but the descriptor is the larger ImgDelayDescr struct and
    // entries are deferred until first call (grAttrs bit 0 = "RVAs, not
    // VAs"; the v1 implementation requires that bit). Game clients
    // typically route the bulk of their `d3d11`/`dxgi`/`xinput` calls
    // through here, so without this they all degrade to indirect calls.
    [[nodiscard]] Result<void>
    parse_delay_imports(std::unordered_map<addr_t, std::string>& got_to_name);
    // Walks IMAGE_DIRECTORY_ENTRY_TLS (data dir 9). The TLS callback
    // array is the first userland code that runs in any PE — packers,
    // anti-cheats, and obfuscators install hooks here long before
    // `main`. Without listing them, the entry-point view is misleading.
    // Synthesizes `tls_callback_<N>` Symbol entries; size gets filled in
    // later by absorb_pdata_function_starts() when the .pdata covers
    // the callback. Empty / absent TLS directory → no-op.
    [[nodiscard]] Result<void> parse_tls_callbacks();
    // Walks IMAGE_DIRECTORY_ENTRY_EXPORT. Named exports become Symbols
    // with is_export=true. Forwarder exports (whose RVA points inside
    // the export directory range) are skipped silently.
    [[nodiscard]] Result<void> parse_exports();
    // Scans executable sections for `FF 25 rel32` (jmp qword ptr
    // [rip+disp]) thunks; when the target RIP-relative address matches
    // a known IAT slot, sets Symbol.addr on the import to the thunk's VA.
    void scan_iat_thunks(
        const std::unordered_map<addr_t, std::string>& got_to_name);
    // Fills symbol size on existing functions and emits synthetic
    // `sub_<hex>` entries for PDATA-described functions that weren't
    // named by exports. Mirrors macho.cpp's LC_FUNCTION_STARTS pass.
    void absorb_pdata_function_starts();
    void sort_and_dedupe_symbols();

    // Resolve an RVA to the in-memory byte span starting at that VA.
    // Returns an empty span if the RVA falls outside every section or in
    // the zero-init tail of a section.
    [[nodiscard]] std::span<const std::byte>
    bytes_at_rva(u32 rva) const noexcept;
    [[nodiscard]] bool
    rva_is_mapped(u32 rva, std::size_t min_size = 1) const noexcept;
    // Resolve an RVA to a null-terminated ASCII string. Caps length at
    // the remaining bytes of the containing section.
    [[nodiscard]] std::string_view cstr_at_rva(u32 rva) const noexcept;

    std::vector<std::byte>     buffer_;
    Arch                       arch_       = Arch::Unknown;
    addr_t                     entry_      = 0;
    addr_t                     image_base_ = 0;
    std::vector<Section>       sections_;
    std::vector<Symbol>        symbols_;
    std::vector<DataDirectory> data_dirs_;
};

}  // namespace ember
