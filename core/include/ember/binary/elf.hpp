#pragma once

#include <cstddef>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
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
    [[nodiscard]] Endian endian() const noexcept override { return endian_; }
    [[nodiscard]] addr_t entry_point() const noexcept override { return entry_; }

    [[nodiscard]] std::span<const Section> sections() const noexcept override { return sections_; }
    [[nodiscard]] std::span<const Symbol>  symbols() const noexcept  override { return symbols_;  }
    [[nodiscard]] std::span<const std::byte> image() const noexcept  override { return buffer_;   }

    [[nodiscard]] std::span<const LoadSegment> segments() const noexcept { return segments_; }

protected:
    [[nodiscard]] std::vector<Symbol>& mutable_symbols() noexcept override { return symbols_; }
public:

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

    // Parse phases. Each stage reads from buffer_ and appends to the
    // appropriate vector. Ordering matters: segments and sections have no
    // dependency, symbols must come after sections, and the PLT/GOT
    // attachment needs symbols + sections.
    struct ParsedEhdr {
        u16 e_machine;
        u64 e_entry;
        u64 e_phoff, e_shoff;
        u16 e_phentsize, e_phnum;
        u16 e_shentsize, e_shnum, e_shstrndx;
    };
    [[nodiscard]] Result<ParsedEhdr>   parse_ehdr();
    [[nodiscard]] Result<void>         parse_segments(const ParsedEhdr& h);
    [[nodiscard]] Result<void>         parse_sections(const ParsedEhdr& h);
    // Parses SYMTAB + DYNSYM into symbols_; records dynsym string names so
    // that relocations keyed by dynsym index can look up the name back.
    [[nodiscard]] Result<void>
    parse_symbols(const ParsedEhdr& h,
                  std::vector<std::string>& dynsym_names,
                  u16& dynsym_section,
                  bool& dynsym_section_seen);
    // Walks RELA sections and attaches GOT-slot addrs to matching imports.
    [[nodiscard]] Result<void>
    attach_got_addrs(const ParsedEhdr& h,
                     const std::vector<std::string>& dynsym_names,
                     u16 dynsym_section,
                     std::unordered_map<addr_t, std::string>& got_to_name);
    // Scans .plt* sections for the jmp-through-GOT stub pattern; sets
    // Symbol.addr on imports whose stub is found.
    void scan_plt_stubs(const std::unordered_map<addr_t, std::string>& got_to_name);
    void sort_and_dedupe_symbols();

    // Fallback path for stripped binaries with no section table (e_shnum==0).
    // Recovers symbols from PT_DYNAMIC (dynsym + hash tables), synthesizes
    // .text/.plt/.got/.eh_frame/.dynsym/.dynstr sections from program-header
    // metadata so downstream analyses keep working, and seeds `_start` at
    // the entry point. Runs instead of parse_sections/parse_symbols/etc.
    [[nodiscard]] Result<void>
    parse_from_phdr(const ParsedEhdr& h);
    [[nodiscard]] bool is_executable_addr(addr_t vaddr) const noexcept;
    [[nodiscard]] std::optional<addr_t>
    resolve_ppc64_descriptor_target(addr_t vaddr) const noexcept;
    void normalize_ppc64_descriptors() noexcept;

    std::vector<std::byte>    buffer_;
    Arch                      arch_  = Arch::Unknown;
    Endian                    endian_ = Endian::Unknown;
    addr_t                    entry_ = 0;
    std::vector<Section>      sections_;
    std::vector<Symbol>       symbols_;
    std::vector<LoadSegment>  segments_;
};

}  // namespace ember
