#pragma once

#include <cstddef>
#include <memory>
#include <span>
#include <vector>

#include <spelunk/binary/binary.hpp>
#include <spelunk/binary/elf.hpp>  // for LoadSegment
#include <spelunk/common/error.hpp>

namespace spelunk {

class MachOBinary final : public Binary {
public:
    [[nodiscard]] static Result<std::unique_ptr<MachOBinary>>
    load_from_buffer(std::vector<std::byte> buffer);

    [[nodiscard]] Format format() const noexcept override { return Format::MachO; }
    [[nodiscard]] Arch   arch() const noexcept   override { return arch_;  }
    [[nodiscard]] Endian endian() const noexcept override { return endian_; }
    [[nodiscard]] addr_t entry_point() const noexcept override { return entry_; }

    [[nodiscard]] std::span<const Section> sections() const noexcept override { return sections_; }
    [[nodiscard]] std::span<const Symbol>  symbols() const noexcept  override { return symbols_;  }
    [[nodiscard]] std::span<const std::byte> image() const noexcept  override { return buffer_;   }

    [[nodiscard]] std::span<const LoadSegment> segments() const noexcept { return segments_; }

    // Lowest non-empty loadable segment vmaddr. parse_segments() excludes
    // __PAGEZERO explicitly; permission bits do not decide whether dyld maps
    // a segment, so execute-only and write-only segments participate too.
    [[nodiscard]] addr_t preferred_load_base() const noexcept override {
        addr_t lo = 0;
        bool   set = false;
        for (const auto& seg : segments_) {
            if (!set || seg.vaddr < lo) { lo = seg.vaddr; set = true; }
        }
        return set ? lo : 0;
    }

    // VA span of the non-empty loadable segments. __PAGEZERO is absent from
    // segments_, keeping this consistent with preferred_load_base().
    [[nodiscard]] addr_t mapped_size() const noexcept override {
        addr_t lo = 0, hi = 0;
        bool set = false;
        for (const auto& seg : segments_) {
            if (!set) { lo = seg.vaddr; hi = seg.vaddr + seg.memsz; set = true; }
            else {
                if (seg.vaddr < lo) lo = seg.vaddr;
                if (seg.vaddr + seg.memsz > hi) hi = seg.vaddr + seg.memsz;
            }
        }
        return set ? hi - lo : 0;
    }

protected:
    [[nodiscard]] std::vector<Symbol>& mutable_symbols() noexcept override { return symbols_; }
public:

    // Address ranges marked as non-code data inside __TEXT (jump tables,
    // ARM switch constants, etc.), extracted from LC_DATA_IN_CODE.
    // The CFG walker stops at the start of any such range so the decoder
    // doesn't misinterpret raw bytes as instructions.
    struct DataInCodeRange { addr_t start; u32 length; u16 kind; };
    [[nodiscard]] std::span<const DataInCodeRange>
    data_in_code() const noexcept { return data_in_code_; }

    [[nodiscard]] std::span<const std::byte>
    bytes_at(addr_t vaddr) const noexcept override {
        if (section_bytes_authoritative_) return Binary::bytes_at(vaddr);
        for (const auto& seg : segments_) {
            if (vaddr < seg.vaddr) continue;
            const u64 off = vaddr - seg.vaddr;
            if (off >= seg.memsz) continue;
            if (off >= seg.filesz) return {};
            if (seg.data.empty()) return {};
            return seg.data.subspan(static_cast<std::size_t>(off));
        }
        if (has_load_segments_) return {};
        return Binary::bytes_at(vaddr);
    }

    [[nodiscard]] bool is_data_in_code(addr_t addr) const noexcept override {
        for (const auto& r : data_in_code_) {
            if (addr >= r.start && addr < r.start + r.length) return true;
        }
        return false;
    }

private:
    explicit MachOBinary(std::vector<std::byte> buffer) noexcept
        : buffer_(std::move(buffer)) {}

    // parse() runs these in order; ParseState carries the load-command
    // index and __LINKEDIT slices between them.
    struct ParseState;
    [[nodiscard]] Result<void> parse();
    [[nodiscard]] Result<void> read_load_commands(ParseState& st);
    [[nodiscard]] Result<void> parse_segments(ParseState& st);
    [[nodiscard]] Result<void> read_linkedit_commands(ParseState& st);
    void parse_nlist_symbols(ParseState& st);
    void add_exported_symbols(const ParseState& st);
    void collect_bind_records(ParseState& st);
    void parse_data_in_code(const ParseState& st);
    void attach_import_slots(const ParseState& st);
    void resolve_import_stubs(const ParseState& st);
    void strip_c_symbol_prefix();
    void synthesize_entry_symbol();
    void apply_function_starts(const ParseState& st);
    void scan_objc_methods();
    void scan_swift_types();
    void finalize_symbols();

    std::vector<std::byte>    buffer_;
    Arch                      arch_  = Arch::Unknown;
    Endian                    endian_ = Endian::Unknown;
    addr_t                    entry_ = 0;
    std::vector<Section>         sections_;
    std::vector<Symbol>          symbols_;
    std::vector<LoadSegment>     segments_;
    std::vector<DataInCodeRange> data_in_code_;
    bool                         has_load_segments_ = false;
    // dSYM files may compact selected section payloads while preserving
    // their original virtual addresses, so segment delta mapping is not
    // authoritative for their file bytes.
    bool                         section_bytes_authoritative_ = false;
};

}  // namespace spelunk
