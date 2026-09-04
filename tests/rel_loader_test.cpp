#include <algorithm>
#include <chrono>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <ember/binary/binary.hpp>
#include <ember/binary/rel.hpp>
#include <ember/common/bytes.hpp>
#include <ember/disasm/decoder.hpp>

namespace {

using namespace ember;

namespace fixture {

constexpr u32 kModuleId = 5;
constexpr u32 kExternalModuleId = 7;
constexpr u32 kDolModuleId = 0;
constexpr u8 kDataSection = 2;

constexpr addr_t kLoadBase = 0x80500000;
constexpr addr_t kDataAddress = kLoadBase + 0x10;
constexpr addr_t kBssAddress = kLoadBase + 0x1c;
constexpr u32 kUnusedFileGap = 0x70;

constexpr std::size_t kModuleIdField = 0x00;
constexpr std::size_t kMinimumHeaderSize = 0x40;
constexpr std::size_t kVersionField = 0x1c;
constexpr std::size_t kRelOffsetField = 0x24;
constexpr std::size_t kEpilogSectionField = 0x31;
constexpr std::size_t kUnresolvedSectionField = 0x32;
constexpr std::size_t kPrologOffsetField = 0x34;
constexpr std::size_t kEpilogOffsetField = 0x38;
constexpr std::size_t kSectionAlignField = 0x40;
constexpr std::size_t kBssAlignField = 0x44;
constexpr std::size_t kFixSizeField = 0x48;
constexpr std::size_t kSectionTable = 0x4c;
constexpr std::size_t kSectionEntrySize = 8;

constexpr std::size_t kImportTable = 0xa0;
constexpr std::size_t kImportEntrySize = 8;
constexpr std::size_t kImportStreamOffset = 4;
constexpr std::size_t kExternalImport = 0;
constexpr std::size_t kSelfImport = 1;
constexpr std::size_t kDolImport = 2;

constexpr std::size_t kRelocationEntrySize = 8;
constexpr std::size_t kRelocationTypeOffset = 2;
constexpr std::size_t kRelocationSectionOffset = 3;
constexpr std::size_t kRelocationAddendOffset = 4;
constexpr std::size_t kSectionSizeOffset = 4;
constexpr u32 kExternalStream = 0xc0;
constexpr u32 kSelfStream = 0xd8;
constexpr u32 kDolStream = 0x108;
constexpr std::size_t kExternalSectionRecord = kExternalStream;
constexpr std::size_t kExternalPointerRecord =
    kExternalSectionRecord + kRelocationEntrySize;
constexpr std::size_t kExternalEndRecord =
    kExternalPointerRecord + kRelocationEntrySize;
constexpr u32 kExternalEndRecordInterior = static_cast<u32>(
    kExternalEndRecord + kRelocationAddendOffset);
static_assert(kExternalEndRecordInterior > kExternalEndRecord &&
              kExternalEndRecordInterior <
                  kExternalEndRecord + kRelocationEntrySize);
constexpr std::size_t kSelfSectionRecord = kSelfStream;
constexpr std::size_t kSelfHaRecord =
    kSelfSectionRecord + kRelocationEntrySize;
constexpr std::size_t kSelfLoRecord =
    kSelfHaRecord + kRelocationEntrySize;
constexpr std::size_t kSelfDataSectionRecord =
    kSelfLoRecord + kRelocationEntrySize;
constexpr std::size_t kSelfPointerRecord =
    kSelfDataSectionRecord + kRelocationEntrySize;
constexpr std::size_t kDolSectionRecord = kDolStream;
constexpr std::size_t kDolRelocationRecord =
    kDolSectionRecord + kRelocationEntrySize;
constexpr std::size_t kDolEndRecord =
    kDolRelocationRecord + kRelocationEntrySize;

constexpr u8 kNone = 0;
constexpr u8 kAddr32 = 1;
constexpr u8 kAddr24 = 2;
constexpr u8 kAddr16 = 3;
constexpr u8 kAddr16Lo = 4;
constexpr u8 kAddr16Ha = 6;
constexpr u8 kRel24 = 10;
constexpr u8 kUaddr32 = 24;

}  // namespace fixture

struct TestFailure {};

void check(bool condition, std::string_view message) {
    if (condition) return;
    std::cerr << "rel_loader_test: " << message << "\n";
    throw TestFailure{};
}

u32 word_at(const Binary& binary, addr_t address) {
    const auto bytes = binary.bytes_at(address);
    check(bytes.size() >= 4, "expected mapped word");
    return read_be_at<u32>(bytes.data());
}

const Relocation* find_relocation(const Binary& binary, u8 type,
                                  addr_t site, u32 target_module) {
    const auto relocations = binary.relocations();
    const auto found = std::ranges::find_if(
        relocations, [&](const Relocation& relocation) {
            return relocation.type == type && relocation.site == site &&
                   relocation.target_module == target_module;
        });
    return found == relocations.end() ? nullptr : &*found;
}

std::vector<std::byte> read_fixture(const std::filesystem::path& path) {
    const auto size = std::filesystem::file_size(path);
    check(size <= std::numeric_limits<std::size_t>::max(), "fixture is too large");
    std::vector<std::byte> bytes(static_cast<std::size_t>(size));
    std::ifstream input(path, std::ios::binary);
    check(input.good(), "fixture should open for malformed-input checks");
    input.read(reinterpret_cast<char*>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
    check(input.good(), "fixture should be read completely");
    return bytes;
}

void put_be16(std::vector<std::byte>& bytes, std::size_t offset, u16 value) {
    check(offset <= bytes.size() && bytes.size() - offset >= 2,
          "test mutation should fit in fixture");
    bytes[offset] = static_cast<std::byte>(value >> 8);
    bytes[offset + 1] = static_cast<std::byte>(value);
}

void put_be32(std::vector<std::byte>& bytes, std::size_t offset, u32 value) {
    check(offset <= bytes.size() && bytes.size() - offset >= 4,
          "test mutation should fit in fixture");
    bytes[offset] = static_cast<std::byte>(value >> 24);
    bytes[offset + 1] = static_cast<std::byte>(value >> 16);
    bytes[offset + 2] = static_cast<std::byte>(value >> 8);
    bytes[offset + 3] = static_cast<std::byte>(value);
}

u32 header_word(const std::vector<std::byte>& bytes, std::size_t field) {
    check(field <= bytes.size() && bytes.size() - field >= 4,
          "header field should fit in fixture");
    return read_be_at<u32>(bytes.data() + field);
}

void set_header_word(std::vector<std::byte>& bytes,
                     std::size_t field, u32 value) {
    put_be32(bytes, field, value);
}

void set_header_byte(std::vector<std::byte>& bytes,
                     std::size_t field, u8 value) {
    check(field < bytes.size(), "header byte should fit in fixture");
    bytes[field] = static_cast<std::byte>(value);
}

[[nodiscard]] constexpr std::size_t import_entry(std::size_t index) {
    return fixture::kImportTable + index * fixture::kImportEntrySize;
}

void set_import(std::vector<std::byte>& bytes, std::size_t index,
                u32 module_id, u32 stream_offset) {
    put_be32(bytes, import_entry(index), module_id);
    put_be32(bytes, import_entry(index) + fixture::kImportStreamOffset,
             stream_offset);
}

void set_import_module(std::vector<std::byte>& bytes,
                       std::size_t index, u32 module_id) {
    put_be32(bytes, import_entry(index), module_id);
}

void set_import_stream(std::vector<std::byte>& bytes,
                       std::size_t index, u32 stream_offset) {
    put_be32(bytes, import_entry(index) + fixture::kImportStreamOffset,
             stream_offset);
}

void set_section_offset_and_flags(std::vector<std::byte>& bytes,
                                  std::size_t index, u32 value) {
    put_be32(bytes,
             fixture::kSectionTable + index * fixture::kSectionEntrySize,
             value);
}

void set_section_size(std::vector<std::byte>& bytes,
                      std::size_t index, u32 value) {
    put_be32(bytes,
             fixture::kSectionTable + index * fixture::kSectionEntrySize +
                 fixture::kSectionSizeOffset,
             value);
}

void set_relocation_delta(std::vector<std::byte>& bytes,
                          std::size_t record, u16 delta) {
    put_be16(bytes, record, delta);
}

void set_relocation_type(std::vector<std::byte>& bytes,
                         std::size_t record, u8 type) {
    check(record <= bytes.size() &&
              bytes.size() - record > fixture::kRelocationTypeOffset,
          "relocation type should fit in fixture");
    bytes[record + fixture::kRelocationTypeOffset] =
        static_cast<std::byte>(type);
}

void set_relocation_section(std::vector<std::byte>& bytes,
                            std::size_t record, u8 section) {
    check(record <= bytes.size() &&
              bytes.size() - record > fixture::kRelocationSectionOffset,
          "relocation section should fit in fixture");
    bytes[record + fixture::kRelocationSectionOffset] =
        static_cast<std::byte>(section);
}

void set_relocation_addend(std::vector<std::byte>& bytes,
                           std::size_t record, u32 addend) {
    put_be32(bytes, record + fixture::kRelocationAddendOffset, addend);
}

class ScopedTempDirectory {
public:
    ScopedTempDirectory() {
        const auto seed =
            std::chrono::steady_clock::now().time_since_epoch().count();
        const auto base = std::filesystem::temp_directory_path();
        for (unsigned attempt = 0; attempt < 1024; ++attempt) {
            const auto candidate = base /
                ("ember_rel_loader_test_" + std::to_string(seed) + "_" +
                 std::to_string(attempt));
            std::error_code error;
            if (std::filesystem::create_directory(candidate, error)) {
                path_ = candidate;
                return;
            }
            if (error) {
                check(false, "temporary DTK symbol directory should be created");
            }
        }
        check(false, "could not allocate a unique DTK symbol directory");
    }

    ~ScopedTempDirectory() {
        if (path_.empty()) return;
        std::error_code error;
        std::filesystem::remove_all(path_, error);
    }

    ScopedTempDirectory(const ScopedTempDirectory&) = delete;
    ScopedTempDirectory& operator=(const ScopedTempDirectory&) = delete;

    [[nodiscard]] std::filesystem::path file(std::string_view name) const {
        return path_ / name;
    }

private:
    std::filesystem::path path_;
};

struct TestContext {
    std::filesystem::path rel_path;
    std::filesystem::path symbols_path;
    std::vector<std::byte> fixture_bytes;
};

void test_baseline(const TestContext& context) {
    auto loaded = load_binary(context.rel_path);
    check(loaded.has_value(), "Wii REL fixture should load");
    const auto& binary = **loaded;
    const auto* rel = dynamic_cast<const RelBinary*>(&binary);

    check(rel != nullptr && binary.format() == Format::Rel,
          "loader should select RelBinary");
    check(rel->module_id() == fixture::kModuleId && rel->version() == 3,
          "REL header identity should be retained");
    check(binary.arch() == Arch::Ppc32 && binary.endian() == Endian::Big,
          "REL should use big-endian PPC32");
    check(binary.preferred_load_base() == fixture::kLoadBase &&
              binary.mapped_size() == 0x20,
          "REL sections should receive a deterministic Wii-range layout");

    const auto* prolog = binary.find_by_name("_prolog");
    const auto* self_data = binary.find_by_name("rel5_s2_00000000");
    const auto* dol_import = binary.find_by_name("dol_80001200");
    const auto* external = binary.find_by_name("rel7_s2_00000010");
    check(prolog && prolog->addr == fixture::kLoadBase &&
              binary.entry_point() == prolog->addr,
          "prolog should define the REL entry point");
    check(self_data && self_data->addr == fixture::kDataAddress,
          "self relocation should synthesize a local data symbol");
    check(dol_import && dol_import->is_import && dol_import->addr == 0x80001200,
          "DOL relocation should synthesize a resolved import");
    check(external && external->is_import && external->addr == 0,
          "cross-REL target should remain explicitly unresolved");

    check(binary.relocations().size() == 5,
          "all REL relocation edges should be retained");
    const auto* self_ha = find_relocation(
        binary, fixture::kAddr16Ha, prolog->addr + 6, fixture::kModuleId);
    const auto* self_lo = find_relocation(
        binary, fixture::kAddr16Lo, prolog->addr + 10, fixture::kModuleId);
    const auto* self_pointer = find_relocation(
        binary, fixture::kAddr32, self_data->addr, fixture::kModuleId);
    const auto* dol_call = find_relocation(
        binary, fixture::kRel24, prolog->addr, fixture::kDolModuleId);
    const auto* external_pointer =
        find_relocation(binary, fixture::kAddr32, self_data->addr + 8,
                        fixture::kExternalModuleId);
    check(self_ha && self_ha->target == self_data->addr && self_ha->applied &&
              self_ha->type_name == "R_PPC_ADDR16_HA",
          "self HA relocation should patch and retain evidence");
    check(self_lo && self_lo->target == self_data->addr && self_lo->applied,
          "self LO relocation should patch and retain evidence");
    check(self_pointer && self_pointer->target == prolog->addr &&
              self_pointer->applied,
          "self ADDR32 relocation should patch the data pointer");
    check(dol_call && dol_call->target == dol_import->addr &&
              dol_call->pc_relative && dol_call->applied,
          "DOL REL24 relocation should resolve and patch");
    check(external_pointer && external_pointer->target == 0 &&
              !external_pointer->applied &&
              external_pointer->symbol_name == "rel7_s2_00000010",
          "cross-REL relocation should remain visible but unapplied");

    auto decoder = make_decoder(binary);
    check(decoder.has_value(), "PPC decoder should be available");
    auto call = (*decoder)->decode(binary.bytes_at(prolog->addr), prolog->addr);
    check(call.has_value() && call->mnemonic == Mnemonic::Call &&
              branch_target(*call) == dol_import->addr,
          "relocated branch should decode to the DOL import");
    check(binary.import_at_plt(dol_import->addr) == dol_import,
          "resolved DOL target should participate in named call lookup");

    const u32 lis = word_at(binary, prolog->addr + 4);
    const u32 addi = word_at(binary, prolog->addr + 8);
    const i64 rebuilt = static_cast<i64>((lis & 0xffffu) << 16) +
                        static_cast<i64>(static_cast<i16>(addi & 0xffffu));
    check(static_cast<addr_t>(rebuilt) == self_data->addr,
          "HA/LO instructions should reconstruct the self data address");
    check(word_at(binary, self_data->addr) == prolog->addr,
          "self data pointer should contain the relocated prolog address");
    check(word_at(binary, self_data->addr + 8) == 0,
          "unresolved cross-REL pointer should remain untouched");
}

void test_stream_structure(const TestContext& context) {
    const auto& fixture_bytes = context.fixture_bytes;
    auto sniff_path = context.rel_path;
    sniff_path.replace_extension();
    check(looks_like_rel_path(sniff_path, fixture_bytes),
          "validated REL structure should be detected");
    auto invalid_detected_header = fixture_bytes;
    set_header_word(invalid_detected_header, fixture::kModuleIdField,
                    fixture::kDolModuleId);
    check(!looks_like_rel_path(sniff_path, invalid_detected_header),
          "REL detection should map structural validation failures to false");
    auto named_rel_path = sniff_path;
    named_rel_path.replace_extension(".ReL");
    check(looks_like_rel_path(named_rel_path, invalid_detected_header),
          "named RELs should reach the parser for detailed diagnostics");
    const std::vector<std::byte> truncated_header(
        fixture::kMinimumHeaderSize - 1);
    check(!looks_like_rel_path(named_rel_path, truncated_header),
          "named REL detection should still require the minimum header size");
    check(header_word(fixture_bytes, fixture::kFixSizeField) ==
              fixture::kSelfStream,
          "baseline fixSize should retain the required external stream");

    auto independent_fix_size = fixture_bytes;
    set_header_word(independent_fix_size, fixture::kFixSizeField,
                    static_cast<u32>(independent_fix_size.size()));
    check(RelBinary::load_from_buffer(std::move(independent_fix_size)).has_value(),
          "v3 fixSize need not equal the self relocation stream offset");

    auto late_external_import = fixture_bytes;
    set_import(late_external_import, fixture::kExternalImport,
               fixture::kModuleId, fixture::kSelfStream);
    set_import(late_external_import, fixture::kSelfImport,
               fixture::kDolModuleId, fixture::kDolStream);
    set_import(late_external_import, fixture::kDolImport,
               fixture::kExternalModuleId, fixture::kExternalStream);
    auto shuffled_imports = late_external_import;
    set_header_word(shuffled_imports, fixture::kVersionField, 2);
    auto shuffled = RelBinary::load_from_buffer(std::move(shuffled_imports));
    check(shuffled.has_value() && (*shuffled)->relocations().size() == 5,
          "ordinary OSLink import order should not identify the first stream");
    check(!RelBinary::load_from_buffer(std::move(late_external_import)),
          "v3 external imports should precede self and DOL imports");

    auto mismatched_rel_offset = fixture_bytes;
    set_header_word(mismatched_rel_offset, fixture::kRelOffsetField,
                    fixture::kExternalStream - 4);
    check(!RelBinary::load_from_buffer(std::move(mismatched_rel_offset)),
          "relOffset should equal the minimum import stream start");

    auto padded_streams = fixture_bytes;
    constexpr u32 kStreamPadding = 4;
    padded_streams.insert(
        padded_streams.begin() +
            static_cast<std::ptrdiff_t>(fixture::kSelfStream),
        kStreamPadding, std::byte{0});
    set_header_word(padded_streams, fixture::kFixSizeField,
                    fixture::kSelfStream + kStreamPadding);
    set_import_stream(padded_streams, fixture::kSelfImport,
                      fixture::kSelfStream + kStreamPadding);
    set_import_stream(padded_streams, fixture::kDolImport,
                      fixture::kDolStream + kStreamPadding);
    auto padded = RelBinary::load_from_buffer(std::move(padded_streams));
    check(padded.has_value() && (*padded)->relocations().size() == 5,
          "four-byte padding between relocation streams should be accepted");

    auto unaligned_uaddr32 = fixture_bytes;
    set_relocation_delta(
        unaligned_uaddr32, fixture::kSelfPointerRecord, 1);
    set_relocation_type(
        unaligned_uaddr32, fixture::kSelfPointerRecord, fixture::kUaddr32);
    auto unaligned = RelBinary::load_from_buffer(std::move(unaligned_uaddr32));
    check(unaligned.has_value(), "unaligned R_PPC_UADDR32 should load");
    const auto* uaddr32 = find_relocation(
        **unaligned, fixture::kUaddr32, fixture::kDataAddress + 1,
        fixture::kModuleId);
    check(uaddr32 && uaddr32->applied &&
              word_at(**unaligned, uaddr32->site) == 0x80500000,
          "R_PPC_UADDR32 should preserve and patch its unaligned source offset");

    auto none_delta = fixture_bytes;
    set_relocation_type(
        none_delta, fixture::kSelfHaRecord, fixture::kNone);
    auto none_shifted = RelBinary::load_from_buffer(std::move(none_delta));
    check(none_shifted.has_value() &&
              find_relocation(**none_shifted, fixture::kAddr16Lo,
                              fixture::kLoadBase + 10,
                              fixture::kModuleId) != nullptr,
          "R_PPC_NONE delta should advance the following relocation site");

    auto misaligned_halfword = fixture_bytes;
    set_relocation_delta(
        misaligned_halfword, fixture::kSelfHaRecord, 5);
    check(!RelBinary::load_from_buffer(std::move(misaligned_halfword)),
          "16-bit relocation fields should retain two-byte alignment");

    auto misaligned_word = fixture_bytes;
    set_relocation_delta(
        misaligned_word, fixture::kExternalPointerRecord, 6);
    check(!RelBinary::load_from_buffer(std::move(misaligned_word)),
          "ordinary 32-bit relocation fields should retain four-byte alignment");

    auto invalid_section = fixture_bytes;
    set_relocation_section(
        invalid_section, fixture::kExternalSectionRecord, 9);
    check(!RelBinary::load_from_buffer(std::move(invalid_section)),
          "out-of-range R_DOLPHIN_SECTION should be rejected");

    auto duplicate_stream = fixture_bytes;
    set_import_stream(
        duplicate_stream, fixture::kDolImport, fixture::kSelfStream);
    check(!RelBinary::load_from_buffer(std::move(duplicate_stream)),
          "imports sharing a relocation stream start should be rejected");

    auto duplicate_module = fixture_bytes;
    set_import_module(
        duplicate_module, fixture::kExternalImport, fixture::kDolModuleId);
    check(!RelBinary::load_from_buffer(std::move(duplicate_module)),
          "distinct streams for a duplicate target module should be rejected");

    auto aliased_stream = fixture_bytes;
    set_import_stream(aliased_stream, fixture::kDolImport,
                      static_cast<u32>(fixture::kSelfDataSectionRecord));
    check(!RelBinary::load_from_buffer(std::move(aliased_stream)),
          "an import starting inside another relocation stream should be rejected");

    auto borrowed_end = fixture_bytes;
    set_relocation_type(
        borrowed_end, fixture::kExternalEndRecord, fixture::kNone);
    check(!RelBinary::load_from_buffer(std::move(borrowed_end)),
          "a relocation stream must end before the next import stream starts");

    auto missing_end = fixture_bytes;
    set_relocation_type(
        missing_end, fixture::kDolEndRecord, fixture::kAddr32);
    check(!RelBinary::load_from_buffer(std::move(missing_end)),
          "relocation stream without R_DOLPHIN_END should be rejected");
}

void test_header_and_section_validation(const TestContext& context) {
    const auto& fixture_bytes = context.fixture_bytes;
    auto reserved_module = fixture_bytes;
    set_header_word(
        reserved_module, fixture::kModuleIdField, fixture::kDolModuleId);
    set_import_module(reserved_module, fixture::kDolImport, 11);
    set_header_word(reserved_module, fixture::kFixSizeField,
                    static_cast<u32>(reserved_module.size()));
    check(!RelBinary::load_from_buffer(std::move(reserved_module)),
          "REL module ID zero should be rejected as reserved for the DOL");

    auto zero_alignment = fixture_bytes;
    set_header_word(zero_alignment, fixture::kSectionAlignField, 0);
    set_header_word(zero_alignment, fixture::kBssAlignField, 0);
    check(RelBinary::load_from_buffer(std::move(zero_alignment)).has_value(),
          "zero alignments should mean no additional SDK constraint");

    auto invalid_section_alignment = fixture_bytes;
    set_header_word(invalid_section_alignment,
                    fixture::kSectionAlignField, 3);
    check(!RelBinary::load_from_buffer(std::move(invalid_section_alignment)),
          "non-power-of-two section alignment should be rejected");

    auto invalid_alignment = fixture_bytes;
    set_header_word(invalid_alignment, fixture::kBssAlignField, 6);
    check(!RelBinary::load_from_buffer(std::move(invalid_alignment)),
          "non-power-of-two BSS alignment should be rejected");

    auto invalid_prolog_offset = fixture_bytes;
    set_header_word(
        invalid_prolog_offset, fixture::kPrologOffsetField, 0x10);
    check(!RelBinary::load_from_buffer(std::move(invalid_prolog_offset)),
          "prolog offsets outside their selected section should be rejected");

    auto unaligned_prolog_offset = fixture_bytes;
    set_header_word(
        unaligned_prolog_offset, fixture::kPrologOffsetField, 2);
    check(!RelBinary::load_from_buffer(std::move(unaligned_prolog_offset)),
          "non-null function offsets should be four-byte aligned");

    auto invalid_epilog_section = fixture_bytes;
    set_header_byte(
        invalid_epilog_section, fixture::kEpilogSectionField, 4);
    check(!RelBinary::load_from_buffer(std::move(invalid_epilog_section)),
          "out-of-range epilog sections should be rejected");

    auto invalid_absent_epilog = fixture_bytes;
    set_header_word(
        invalid_absent_epilog, fixture::kEpilogOffsetField, 4);
    check(!RelBinary::load_from_buffer(std::move(invalid_absent_epilog)),
          "absent function coordinates should be encoded as 0:0");

    auto invalid_unresolved_section = fixture_bytes;
    set_header_byte(invalid_unresolved_section,
                    fixture::kUnresolvedSectionField,
                    fixture::kDataSection);
    check(!RelBinary::load_from_buffer(std::move(invalid_unresolved_section)),
          "unresolved handlers in non-executable sections should be rejected");

    auto nonempty_section_zero = fixture_bytes;
    set_section_offset_and_flags(
        nonempty_section_zero, 0, fixture::kUnusedFileGap);
    set_section_size(nonempty_section_zero, 0, 4);
    check(!RelBinary::load_from_buffer(std::move(nonempty_section_zero)),
          "reserved REL section zero should be empty");

    auto flagged_section_zero = fixture_bytes;
    set_section_offset_and_flags(flagged_section_zero, 0, 1);
    check(!RelBinary::load_from_buffer(std::move(flagged_section_zero)),
          "reserved REL section zero flags and offset should also be zero");

    auto fix_past_file = fixture_bytes;
    set_header_word(fix_past_file, fixture::kFixSizeField,
                    static_cast<u32>(fix_past_file.size()) + 4);
    check(!RelBinary::load_from_buffer(std::move(fix_past_file)),
          "fixSize beyond the file should be rejected");

    auto fix_before_imports = fixture_bytes;
    set_header_word(fix_before_imports, fixture::kFixSizeField,
                    static_cast<u32>(
                        import_entry(fixture::kDolImport) +
                        fixture::kImportStreamOffset));
    check(!RelBinary::load_from_buffer(std::move(fix_before_imports)),
          "fixSize should retain the complete import table");

    auto fix_cuts_record = fixture_bytes;
    set_header_word(fix_cuts_record, fixture::kFixSizeField,
                    fixture::kExternalEndRecordInterior);
    check(!RelBinary::load_from_buffer(std::move(fix_cuts_record)),
          "fixSize should not split a relocation record or stream");

    auto fix_discards_external = fixture_bytes;
    set_header_word(fix_discards_external, fixture::kFixSizeField,
                    fixture::kExternalStream);
    check(!RelBinary::load_from_buffer(std::move(fix_discards_external)),
          "fixSize should retain external-module relocation streams");

    auto unaligned_fix = fixture_bytes;
    set_header_word(unaligned_fix, fixture::kFixSizeField,
                    fixture::kSelfStream + 1);
    check(!RelBinary::load_from_buffer(std::move(unaligned_fix)),
          "fixSize should retain four-byte structural alignment");
}

void test_ppc_encoding(const TestContext& context) {
    const auto& fixture_bytes = context.fixture_bytes;
    auto high_addr24 = fixture_bytes;
    set_relocation_type(
        high_addr24, fixture::kDolRelocationRecord, fixture::kAddr24);
    set_relocation_addend(
        high_addr24, fixture::kDolRelocationRecord, 0xfe000000);
    auto high_addr24_rel = RelBinary::load_from_buffer(std::move(high_addr24));
    check(high_addr24_rel.has_value(),
          "sign-extended high R_PPC_ADDR24 targets should load");
    const auto* applied_high_addr24 =
        find_relocation(**high_addr24_rel, fixture::kAddr24,
                        fixture::kLoadBase, fixture::kDolModuleId);
    check(applied_high_addr24 && applied_high_addr24->applied &&
              word_at(**high_addr24_rel, fixture::kLoadBase) == 0x4a000001,
          "R_PPC_ADDR24 should accept an all-one upper seven-bit target");

    auto overflowing_addr24 = fixture_bytes;
    set_relocation_type(
        overflowing_addr24, fixture::kDolRelocationRecord, fixture::kAddr24);
    set_relocation_addend(
        overflowing_addr24, fixture::kDolRelocationRecord, 0x02000000);
    auto overflowing_addr24_rel =
        RelBinary::load_from_buffer(std::move(overflowing_addr24));
    check(overflowing_addr24_rel.has_value(),
          "out-of-range R_PPC_ADDR24 should remain loader-visible");
    const auto* rejected_addr24 =
        find_relocation(**overflowing_addr24_rel, fixture::kAddr24,
                        fixture::kLoadBase, fixture::kDolModuleId);
    check(rejected_addr24 && !rejected_addr24->applied &&
              word_at(**overflowing_addr24_rel,
                      fixture::kLoadBase) == 0x48000001,
          "rejected R_PPC_ADDR24 should leave its instruction unchanged");

    auto unaligned_addr24 = fixture_bytes;
    set_relocation_type(
        unaligned_addr24, fixture::kDolRelocationRecord, fixture::kAddr24);
    set_relocation_addend(
        unaligned_addr24, fixture::kDolRelocationRecord, 0xfe000002);
    auto unaligned_addr24_rel =
        RelBinary::load_from_buffer(std::move(unaligned_addr24));
    const auto* rejected_unaligned_addr24 = unaligned_addr24_rel
        ? find_relocation(**unaligned_addr24_rel, fixture::kAddr24,
                          fixture::kLoadBase, fixture::kDolModuleId)
        : nullptr;
    check(rejected_unaligned_addr24 && !rejected_unaligned_addr24->applied &&
              word_at(**unaligned_addr24_rel,
                      fixture::kLoadBase) == 0x48000001,
          "unaligned R_PPC_ADDR24 targets should leave instructions unchanged");

    auto high_addr16 = fixture_bytes;
    set_relocation_type(
        high_addr16, fixture::kDolRelocationRecord, fixture::kAddr16);
    set_relocation_addend(
        high_addr16, fixture::kDolRelocationRecord, 0xffff8000);
    auto high_addr16_rel = RelBinary::load_from_buffer(std::move(high_addr16));
    check(high_addr16_rel.has_value(),
          "sign-extended high R_PPC_ADDR16 targets should load");
    const auto* applied_high_addr16 =
        find_relocation(**high_addr16_rel, fixture::kAddr16,
                        fixture::kLoadBase, fixture::kDolModuleId);
    check(applied_high_addr16 && applied_high_addr16->applied &&
              word_at(**high_addr16_rel, fixture::kLoadBase) == 0x80000001,
          "R_PPC_ADDR16 should accept an all-one upper seventeen-bit target");

    auto overflowing_addr16 = fixture_bytes;
    set_relocation_type(
        overflowing_addr16, fixture::kDolRelocationRecord, fixture::kAddr16);
    set_relocation_addend(
        overflowing_addr16, fixture::kDolRelocationRecord, 0x00008000);
    auto overflowing_addr16_rel =
        RelBinary::load_from_buffer(std::move(overflowing_addr16));
    check(overflowing_addr16_rel.has_value(),
          "out-of-range R_PPC_ADDR16 should remain loader-visible");
    const auto* rejected_addr16 =
        find_relocation(**overflowing_addr16_rel, fixture::kAddr16,
                        fixture::kLoadBase, fixture::kDolModuleId);
    check(rejected_addr16 && !rejected_addr16->applied &&
              word_at(**overflowing_addr16_rel,
                      fixture::kLoadBase) == 0x48000001,
          "rejected R_PPC_ADDR16 should leave its halfword unchanged");

    auto truncating_addr16_lo = fixture_bytes;
    set_relocation_type(truncating_addr16_lo,
                        fixture::kDolRelocationRecord,
                        fixture::kAddr16Lo);
    set_relocation_addend(
        truncating_addr16_lo, fixture::kDolRelocationRecord, 0x00008000);
    auto addr16_lo_rel =
        RelBinary::load_from_buffer(std::move(truncating_addr16_lo));
    const auto* applied_addr16_lo = addr16_lo_rel
        ? find_relocation(**addr16_lo_rel, fixture::kAddr16Lo,
                          fixture::kLoadBase, fixture::kDolModuleId)
        : nullptr;
    check(applied_addr16_lo && applied_addr16_lo->applied &&
              word_at(**addr16_lo_rel, fixture::kLoadBase) == 0x80000001,
          "R_PPC_ADDR16_LO should continue to truncate without a fit check");

    auto wrapping_addr16_ha = fixture_bytes;
    set_relocation_type(wrapping_addr16_ha,
                        fixture::kDolRelocationRecord,
                        fixture::kAddr16Ha);
    set_relocation_addend(
        wrapping_addr16_ha, fixture::kDolRelocationRecord, 0xffff8000);
    auto addr16_ha_rel =
        RelBinary::load_from_buffer(std::move(wrapping_addr16_ha));
    const auto* applied_addr16_ha = addr16_ha_rel
        ? find_relocation(**addr16_ha_rel, fixture::kAddr16Ha,
                          fixture::kLoadBase, fixture::kDolModuleId)
        : nullptr;
    check(applied_addr16_ha && applied_addr16_ha->applied &&
              word_at(**addr16_ha_rel, fixture::kLoadBase) == 0x00000001,
          "R_PPC_ADDR16_HA carry should wrap modulo PPC32");

    auto wrapping_rel24 = fixture_bytes;
    set_relocation_addend(
        wrapping_rel24, fixture::kDolRelocationRecord, 0x10);
    constexpr addr_t kWrappingLoadBase = 0xffffffdc;
    auto wrapping_rel24_binary = RelBinary::load_from_buffer(
        std::move(wrapping_rel24), kWrappingLoadBase);
    check(wrapping_rel24_binary.has_value(),
          "near-boundary REL24 fixture should fit in PPC32 layout");
    const auto* applied_wrapping_rel24 =
        find_relocation(**wrapping_rel24_binary, fixture::kRel24,
                        kWrappingLoadBase, fixture::kDolModuleId);
    check(applied_wrapping_rel24 && applied_wrapping_rel24->applied &&
              word_at(**wrapping_rel24_binary,
                      kWrappingLoadBase) == 0x48000035,
          "R_PPC_REL24 displacement should use modulo-2^32 subtraction");
}

void test_dtk_symbols(const TestContext& context) {
    const auto& fixture_bytes = context.fixture_bytes;
    LoadOptions options;
    options.dol_symbols_path = context.symbols_path;
    auto named = load_binary(context.rel_path, options);
    check(named.has_value(), "REL should load with DTK section-relative symbols");
    const auto* named_prolog = (*named)->find_by_name("fixture_prolog");
    const auto* named_data = (*named)->find_by_name("fixture_data");
    const auto* named_bss = (*named)->find_by_name("fixture_bss");
    check(named_prolog && named_prolog->addr == fixture::kLoadBase &&
              named_prolog->size == 0x10 && named_prolog->kind == SymbolKind::Function,
          "DTK .text function should map from its section-relative offset");
    check(named_data && named_data->addr == fixture::kDataAddress &&
              named_data->size == 8,
          "DTK .data object should map from its section-relative offset");
    check(named_bss && named_bss->addr == fixture::kBssAddress &&
              !named_bss->is_export,
          "DTK .bss local should preserve its scope and synthetic address");

    ScopedTempDirectory temp_directory;
    const auto oversized_symbols_path = temp_directory.file("symbols.txt");
    auto write_symbol_fixture = [&](std::string_view contents) {
        std::ofstream output(oversized_symbols_path, std::ios::trunc);
        check(output.good(), "temporary DTK symbol fixture should open");
        output.write(contents.data(), static_cast<std::streamsize>(contents.size()));
        check(output.good(), "temporary DTK symbol fixture should be written");
    };

    write_symbol_fixture(
        "fixture_endpoint = .data:0xc; // type:object size:0\n");
    auto endpoint_symbol_rel = RelBinary::load_from_buffer(fixture_bytes);
    check(endpoint_symbol_rel.has_value() &&
              (*endpoint_symbol_rel)->attach_dtk_symbols_from_path(
                  oversized_symbols_path).has_value(),
          "zero-sized DTK symbols should be accepted at a section endpoint");
    const auto* endpoint_symbol =
        (*endpoint_symbol_rel)->find_by_name("fixture_endpoint");
    check(endpoint_symbol && endpoint_symbol->addr == fixture::kBssAddress &&
              endpoint_symbol->size == 0,
          "an accepted DTK endpoint symbol should preserve its zero size");

    write_symbol_fixture(
        "fixture_endpoint = .data:0xc; // type:object size:1\n");
    auto nonzero_endpoint_rel = RelBinary::load_from_buffer(fixture_bytes);
    check(nonzero_endpoint_rel.has_value() &&
              !(*nonzero_endpoint_rel)->attach_dtk_symbols_from_path(
                  oversized_symbols_path),
          "nonzero DTK symbols at a section endpoint should be rejected");

    write_symbol_fixture(
        "fixture_escape = .data:0x8; // type:object size:0x8\n");
    auto oversized_symbol_rel = RelBinary::load_from_buffer(fixture_bytes);
    check(oversized_symbol_rel.has_value(),
          "REL should load before oversized DTK symbol validation");
    const auto oversized_symbol_result =
        (*oversized_symbol_rel)->attach_dtk_symbols_from_path(oversized_symbols_path);
    check(!oversized_symbol_result,
          "DTK symbol sizes extending past their section should be rejected");
}

}  // namespace

int main(int argc, char** argv) {
    try {
        check(argc == 3, "expected fixture and DTK symbols paths");
        TestContext context{
            argv[1], argv[2], read_fixture(argv[1]),
        };
        test_baseline(context);
        test_stream_structure(context);
        test_header_and_section_validation(context);
        test_ppc_encoding(context);
        test_dtk_symbols(context);
    } catch (const TestFailure&) {
        return 1;
    }
    return 0;
}
