#include <ember/binary/macho.hpp>

#include <array>
#include <cstdio>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

int fails = 0;

void check(bool condition, const char* message) {
    if (condition) return;
    std::fprintf(stderr, "FAIL: %s\n", message);
    ++fails;
}

void put32(std::vector<std::byte>& bytes, std::size_t off, ember::u32 value) {
    for (unsigned i = 0; i < 4; ++i) {
        bytes[off + i] = static_cast<std::byte>((value >> (i * 8)) & 0xff);
    }
}

void put16(std::vector<std::byte>& bytes, std::size_t off, ember::u16 value) {
    for (unsigned i = 0; i < 2; ++i) {
        bytes[off + i] = static_cast<std::byte>((value >> (i * 8)) & 0xff);
    }
}

void put64(std::vector<std::byte>& bytes, std::size_t off, ember::u64 value) {
    for (unsigned i = 0; i < 8; ++i) {
        bytes[off + i] = static_cast<std::byte>((value >> (i * 8)) & 0xff);
    }
}

void put_fixed_name(std::vector<std::byte>& bytes, std::size_t off,
                    std::string_view name) {
    for (std::size_t i = 0; i < name.size() && i < 16; ++i) {
        bytes[off + i] = static_cast<std::byte>(name[i]);
    }
}

void put_macho_segment(std::vector<std::byte>& bytes,
                       std::size_t command_offset,
                       ember::u32 command_size,
                       std::string_view name,
                       ember::u64 vmaddr,
                       ember::u64 vmsize,
                       ember::u64 fileoff,
                       ember::u64 filesize,
                       ember::u32 initprot,
                       ember::u32 section_count) {
    put32(bytes, command_offset + 0, 0x19);  // LC_SEGMENT_64
    put32(bytes, command_offset + 4, command_size);
    put_fixed_name(bytes, command_offset + 8, name);
    put64(bytes, command_offset + 24, vmaddr);
    put64(bytes, command_offset + 32, vmsize);
    put64(bytes, command_offset + 40, fileoff);
    put64(bytes, command_offset + 48, filesize);
    put32(bytes, command_offset + 60, initprot);
    put32(bytes, command_offset + 64, section_count);
}

std::vector<std::byte> macho_header(ember::u32 ncmds, ember::u32 sizeofcmds) {
    std::vector<std::byte> bytes(32 + sizeofcmds);
    put32(bytes, 0, 0xfeedfacf);
    put32(bytes, 4, 0x01000007);  // CPU_TYPE_X86_64
    put32(bytes, 16, ncmds);
    put32(bytes, 20, sizeofcmds);
    return bytes;
}

std::vector<std::byte> macho_chained_fixup(
    ember::u64 vmaddr,
    ember::u64 vmsize,
    ember::u64 fileoff,
    ember::u64 filesize,
    ember::u64 segment_offset = 0,
    ember::u16 page_start = 0)
{
    constexpr std::size_t segment_command = 32;
    constexpr std::size_t fixups_command = 104;
    constexpr std::size_t fixups_data = 120;

    auto bytes = macho_header(2, 88);
    bytes.resize(fixups_data + 64);

    put32(bytes, segment_command + 0, 0x19);  // LC_SEGMENT_64
    put32(bytes, segment_command + 4, 72);
    put64(bytes, segment_command + 24, vmaddr);
    put64(bytes, segment_command + 32, vmsize);
    put64(bytes, segment_command + 40, fileoff);
    put64(bytes, segment_command + 48, filesize);
    put32(bytes, segment_command + 60, 1);    // VM_PROT_READ

    put32(bytes, fixups_command + 0, 0x80000034);  // LC_DYLD_CHAINED_FIXUPS
    put32(bytes, fixups_command + 4, 16);
    put32(bytes, fixups_command + 8,
          static_cast<ember::u32>(fixups_data));
    put32(bytes, fixups_command + 12, 64);

    // dyld_chained_fixups_header followed by one starts-in-image entry and
    // one starts-in-segment record using DYLD_CHAINED_PTR_64.
    put32(bytes, fixups_data + 4, 32);   // starts_offset
    put32(bytes, fixups_data + 8, 64);   // imports_offset
    put32(bytes, fixups_data + 12, 64);  // symbols_offset
    put32(bytes, fixups_data + 20, 1);  // imports_format
    put32(bytes, fixups_data + 32, 1);  // seg_count
    put32(bytes, fixups_data + 36, 8);  // seg_info_offset[0]
    put32(bytes, fixups_data + 40, 24); // starts-in-segment size
    put16(bytes, fixups_data + 44, 0x1000);
    put16(bytes, fixups_data + 46, 2);  // DYLD_CHAINED_PTR_64
    put64(bytes, fixups_data + 48, segment_offset);
    put16(bytes, fixups_data + 60, 1);  // page_count
    put16(bytes, fixups_data + 62, page_start);
    return bytes;
}

std::vector<std::byte> macho_two_segment_chained_fixup(
    ember::u16 pointer_format,
    ember::u64 first_pointer,
    ember::u64 second_pointer)
{
    constexpr ember::u64 image_base = 0x100000000ull;
    constexpr std::size_t text_command = 32;
    constexpr std::size_t data_command = text_command + 72;
    constexpr std::size_t fixups_command = data_command + 72;
    constexpr std::size_t fixups_data = 0x1800;
    constexpr std::size_t chain_file_offset = 0x1100;

    auto bytes = macho_header(3, 160);
    bytes.resize(0x2000);
    put_macho_segment(bytes, text_command, 72, "__TEXT",
                      image_base, 0x1000, 0, 0x1000, 5, 0);
    put_macho_segment(bytes, data_command, 72, "__DATA",
                      image_base + 0x1000, 0x1000,
                      0x1000, 0x1000, 3, 0);

    put32(bytes, fixups_command + 0, 0x80000034);  // LC_DYLD_CHAINED_FIXUPS
    put32(bytes, fixups_command + 4, 16);
    put32(bytes, fixups_command + 8,
          static_cast<ember::u32>(fixups_data));
    put32(bytes, fixups_command + 12, 96);

    // starts_in_image contains one empty __TEXT entry and one __DATA record.
    put32(bytes, fixups_data + 4, 32);   // starts_offset
    put32(bytes, fixups_data + 8, 72);   // imports_offset
    put32(bytes, fixups_data + 12, 72);  // symbols_offset
    put32(bytes, fixups_data + 20, 1);   // imports_format
    put32(bytes, fixups_data + 32, 2);   // seg_count
    put32(bytes, fixups_data + 36, 0);   // no starts in __TEXT
    put32(bytes, fixups_data + 40, 12);  // __DATA starts record
    put32(bytes, fixups_data + 44, 24);  // record size
    put16(bytes, fixups_data + 48, 0x1000);
    put16(bytes, fixups_data + 50, pointer_format);
    put64(bytes, fixups_data + 52, 0x1000);  // image-relative segment offset
    put16(bytes, fixups_data + 64, 1);       // page_count
    put16(bytes, fixups_data + 66, 0x100);   // page_start

    put64(bytes, chain_file_offset, first_pointer);
    put64(bytes, chain_file_offset + 8, second_pointer);
    return bytes;
}

std::vector<std::byte> macho_pagezero_order_chained_fixup() {
    constexpr ember::u64 image_base = 0x100000000ull;
    constexpr std::size_t pagezero_command = 32;
    constexpr std::size_t text_command = pagezero_command + 72;
    constexpr std::size_t data_command = text_command + 72;
    constexpr std::size_t fixups_command = data_command + 72;
    constexpr std::size_t fixups_data = 0x1800;

    auto bytes = macho_header(4, 232);
    bytes.resize(0x2000);
    put_macho_segment(bytes, pagezero_command, 72, "__PAGEZERO",
                      0, image_base, 0, 0, 0, 0);
    put_macho_segment(bytes, text_command, 72, "__TEXT",
                      image_base, 0x1000, 0, 0x1000, 5, 0);
    put_macho_segment(bytes, data_command, 72, "__DATA",
                      image_base + 0x1000, 0x1000,
                      0x1000, 0x1000, 3, 0);
    put32(bytes, fixups_command + 0, 0x80000034);
    put32(bytes, fixups_command + 4, 16);
    put32(bytes, fixups_command + 8,
          static_cast<ember::u32>(fixups_data));
    put32(bytes, fixups_command + 12, 96);

    put32(bytes, fixups_data + 4, 32);   // starts_offset
    put32(bytes, fixups_data + 8, 72);   // imports_offset
    put32(bytes, fixups_data + 12, 72);  // symbols_offset
    put32(bytes, fixups_data + 20, 1);   // imports_format
    put32(bytes, fixups_data + 32, 3);   // seg_count
    put32(bytes, fixups_data + 36, 0);   // __PAGEZERO
    put32(bytes, fixups_data + 40, 0);   // __TEXT
    put32(bytes, fixups_data + 44, 16);  // __DATA record
    put32(bytes, fixups_data + 48, 24);
    put16(bytes, fixups_data + 52, 0x1000);
    put16(bytes, fixups_data + 54, 7);   // ARM64E_KERNEL
    put64(bytes, fixups_data + 56, 0x1000);
    put16(bytes, fixups_data + 68, 1);
    put16(bytes, fixups_data + 70, 0x100);
    put64(bytes, 0x1100, 0x123);
    return bytes;
}

std::vector<std::byte> macho_userland24_wide_ordinal() {
    constexpr std::size_t fixups_data = 0x2100;
    constexpr ember::u32 wide_ordinal = 0x10000;
    constexpr std::size_t import_count = wide_ordinal + 1u;
    constexpr std::size_t starts_offset = 32;
    constexpr std::size_t imports_offset = 72;
    constexpr std::size_t symbols_offset =
        imports_offset + import_count * 4u;
    constexpr std::size_t payload_size = symbols_offset + 11u;

    auto bytes = macho_two_segment_chained_fixup(
        12, (ember::u64{1} << 62) | wide_ordinal, 0);
    bytes.resize(fixups_data + payload_size);
    put32(bytes, 32 + 72 + 72 + 8,
          static_cast<ember::u32>(fixups_data));
    put32(bytes, 32 + 72 + 72 + 12,
          static_cast<ember::u32>(payload_size));

    put32(bytes, fixups_data + 4,
          static_cast<ember::u32>(starts_offset));
    put32(bytes, fixups_data + 8,
          static_cast<ember::u32>(imports_offset));
    put32(bytes, fixups_data + 12,
          static_cast<ember::u32>(symbols_offset));
    put32(bytes, fixups_data + 16,
          static_cast<ember::u32>(import_count));
    put32(bytes, fixups_data + 20, 1);
    put32(bytes, fixups_data + starts_offset, 2);
    put32(bytes, fixups_data + starts_offset + 4, 0);
    put32(bytes, fixups_data + starts_offset + 8, 12);
    put32(bytes, fixups_data + starts_offset + 12, 24);
    put16(bytes, fixups_data + starts_offset + 16, 0x1000);
    put16(bytes, fixups_data + starts_offset + 18, 12);
    put64(bytes, fixups_data + starts_offset + 20, 0x1000);
    put16(bytes, fixups_data + starts_offset + 32, 1);
    put16(bytes, fixups_data + starts_offset + 34, 0x100);

    put32(bytes, fixups_data + imports_offset, 0);          // "wrong"
    put32(bytes, fixups_data + imports_offset + wide_ordinal * 4u,
          6u << 9);                                        // "wide"
    constexpr std::string_view names{"wrong\0wide\0", 11};
    for (std::size_t i = 0; i < names.size(); ++i) {
        bytes[fixups_data + symbols_offset + i] =
            static_cast<std::byte>(names[i]);
    }
    return bytes;
}

ember::u64 read_mapped_u64(std::span<const std::byte> bytes) {
    if (bytes.size() < 8) return std::numeric_limits<ember::u64>::max();
    ember::u64 value = 0;
    for (unsigned i = 0; i < 8; ++i) {
        value |= static_cast<ember::u64>(bytes[i]) << (i * 8);
    }
    return value;
}

std::vector<std::byte> macho_bind_with_sleb(
    std::span<const std::byte> sleb)
{
    constexpr std::size_t segment_command = 32;
    constexpr std::size_t dyld_info_command = segment_command + 72;
    constexpr std::size_t bind_offset = dyld_info_command + 48;

    std::vector<std::byte> stream;
    stream.push_back(std::byte{0x40});  // SET_SYMBOL_TRAILING_FLAGS_IMM
    for (char c : std::string_view("sleb_ok")) {
        stream.push_back(static_cast<std::byte>(c));
    }
    stream.push_back(std::byte{0});
    stream.push_back(std::byte{0x70});  // SET_SEGMENT_AND_OFFSET_ULEB, segment 0
    stream.push_back(std::byte{0});
    stream.push_back(std::byte{0x60});  // SET_ADDEND_SLEB
    for (std::byte b : sleb) stream.push_back(b);
    stream.push_back(std::byte{0x90});  // DO_BIND
    stream.push_back(std::byte{0});     // DONE

    auto bytes = macho_header(2, 120);
    bytes.resize(bind_offset + stream.size());
    put_macho_segment(bytes, segment_command, 72, "__DATA",
                      0x1000, 0x100, 0, 0, 3, 0);
    put32(bytes, dyld_info_command + 0, 0x22);  // LC_DYLD_INFO
    put32(bytes, dyld_info_command + 4, 48);
    put32(bytes, dyld_info_command + 16,
          static_cast<ember::u32>(bind_offset));
    put32(bytes, dyld_info_command + 20,
          static_cast<ember::u32>(stream.size()));
    for (std::size_t i = 0; i < stream.size(); ++i) {
        bytes[bind_offset + i] = stream[i];
    }
    return bytes;
}

std::vector<std::byte> macho_section(
    ember::u64 section_addr,
    ember::u64 section_size,
    ember::u32 section_offset)
{
    constexpr std::size_t segment_command = 32;
    constexpr std::size_t section_header = segment_command + 72;

    auto bytes = macho_header(1, 152);
    bytes.resize(208);
    put_macho_segment(bytes, segment_command, 152, "__DATA",
                      0x1000, 0x10, 184, 8, 1, 1);
    put_fixed_name(bytes, section_header + 0, "__test");
    put_fixed_name(bytes, section_header + 16, "__DATA");
    put64(bytes, section_header + 32, section_addr);
    put64(bytes, section_header + 40, section_size);
    put32(bytes, section_header + 48, section_offset);
    return bytes;
}

std::vector<std::byte> macho_mapping_with_pagezero(ember::u64 mapped_size)
{
    constexpr std::size_t text_command = 32;
    constexpr std::size_t pagezero_command = text_command + 72;

    auto bytes = macho_header(2, 144);
    put_macho_segment(bytes, text_command, 72, "__TEXT",
                      0x4000, mapped_size, 0, 0, 4, 0);
    put_macho_segment(bytes, pagezero_command, 72, "__PAGEZERO",
                      0, 0x4000, 0, 0, 0, 0);
    return bytes;
}

void test_macho_validates_command_count_before_allocating() {
    check(!ember::MachOBinary::load_from_buffer(macho_header(0xffffffff, 0)),
          "Mach-O rejects impossible load-command count");
    check(!ember::MachOBinary::load_from_buffer(macho_header(1, 0)),
          "Mach-O rejects command count without command bytes");

    auto malformed = macho_header(1, 8);
    put32(malformed, 32, 1);
    put32(malformed, 36, 4);  // cmdsize must be at least 8
    check(!ember::MachOBinary::load_from_buffer(std::move(malformed)),
          "Mach-O rejects undersized load command");
}

void test_macho_rejects_unmapped_initialized_tables() {
    auto symtab = macho_header(1, 24);
    put32(symtab, 32, 0x2);          // LC_SYMTAB
    put32(symtab, 36, 24);
    put32(symtab, 40, 56);           // symoff
    put32(symtab, 44, 0xffffffff);   // nsyms: must not allocate from this
    put32(symtab, 48, 56);           // stroff
    put32(symtab, 52, 0);            // strsize
    check(!ember::MachOBinary::load_from_buffer(std::move(symtab)),
          "Mach-O rejects an out-of-file symbol table before allocation");

    auto segment = macho_header(1, 72);
    put32(segment, 32, 0x19);        // LC_SEGMENT_64
    put32(segment, 36, 72);
    put64(segment, 56, 0x100000000); // vmaddr
    put64(segment, 64, 0x1000);      // vmsize
    put64(segment, 72, 0xffffffff);  // fileoff
    put64(segment, 80, 0x10);        // filesize
    put32(segment, 92, 1);           // initprot = read
    check(!ember::MachOBinary::load_from_buffer(std::move(segment)),
          "Mach-O rejects initialized segment bytes outside the image");

    auto empty_at_invalid_offset = macho_header(1, 72);
    put_macho_segment(empty_at_invalid_offset, 32, 72, "__DATA",
                      0x1000, 0x1000,
                      std::numeric_limits<ember::u64>::max(), 0, 1, 0);
    check(!ember::MachOBinary::load_from_buffer(
              std::move(empty_at_invalid_offset)),
          "Mach-O rejects an empty segment whose file offset is outside the image");
}

void test_macho_rejects_unsupported_cpu() {
    auto bytes = macho_header(0, 0);
    put32(bytes, 4, 0x7fffffff);
    auto loaded = ember::MachOBinary::load_from_buffer(std::move(bytes));
    check(!loaded && loaded.error().kind == ember::ErrorKind::UnsupportedFormat,
          "Mach-O rejects an unsupported CPU type");
}

void test_macho_sections_stay_within_their_declaring_segment() {
    auto virtual_overrun = ember::MachOBinary::load_from_buffer(
        macho_section(0x100f, 2, 184));
    check(!virtual_overrun &&
              virtual_overrun.error().kind == ember::ErrorKind::InvalidFormat,
          "Mach-O rejects a section whose virtual end exceeds its segment");

    auto file_overrun = ember::MachOBinary::load_from_buffer(
        macho_section(0x1000, 2, 191));
    check(!file_overrun &&
              file_overrun.error().kind == ember::ErrorKind::InvalidFormat,
          "Mach-O rejects a globally backed section outside its segment file range");

    auto wrong_segment_name = macho_section(0x1000, 2, 184);
    put_fixed_name(wrong_segment_name, 32 + 72 + 16, "__TEXT");
    auto wrong_segment_result = ember::MachOBinary::load_from_buffer(
        std::move(wrong_segment_name));
    check(!wrong_segment_result &&
              wrong_segment_result.error().kind == ember::ErrorKind::InvalidFormat,
          "Mach-O rejects a section that names a different declaring segment");

    auto incongruent = ember::MachOBinary::load_from_buffer(
        macho_section(0x1001, 2, 184));
    check(!incongruent &&
              incongruent.error().kind == ember::ErrorKind::InvalidFormat,
          "Mach-O rejects inconsistent section file and virtual offsets");

    auto object = macho_section(0x1000, 2, 184);
    put32(object, 12, 1);  // MH_OBJECT
    for (std::size_t i = 0; i < 16; ++i) object[32 + 8 + i] = std::byte{0};
    auto object_result = ember::MachOBinary::load_from_buffer(std::move(object));
    check(object_result.has_value() &&
              (*object_result)->sections().size() == 1 &&
              (*object_result)->sections().front().name == "__DATA,__test",
          "Mach-O accepts MH_OBJECT sections in an anonymous segment");

    auto anonymous_section_name = macho_section(0x1000, 2, 184);
    for (std::size_t i = 0; i < 16; ++i) {
        anonymous_section_name[32 + 72 + 16 + i] = std::byte{0};
    }
    auto anonymous_section_result = ember::MachOBinary::load_from_buffer(
        std::move(anonymous_section_name));
    check(anonymous_section_result.has_value() &&
              (*anonymous_section_result)->sections().front().name ==
                  "__DATA,__test",
          "Mach-O accepts an empty section segname as its enclosing segment");

    auto dsym_placeholder = macho_section(0x1000, 2, 0);
    put32(dsym_placeholder, 12, 0x0a);  // MH_DSYM
    auto dsym_placeholder_result = ember::MachOBinary::load_from_buffer(
        std::move(dsym_placeholder));
    check(dsym_placeholder_result.has_value() &&
              (*dsym_placeholder_result)->sections().size() == 1 &&
              (*dsym_placeholder_result)->sections().front().data.empty(),
          "Mach-O accepts an unbacked dSYM placeholder section");

    auto compact_dsym_section = macho_section(0x1004, 2, 184);
    put32(compact_dsym_section, 12, 0x0a);  // MH_DSYM
    compact_dsym_section[184] = std::byte{0x5a};
    compact_dsym_section[188] = std::byte{0xa5};
    auto compact_dsym_result = ember::MachOBinary::load_from_buffer(
        std::move(compact_dsym_section));
    check(compact_dsym_result.has_value() &&
              (*compact_dsym_result)->sections().front().data.size() == 2 &&
              !(*compact_dsym_result)->bytes_at(0x1004).empty() &&
              (*compact_dsym_result)->bytes_at(0x1004).front() ==
                  std::byte{0x5a},
          "Mach-O accepts compacted dSYM data at a preserved virtual offset");

    auto dylib_stub = macho_section(0x1000, 2, 0);
    put32(dylib_stub, 12, 0x09);  // MH_DYLIB_STUB
    put64(dylib_stub, 32 + 48, 0);
    auto dylib_stub_result = ember::MachOBinary::load_from_buffer(
        std::move(dylib_stub));
    check(dylib_stub_result.has_value() &&
              (*dylib_stub_result)->sections().size() == 1 &&
              (*dylib_stub_result)->sections().front().data.empty(),
          "Mach-O accepts metadata-only MH_DYLIB_STUB sections");

    auto stripped_dylib_stub = macho_section(0, 0, 0);
    put32(stripped_dylib_stub, 12, 0x09);  // MH_DYLIB_STUB
    put64(stripped_dylib_stub, 32 + 48, 0);
    auto stripped_stub_result = ember::MachOBinary::load_from_buffer(
        std::move(stripped_dylib_stub));
    check(stripped_stub_result.has_value() &&
              (*stripped_stub_result)->sections().size() == 1,
          "Mach-O accepts zeroed strip-c section metadata");

    auto oversized_file = macho_header(1, 72);
    oversized_file.resize(105);
    put_macho_segment(oversized_file, 32, 72, "__DATA",
                      0x1000, 0x10, 104, 1, 1, 0);
    put64(oversized_file, 32 + 32, 0);  // vmsize
    auto oversized_result = ember::MachOBinary::load_from_buffer(
        std::move(oversized_file));
    check(!oversized_result &&
              oversized_result.error().kind == ember::ErrorKind::InvalidFormat,
          "Mach-O rejects a mapped segment whose file size exceeds virtual size");

    auto nonalloc_payload = macho_header(1, 72);
    nonalloc_payload.resize(105);
    put_macho_segment(nonalloc_payload, 32, 72, "__DWARF",
                      0, 0, 104, 1, 0, 0);
    put32(nonalloc_payload, 32 + 56, 1);  // maxprot may remain readable
    auto nonalloc_result = ember::MachOBinary::load_from_buffer(
        std::move(nonalloc_payload));
    check(nonalloc_result.has_value() &&
              (*nonalloc_result)->segments().empty(),
          "Mach-O accepts a nonallocating file payload with zero virtual size");

    auto nonalloc_section = macho_header(1, 152);
    nonalloc_section.resize(185);
    put_macho_segment(nonalloc_section, 32, 152, "__DWARF",
                      0x2000, 0, 184, 1, 0, 1);
    put32(nonalloc_section, 32 + 56, 1);  // maxprot
    put_fixed_name(nonalloc_section, 32 + 72, "__debug_info");
    put_fixed_name(nonalloc_section, 32 + 72 + 16, "__DWARF");
    put64(nonalloc_section, 32 + 72 + 32, 0x2000);
    put64(nonalloc_section, 32 + 72 + 40, 1);
    put32(nonalloc_section, 32 + 72 + 48, 184);
    nonalloc_section[184] = std::byte{0x5a};
    auto nonalloc_section_result = ember::MachOBinary::load_from_buffer(
        std::move(nonalloc_section));
    check(nonalloc_section_result.has_value() &&
              (*nonalloc_section_result)->sections().size() == 1 &&
              !(*nonalloc_section_result)->sections().front().flags.allocated &&
              (*nonalloc_section_result)->sections().front().data.size() == 1,
          "Mach-O retains file-only __DWARF sections as nonallocated data");

    auto overlapping_files = macho_header(2, 144);
    overlapping_files.resize(177);
    put_macho_segment(overlapping_files, 32, 72, "__TEXT",
                      0x1000, 1, 176, 1, 5, 0);
    put_macho_segment(overlapping_files, 32 + 72, 72, "__DATA",
                      0x2000, 1, 176, 1, 3, 0);
    check(!ember::MachOBinary::load_from_buffer(std::move(overlapping_files)),
          "Mach-O rejects overlapping nonempty segment file ranges");
}

void test_macho_load_segments_are_mapping_authority() {
    auto execute_only = ember::MachOBinary::load_from_buffer(
        macho_mapping_with_pagezero(0x2000));
    check(execute_only.has_value(),
          "Mach-O with an execute-only segment and __PAGEZERO loads");
    if (execute_only) {
        const auto segments = (*execute_only)->segments();
        check(segments.size() == 1 && segments.front().executable &&
                  !segments.front().readable &&
                  (*execute_only)->preferred_load_base() == 0x4000 &&
                  (*execute_only)->mapped_size() == 0x2000,
              "execute-only Mach-O segments contribute to the mapped extent");
        check((*execute_only)->sections().empty(),
              "canonical __PAGEZERO contributes no section metadata");
        check((*execute_only)->bytes_at(0).empty(),
              "Mach-O does not fall back to section bytes outside loadable segments");
    }

    auto zero_sized = ember::MachOBinary::load_from_buffer(
        macho_mapping_with_pagezero(0));
    check(zero_sized.has_value(), "Mach-O with a zero-sized segment still loads");
    if (zero_sized) {
        check((*zero_sized)->segments().empty() &&
                  (*zero_sized)->preferred_load_base() == 0 &&
                  (*zero_sized)->mapped_size() == 0 &&
                  (*zero_sized)->bytes_at(0).empty(),
              "zero-sized Mach-O segment presence suppresses section fallback");
    }

    auto file_backed_pagezero = macho_mapping_with_pagezero(0x1000);
    file_backed_pagezero.resize(file_backed_pagezero.size() + 1);
    put64(file_backed_pagezero, 32 + 72 + 48, 1);
    check(!ember::MachOBinary::load_from_buffer(
              std::move(file_backed_pagezero)),
          "Mach-O rejects file-backed __PAGEZERO data");

    auto sectioned_pagezero = macho_header(1, 152);
    put_macho_segment(sectioned_pagezero, 32, 152, "__PAGEZERO",
                      0, 0x4000, 0, 0, 0, 1);
    put_fixed_name(sectioned_pagezero, 32 + 72, "__hidden");
    put_fixed_name(sectioned_pagezero, 32 + 72 + 16, "__PAGEZERO");
    check(!ember::MachOBinary::load_from_buffer(
              std::move(sectioned_pagezero)),
          "Mach-O rejects sections declared inside __PAGEZERO");

    auto highvm = macho_header(1, 72);
    put_macho_segment(highvm, 32, 72, "__DATA",
                      0x1000, 0x1000, 0, 0, 1, 0);
    put32(highvm, 32 + 68, 1);  // SG_HIGHVM
    auto highvm_result = ember::MachOBinary::load_from_buffer(
        std::move(highvm));
    check(!highvm_result &&
              highvm_result.error().kind == ember::ErrorKind::UnsupportedFormat,
          "Mach-O rejects unsupported SG_HIGHVM mapping explicitly");

    auto renamed_reservation = macho_mapping_with_pagezero(0x2000);
    for (std::size_t i = 0; i < 16; ++i) {
        renamed_reservation[32 + 72 + 8 + i] = std::byte{0};
    }
    put_fixed_name(renamed_reservation, 32 + 72 + 8, "__GUARD");
    auto renamed_result = ember::MachOBinary::load_from_buffer(
        std::move(renamed_reservation));
    check(renamed_result.has_value() &&
              (*renamed_result)->segments().size() == 1 &&
              (*renamed_result)->preferred_load_base() == 0x4000,
          "Mach-O recognizes a structural null reservation under another name");

    auto misplaced_pagezero = macho_mapping_with_pagezero(0x1000);
    put64(misplaced_pagezero, 32 + 72 + 24, 1);
    check(!ember::MachOBinary::load_from_buffer(
              std::move(misplaced_pagezero)),
          "Mach-O rejects a named __PAGEZERO outside address zero");

    auto overlapping_pagezero = macho_mapping_with_pagezero(0x2000);
    put64(overlapping_pagezero, 32 + 24, 0x1000);
    check(!ember::MachOBinary::load_from_buffer(
              std::move(overlapping_pagezero)),
          "Mach-O rejects a load segment that overlaps the null reservation");

    auto overlapping = macho_header(2, 144);
    put_macho_segment(overlapping, 32, 72, "__TEXT",
                      0x1000, 0x1000, 0, 0, 5, 0);
    put_macho_segment(overlapping, 32 + 72, 72, "__DATA",
                      0x1800, 0x1000, 0, 0, 3, 0);
    check(!ember::MachOBinary::load_from_buffer(std::move(overlapping)),
          "Mach-O rejects overlapping mapped segment ranges");
}

void test_macho_rejects_overflowing_bind_sleb_without_ub() {
    auto overflowing = macho_header(1, 48);
    overflowing.resize(91);
    put32(overflowing, 32, 0x22);  // LC_DYLD_INFO
    put32(overflowing, 36, 48);
    put32(overflowing, 48, 80);    // bind_off
    put32(overflowing, 52, 11);    // bind_size
    overflowing[80] = std::byte{0x60};  // BIND_OPCODE_SET_ADDEND_SLEB
    for (std::size_t i = 81; i < 90; ++i) overflowing[i] = std::byte{0x80};
    overflowing[90] = std::byte{0x02};  // payload spills beyond bit 63
    check(ember::MachOBinary::load_from_buffer(std::move(overflowing)).has_value(),
          "Mach-O ignores an overflowing ten-byte bind SLEB without undefined shifts");

    auto unterminated = macho_header(1, 48);
    unterminated.resize(91);
    put32(unterminated, 32, 0x22);  // LC_DYLD_INFO
    put32(unterminated, 36, 48);
    put32(unterminated, 48, 80);    // bind_off
    put32(unterminated, 52, 11);    // bind_size
    unterminated[80] = std::byte{0x60};
    for (std::size_t i = 81; i < 91; ++i) unterminated[i] = std::byte{0x80};
    check(ember::MachOBinary::load_from_buffer(std::move(unterminated)).has_value(),
          "Mach-O stops at a bind SLEB that requests an eleventh byte");

    const std::array<std::byte, 10> maximum{
        std::byte{0xff}, std::byte{0xff}, std::byte{0xff}, std::byte{0xff},
        std::byte{0xff}, std::byte{0xff}, std::byte{0xff}, std::byte{0xff},
        std::byte{0xff}, std::byte{0x00}};
    const std::array<std::byte, 10> minimum{
        std::byte{0x80}, std::byte{0x80}, std::byte{0x80}, std::byte{0x80},
        std::byte{0x80}, std::byte{0x80}, std::byte{0x80}, std::byte{0x80},
        std::byte{0x80}, std::byte{0x7f}};

    auto valid_extreme_reaches_bind = [](std::span<const std::byte> encoding) {
        auto loaded = ember::MachOBinary::load_from_buffer(
            macho_bind_with_sleb(encoding));
        if (!loaded) return false;
        for (const auto& symbol : (*loaded)->symbols()) {
            if (symbol.name == "sleb_ok" && symbol.got_addr == 0x1000) {
                return true;
            }
        }
        return false;
    };
    check(valid_extreme_reaches_bind(maximum),
          "Mach-O accepts INT64_MAX SLEB and processes the following bind");
    check(valid_extreme_reaches_bind(minimum),
          "Mach-O accepts INT64_MIN SLEB and processes the following bind");
}

void test_macho_bounds_chained_fixup_address_arithmetic() {
    constexpr ember::u64 packed_rebase =
        (ember::u64{0xab} << 36) | ember::u64{0x1234};
    auto wrapped_start = macho_chained_fixup(
        0, 0x1000, 184, 8, std::numeric_limits<ember::u64>::max(), 1);
    wrapped_start.resize(192);
    put64(wrapped_start, 184, packed_rebase);
    auto wrapped_start_result =
        ember::MachOBinary::load_from_buffer(std::move(wrapped_start));
    check(wrapped_start_result.has_value(),
          "Mach-O ignores a chained-fixup start address that wraps");
    if (wrapped_start_result) {
        const auto mapped = (*wrapped_start_result)->bytes_at(0);
        bool unchanged = mapped.size() >= 8;
        for (unsigned i = 0; unchanged && i < 8; ++i) {
            unchanged = mapped[i] == static_cast<std::byte>(
                (packed_rebase >> (i * 8)) & 0xff);
        }
        check(unchanged,
              "Mach-O does not apply a chained fixup reached only through wrapping");
    }

    constexpr ember::u64 vmaddr =
        std::numeric_limits<ember::u64>::max() - 15;
    auto advancing = macho_chained_fixup(vmaddr, 15, 184, 8);
    advancing.resize(192);
    put64(advancing, 184, ember::u64{0xfff} << 51);  // maximum next delta
    auto advancing_result =
        ember::MachOBinary::load_from_buffer(std::move(advancing));
    check(advancing_result.has_value(),
          "Mach-O stops a chained fixup before its next address wraps");
    if (advancing_result) {
        const auto mapped = (*advancing_result)->bytes_at(vmaddr);
        bool decoded_current = mapped.size() >= 8;
        for (unsigned i = 0; decoded_current && i < 8; ++i) {
            decoded_current = mapped[i] == std::byte{0};
        }
        check(decoded_current,
              "Mach-O applies the current chained fixup before bounding its next address");
    }

    auto redirected = macho_two_segment_chained_fixup(7, 0, 0);
    constexpr std::size_t fixups_data = 0x1800;
    constexpr ember::u64 redirected_raw = 0x777;
    put64(redirected, fixups_data + 52, 0x1010);  // not __DATA's offset
    put64(redirected, 0x1110, redirected_raw);
    auto redirected_result = ember::MachOBinary::load_from_buffer(
        std::move(redirected));
    check(redirected_result.has_value() &&
              read_mapped_u64((*redirected_result)->bytes_at(
                  0x100000000ull + 0x1110)) == redirected_raw,
          "Mach-O ignores starts whose segment offset disagrees with the segment table");

    auto overlapping_metadata = macho_two_segment_chained_fixup(7, 0, 0);
    constexpr ember::u64 boundary_raw = 0x888;
    put32(overlapping_metadata, fixups_data + 8, 64);   // imports_offset
    put32(overlapping_metadata, fixups_data + 12, 68); // symbols_offset
    put32(overlapping_metadata, fixups_data + 16, 1);  // imports_count
    put64(overlapping_metadata, 0x1100, boundary_raw);
    auto overlapping_metadata_result = ember::MachOBinary::load_from_buffer(
        std::move(overlapping_metadata));
    check(overlapping_metadata_result.has_value() &&
              read_mapped_u64((*overlapping_metadata_result)->bytes_at(
                  0x100000000ull + 0x1100)) == boundary_raw,
          "Mach-O does not read chained starts through the imports partition");

    auto tiny_pages = macho_two_segment_chained_fixup(7, 0, 0);
    constexpr ember::u64 tiny_page_raw = 0x999;
    put32(tiny_pages, fixups_data + 44, 26);  // two page starts
    put16(tiny_pages, fixups_data + 48, 1);   // invalid page size
    put16(tiny_pages, fixups_data + 64, 2);
    put16(tiny_pages, fixups_data + 66, 0xffff);
    put16(tiny_pages, fixups_data + 68, 0);
    put64(tiny_pages, 0x1001, tiny_page_raw);
    auto tiny_pages_result = ember::MachOBinary::load_from_buffer(
        std::move(tiny_pages));
    check(tiny_pages_result.has_value() &&
              read_mapped_u64((*tiny_pages_result)->bytes_at(
                  0x100000000ull + 0x1001)) == tiny_page_raw,
          "Mach-O rejects nonstandard chained-fixup page sizes");

    auto record_in_offsets = macho_two_segment_chained_fixup(7, 0, 0);
    constexpr ember::u64 offset_record_raw = 0xaaa;
    put32(record_in_offsets, fixups_data + 36, 8);   // record begins at entry 1
    put32(record_in_offsets, fixups_data + 40, 24);  // also record size
    put16(record_in_offsets, fixups_data + 44, 0x1000);
    put16(record_in_offsets, fixups_data + 46, 7);
    put64(record_in_offsets, fixups_data + 48, 0);
    put16(record_in_offsets, fixups_data + 60, 1);
    put16(record_in_offsets, fixups_data + 62, 0x300);
    put64(record_in_offsets, 0x300, offset_record_raw);
    auto offset_record_result = ember::MachOBinary::load_from_buffer(
        std::move(record_in_offsets));
    check(offset_record_result.has_value() &&
              read_mapped_u64((*offset_record_result)->bytes_at(
                  0x100000000ull + 0x300)) == offset_record_raw,
          "Mach-O does not treat segment-offset entries as starts records");

    auto unaligned_arm64e = macho_two_segment_chained_fixup(1, 0, 0);
    constexpr ember::u64 unaligned_arm64e_raw = 0xbbb;
    put16(unaligned_arm64e, fixups_data + 66, 4);
    put64(unaligned_arm64e, 0x1004, unaligned_arm64e_raw);
    auto unaligned_arm64e_result = ember::MachOBinary::load_from_buffer(
        std::move(unaligned_arm64e));
    check(unaligned_arm64e_result.has_value() &&
              read_mapped_u64((*unaligned_arm64e_result)->bytes_at(
                  0x100000000ull + 0x1004)) == unaligned_arm64e_raw,
          "Mach-O ignores an ARM64E fixup that is not eight-byte aligned");

    auto unaligned_kernel = macho_two_segment_chained_fixup(7, 0, 0);
    constexpr ember::u64 unaligned_kernel_raw = 0xccc;
    put16(unaligned_kernel, fixups_data + 66, 2);
    put64(unaligned_kernel, 0x1002, unaligned_kernel_raw);
    auto unaligned_kernel_result = ember::MachOBinary::load_from_buffer(
        std::move(unaligned_kernel));
    check(unaligned_kernel_result.has_value() &&
              read_mapped_u64((*unaligned_kernel_result)->bytes_at(
                  0x100000000ull + 0x1002)) == unaligned_kernel_raw,
          "Mach-O ignores a kernel fixup that is not four-byte aligned");

    auto compressed_symbols = macho_two_segment_chained_fixup(7, 0xddd, 0);
    put32(compressed_symbols, fixups_data + 24, 1);
    auto compressed_symbols_result = ember::MachOBinary::load_from_buffer(
        std::move(compressed_symbols));
    check(compressed_symbols_result.has_value() &&
              read_mapped_u64((*compressed_symbols_result)->bytes_at(
                  0x100000000ull + 0x1100)) == 0xddd,
          "Mach-O ignores unsupported compressed chained symbol pools");
}

void test_macho_chained_pointer_formats_and_segment_offsets() {
    constexpr ember::u64 image_base = 0x100000000ull;
    constexpr ember::u64 second_slot = image_base + 0x1108;

    auto decoded_second = [&](ember::u16 format,
                              ember::u64 first,
                              ember::u64 second) {
        auto loaded = ember::MachOBinary::load_from_buffer(
            macho_two_segment_chained_fixup(format, first, second));
        check(loaded.has_value(), "two-segment chained-fixup Mach-O loads");
        if (!loaded) return std::numeric_limits<ember::u64>::max();
        return read_mapped_u64((*loaded)->bytes_at(second_slot));
    };

    // Format 1 advances in 8-byte units. Authenticated targets in every
    // arm64e format are runtime offsets from the image base.
    const ember::u64 format1 = decoded_second(
        1, (ember::u64{1} << 51) | 0x111,
        (ember::u64{1} << 63) | 0x222);
    check(format1 == image_base + 0x222,
          "ARM64E format 1 uses stride 8 and image-relative auth targets");
    auto format1_absolute_image = ember::MachOBinary::load_from_buffer(
        macho_two_segment_chained_fixup(
            1, (ember::u64{1} << 51) | 0x111,
            (ember::u64{1} << 63) | 0x222));
    check(format1_absolute_image.has_value() &&
              read_mapped_u64((*format1_absolute_image)->bytes_at(
                  image_base + 0x1100)) == 0x111,
          "ARM64E format 1 keeps unauthenticated absolute targets absolute");

    // Kernel and firmware formats use a 4-byte stride, so next=2 reaches
    // the qword eight bytes later.
    const ember::u64 format7 = decoded_second(
        7, (ember::u64{2} << 51) | 0x111, 0x333);
    check(format7 == image_base + 0x333,
          "ARM64E kernel format 7 uses stride 4 and VM-offset targets");

    constexpr ember::u64 firmware_raw =
        (ember::u64{0xab} << 43) | 0x444;
    const ember::u64 format10 = decoded_second(
        10, (ember::u64{2} << 51) | 0x111, firmware_raw);
    check(format10 == (ember::u64{0xab} << 56) + 0x444,
          "ARM64E firmware format 10 uses stride 4 and absolute targets");

    constexpr ember::u64 userland24_raw =
        (ember::u64{0xcd} << 43) | 0x555;
    const ember::u64 format12 = decoded_second(
        12, (ember::u64{1} << 51) | 0x111, userland24_raw);
    check(format12 == ((ember::u64{0xcd} << 56) | (image_base + 0x555)),
          "ARM64E userland24 format 12 uses stride 8 and VM-offset targets");

    auto below_text = macho_two_segment_chained_fixup(7, 0x999, 0);
    put64(below_text, 32 + 24, 0x2000);       // __TEXT vmaddr / image base
    put64(below_text, 32 + 72 + 24, 0x1000); // __DATA lies below __TEXT
    put64(below_text, 0x1800 + 52,
          std::numeric_limits<ember::u64>::max() - 0x0fff);
    auto below_text_result = ember::MachOBinary::load_from_buffer(
        std::move(below_text));
    check(below_text_result.has_value() &&
              read_mapped_u64((*below_text_result)->bytes_at(0x1100)) == 0x2999,
          "Mach-O accepts modulo-encoded starts for a segment below __TEXT");

    auto decode_straddling = [&](ember::u16 format, ember::u64 raw) {
        auto bytes = macho_two_segment_chained_fixup(format, 0, 0);
        bytes.resize(0x2004);
        put64(bytes, 32 + 72 + 32, 0x1004);  // __DATA vmsize
        put64(bytes, 32 + 72 + 48, 0x1004);  // __DATA filesize
        put16(bytes, 0x1800 + 66, 0x0ffc);   // final four bytes of the page
        put64(bytes, 0x1ffc, raw);
        auto loaded = ember::MachOBinary::load_from_buffer(std::move(bytes));
        check(loaded.has_value(), "straddling chained-fixup Mach-O loads");
        if (!loaded) return std::numeric_limits<ember::u64>::max();
        return read_mapped_u64((*loaded)->bytes_at(image_base + 0x1ffc));
    };
    check(decode_straddling(7, 0x666) == image_base + 0x666,
          "ARM64E kernel fixup may start four bytes before a page boundary");
    constexpr ember::u64 straddling_firmware =
        (ember::u64{0xee} << 43) | 0x777;
    check(decode_straddling(10, straddling_firmware) ==
              ((ember::u64{0xee} << 56) | 0x777),
          "ARM64E firmware fixup may straddle a backed page boundary");

    auto conventional_order = ember::MachOBinary::load_from_buffer(
        macho_pagezero_order_chained_fixup());
    check(conventional_order.has_value() &&
              read_mapped_u64((*conventional_order)->bytes_at(
                  image_base + 0x1100)) == image_base + 0x123,
          "PAGEZERO keeps chained-fixup segment indices aligned");

    auto wide_ordinal = ember::MachOBinary::load_from_buffer(
        macho_userland24_wide_ordinal());
    bool recovered_wide_import = false;
    if (wide_ordinal) {
        for (const auto& symbol : (*wide_ordinal)->symbols()) {
            recovered_wide_import |=
                symbol.name == "wide" && symbol.got_addr == image_base + 0x1100;
        }
    }
    check(wide_ordinal.has_value() && recovered_wide_import,
          "ARM64E userland24 preserves a 24-bit bind ordinal");
}

}  // namespace

int main() {
    test_macho_validates_command_count_before_allocating();
    test_macho_rejects_unmapped_initialized_tables();
    test_macho_rejects_unsupported_cpu();
    test_macho_sections_stay_within_their_declaring_segment();
    test_macho_load_segments_are_mapping_authority();
    test_macho_rejects_overflowing_bind_sleb_without_ub();
    test_macho_bounds_chained_fixup_address_arithmetic();
    test_macho_chained_pointer_formats_and_segment_offsets();
    return fails == 0 ? 0 : 1;
}
