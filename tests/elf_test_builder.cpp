#include "elf_test_builder.hpp"

#include <limits>

#include <spelunk/common/bytes.hpp>

namespace elf_test {
namespace {

void put16(std::vector<std::byte>& bytes, std::size_t off, spelunk::u16 value) {
    for (unsigned i = 0; i < 2; ++i) {
        bytes[off + i] = static_cast<std::byte>((value >> (i * 8)) & 0xff);
    }
}

void put32(std::vector<std::byte>& bytes, std::size_t off, spelunk::u32 value) {
    for (unsigned i = 0; i < 4; ++i) {
        bytes[off + i] = static_cast<std::byte>((value >> (i * 8)) & 0xff);
    }
}

void put64(std::vector<std::byte>& bytes, std::size_t off, spelunk::u64 value) {
    for (unsigned i = 0; i < 8; ++i) {
        bytes[off + i] = static_cast<std::byte>((value >> (i * 8)) & 0xff);
    }
}

void put64_be(std::vector<std::byte>& bytes, std::size_t off, spelunk::u64 value) {
    for (unsigned i = 0; i < 8; ++i) {
        bytes[off + 7 - i] = static_cast<std::byte>((value >> (i * 8)) & 0xff);
    }
}

void put16_be(std::vector<std::byte>& bytes, std::size_t off, spelunk::u16 value) {
    for (unsigned i = 0; i < 2; ++i) {
        bytes[off + 1 - i] = static_cast<std::byte>((value >> (i * 8)) & 0xff);
    }
}

void put32_be(std::vector<std::byte>& bytes, std::size_t off, spelunk::u32 value) {
    for (unsigned i = 0; i < 4; ++i) {
        bytes[off + 3 - i] = static_cast<std::byte>((value >> (i * 8)) & 0xff);
    }
}

template <std::size_t N>
void put_literal(std::vector<std::byte>& bytes, std::size_t off,
                 const char (&value)[N]) {
    for (std::size_t i = 0; i + 1 < N; ++i) {
        bytes[off + i] = static_cast<std::byte>(value[i]);
    }
}

void init_elf64_header(std::vector<std::byte>& bytes, spelunk::u16 type,
                       spelunk::u16 machine, spelunk::u64 entry,
                       spelunk::u64 phoff, spelunk::u16 phnum,
                       spelunk::u64 shoff, spelunk::u16 shnum,
                       spelunk::u16 shstrndx) {
    put32(bytes, 0, 0x464c457f);
    bytes[4] = std::byte{2};  // ELFCLASS64
    bytes[5] = std::byte{1};  // ELFDATA2LSB
    bytes[6] = std::byte{1};  // EV_CURRENT
    put16(bytes, 16, type);
    put16(bytes, 18, machine);
    put32(bytes, 20, 1);
    put64(bytes, 24, entry);
    put64(bytes, 32, phoff);
    put64(bytes, 40, shoff);
    put16(bytes, 52, 64);
    put16(bytes, 54, 56);
    put16(bytes, 56, phnum);
    put16(bytes, 58, 64);
    put16(bytes, 60, shnum);
    put16(bytes, 62, shstrndx);
}

void init_elf32_header(std::vector<std::byte>& bytes, spelunk::u16 type,
                       spelunk::u16 machine, spelunk::u32 phoff,
                       spelunk::u16 phnum, spelunk::u32 shoff = 0,
                       spelunk::u16 shnum = 0, spelunk::u16 shstrndx = 0) {
    put32(bytes, 0, 0x464c457f);
    bytes[4] = std::byte{1};  // ELFCLASS32
    bytes[5] = std::byte{1};  // ELFDATA2LSB
    bytes[6] = std::byte{1};  // EV_CURRENT
    put16(bytes, 16, type);
    put16(bytes, 18, machine);
    put32(bytes, 20, 1);
    put32(bytes, 28, phoff);
    put32(bytes, 32, shoff);
    put16(bytes, 40, 52);
    put16(bytes, 42, 32);
    put16(bytes, 44, phnum);
    put16(bytes, 46, 40);
    put16(bytes, 48, shnum);
    put16(bytes, 50, shstrndx);
}

void put_elf64_shdr(std::vector<std::byte>& bytes, std::size_t off,
                    spelunk::u32 name, spelunk::u32 type, spelunk::u64 flags,
                    spelunk::u64 addr, spelunk::u64 file_offset, spelunk::u64 size,
                    spelunk::u32 link = 0, spelunk::u32 info = 0,
                    spelunk::u64 alignment = 1, spelunk::u64 entsize = 0) {
    put32(bytes, off + 0x00, name);
    put32(bytes, off + 0x04, type);
    put64(bytes, off + 0x08, flags);
    put64(bytes, off + 0x10, addr);
    put64(bytes, off + 0x18, file_offset);
    put64(bytes, off + 0x20, size);
    put32(bytes, off + 0x28, link);
    put32(bytes, off + 0x2c, info);
    put64(bytes, off + 0x30, alignment);
    put64(bytes, off + 0x38, entsize);
}

void put_elf64_be_shdr(std::vector<std::byte>& bytes, std::size_t off,
                       spelunk::u32 name, spelunk::u32 type, spelunk::u64 flags,
                       spelunk::u64 addr, spelunk::u64 file_offset,
                       spelunk::u64 size, spelunk::u64 alignment = 1) {
    put32_be(bytes, off + 0x00, name);
    put32_be(bytes, off + 0x04, type);
    put64_be(bytes, off + 0x08, flags);
    put64_be(bytes, off + 0x10, addr);
    put64_be(bytes, off + 0x18, file_offset);
    put64_be(bytes, off + 0x20, size);
    put64_be(bytes, off + 0x30, alignment);
}

void put_elf32_shdr(std::vector<std::byte>& bytes, std::size_t off,
                    spelunk::u32 name, spelunk::u32 type, spelunk::u32 flags,
                    spelunk::u32 addr, spelunk::u32 file_offset, spelunk::u32 size,
                    spelunk::u32 alignment = 1) {
    put32(bytes, off + 0x00, name);
    put32(bytes, off + 0x04, type);
    put32(bytes, off + 0x08, flags);
    put32(bytes, off + 0x0c, addr);
    put32(bytes, off + 0x10, file_offset);
    put32(bytes, off + 0x14, size);
    put32(bytes, off + 0x20, alignment);
}

}  // namespace

void zero_elf64_load_sizes(std::vector<std::byte>& bytes) {
    constexpr std::size_t kProgramHeaderOffsetField = 0x20;
    constexpr std::size_t kFileSizeField = 0x20;
    constexpr std::size_t kMemorySizeField = 0x28;
    const auto program_header = static_cast<std::size_t>(
        spelunk::read_le_at<spelunk::u64>(
            bytes.data() + kProgramHeaderOffsetField));
    put64(bytes, program_header + kFileSizeField, 0);
    put64(bytes, program_header + kMemorySizeField, 0);
}

void zero_elf64_be_load_sizes(std::vector<std::byte>& bytes) {
    constexpr std::size_t kProgramHeaderOffsetField = 0x20;
    constexpr std::size_t kFileSizeField = 0x20;
    constexpr std::size_t kMemorySizeField = 0x28;
    const auto program_header = static_cast<std::size_t>(
        spelunk::read_be_at<spelunk::u64>(
            bytes.data() + kProgramHeaderOffsetField));
    put64_be(bytes, program_header + kFileSizeField, 0);
    put64_be(bytes, program_header + kMemorySizeField, 0);
}

void declare_elf64_extended_section_count(std::vector<std::byte>& bytes,
                                          spelunk::u64 count) {
    constexpr std::size_t kSectionHeaderOffsetField = 0x28;
    constexpr std::size_t kSectionCountField = 0x3c;
    constexpr std::size_t kSectionZeroSizeField = 0x20;
    const auto section_table = static_cast<std::size_t>(
        spelunk::read_le_at<spelunk::u64>(
            bytes.data() + kSectionHeaderOffsetField));
    put16(bytes, kSectionCountField, 0);
    put64(bytes, section_table + kSectionZeroSizeField, count);
}

void mark_elf64_extended_section_name_index(std::vector<std::byte>& bytes) {
    constexpr std::size_t kSectionNameIndexField = 0x3e;
    put16(bytes, kSectionNameIndexField, 0xffff);
}

void mark_elf64_extended_program_header_count(std::vector<std::byte>& bytes) {
    constexpr std::size_t kProgramHeaderCountField = 0x38;
    put16(bytes, kProgramHeaderCountField, 0xffff);
}

void declare_elf64_extended_program_header_count(
    std::vector<std::byte>& bytes, spelunk::u32 count) {
    constexpr std::size_t kSectionHeaderOffsetField = 0x28;
    constexpr std::size_t kSectionZeroInfoField = 0x2c;
    const auto section_table = static_cast<std::size_t>(
        spelunk::read_le_at<spelunk::u64>(
            bytes.data() + kSectionHeaderOffsetField));
    mark_elf64_extended_program_header_count(bytes);
    put32(bytes, section_table + kSectionZeroInfoField, count);
}

std::vector<std::byte> elf64_load(spelunk::u64 file_offset,
                                  spelunk::u64 vaddr,
                                  spelunk::u64 filesz,
                                  spelunk::u64 memsz) {
    std::vector<std::byte> bytes(64 + 56);
    init_elf64_header(bytes, 2, 62, 0, 64, 1, 0, 0, 0);
    put32(bytes, 64, 1);      // PT_LOAD
    put32(bytes, 68, 4);      // PF_R
    put64(bytes, 72, file_offset);
    put64(bytes, 80, vaddr);
    put64(bytes, 96, filesz);
    put64(bytes, 104, memsz);
    return bytes;
}

std::vector<std::byte> elf32_load(spelunk::u32 file_offset,
                                  spelunk::u32 vaddr,
                                  spelunk::u32 filesz,
                                  spelunk::u32 memsz) {
    std::vector<std::byte> bytes(52 + 32);
    init_elf32_header(bytes, 2, 3, 52, 1);
    put32(bytes, 52, 1);      // PT_LOAD
    put32(bytes, 56, file_offset);
    put32(bytes, 60, vaddr);
    put32(bytes, 68, filesz);
    put32(bytes, 72, memsz);
    put32(bytes, 76, 4);      // PF_R
    return bytes;
}

std::vector<std::byte> elf64_with_alloc_section(spelunk::u64 section_vaddr,
                                                spelunk::u64 section_size,
                                                bool with_load,
                                                spelunk::u16 elf_type) {
    constexpr std::size_t kLoadOffset = 0x80;
    constexpr std::size_t kSectionOffset = 0x84;
    constexpr std::size_t kShstrOffset = 0x88;
    constexpr std::size_t kShoff = 0xa0;
    constexpr char kShstr[] = "\0.text\0.shstrtab\0";
    std::vector<std::byte> bytes(kShoff + 3 * 64);
    init_elf64_header(bytes, elf_type, 62, 0,
                      with_load ? spelunk::u64{64} : spelunk::u64{0},
                      with_load ? spelunk::u16{1} : spelunk::u16{0},
                      kShoff, 3, 2);
    if (with_load) {
        put32(bytes, 64, 1);  // PT_LOAD
        put32(bytes, 68, 5);  // PF_R | PF_X
        put64(bytes, 72, kLoadOffset);
        put64(bytes, 80, 0x1000);
        put64(bytes, 96, 4);
        put64(bytes, 104, 8);
        bytes[kLoadOffset] = std::byte{0x11};
        bytes[kLoadOffset + 1] = std::byte{0x22};
        bytes[kLoadOffset + 2] = std::byte{0x33};
        bytes[kLoadOffset + 3] = std::byte{0x44};
    }
    bytes[kSectionOffset] = std::byte{0xaa};
    bytes[kSectionOffset + 1] = std::byte{0xbb};
    bytes[kSectionOffset + 2] = std::byte{0xcc};
    bytes[kSectionOffset + 3] = std::byte{0xdd};
    put_literal(bytes, kShstrOffset, kShstr);
    put_elf64_shdr(bytes, kShoff + 64, 1, 1, 0x6, section_vaddr,
                   kSectionOffset, section_size, 0, 0, 4);
    put_elf64_shdr(bytes, kShoff + 2 * 64, 7, 3, 0, 0,
                   kShstrOffset, sizeof(kShstr) - 1);
    return bytes;
}

std::vector<std::byte> elf64_relocatable_symbol(spelunk::u16 shndx,
                                                spelunk::u64 value,
                                                spelunk::u64 size,
                                                spelunk::u64 text_alignment) {
    constexpr std::size_t kTextOffset = 0x40;
    constexpr std::size_t kSymtabOffset = 0x48;
    constexpr std::size_t kStrtabOffset = 0x78;
    constexpr std::size_t kShstrOffset = 0x80;
    constexpr std::size_t kShoff = 0xa8;
    constexpr char kStrtab[] = "\0symbol\0";
    constexpr char kShstr[] =
        "\0.text\0.symtab\0.strtab\0.shstrtab\0";
    std::vector<std::byte> bytes(kShoff + 5 * 64);
    init_elf64_header(bytes, 1, 62, 0, 0, 0, kShoff, 5, 4);
    bytes[kTextOffset] = std::byte{0x90};
    bytes[kTextOffset + 1] = std::byte{0x90};
    bytes[kTextOffset + 2] = std::byte{0x90};
    bytes[kTextOffset + 3] = std::byte{0x90};
    put32(bytes, kSymtabOffset + 24, 1);
    bytes[kSymtabOffset + 28] = std::byte{0x12};
    put16(bytes, kSymtabOffset + 30, shndx);
    put64(bytes, kSymtabOffset + 32, value);
    put64(bytes, kSymtabOffset + 40, size);
    put_literal(bytes, kStrtabOffset, kStrtab);
    put_literal(bytes, kShstrOffset, kShstr);
    put_elf64_shdr(bytes, kShoff + 64, 1, 1, 0x6, 0,
                   kTextOffset, 4, 0, 0, text_alignment);
    put_elf64_shdr(bytes, kShoff + 2 * 64, 7, 2, 0, 0,
                   kSymtabOffset, 48, 3, 1, 8, 24);
    put_elf64_shdr(bytes, kShoff + 3 * 64, 15, 3, 0, 0,
                   kStrtabOffset, sizeof(kStrtab) - 1);
    put_elf64_shdr(bytes, kShoff + 4 * 64, 23, 3, 0, 0,
                   kShstrOffset, sizeof(kShstr) - 1);
    return bytes;
}

std::vector<std::byte> elf64_relocatable_xindex(
    spelunk::u64 companion_entsize, spelunk::u64 companion_size,
    spelunk::u32 companion_link, spelunk::u32 extended_index,
    spelunk::u16 raw_shndx) {
    constexpr std::size_t kTextOffset = 0x40;
    constexpr std::size_t kSymtabOffset = 0x48;
    constexpr std::size_t kStrtabOffset = 0x78;
    constexpr std::size_t kShndxOffset = 0x80;
    constexpr std::size_t kShstrOffset = 0x88;
    constexpr std::size_t kShoff = 0xb8;
    constexpr char kStrtab[] = "\0symbol\0";
    constexpr char kShstr[] =
        "\0.text\0.symtab\0.strtab\0.shstrtab\0.symtab_shndx\0";
    std::vector<std::byte> bytes(kShoff + 6 * 64);
    init_elf64_header(bytes, 1, 62, 0, 0, 0, kShoff, 6, 4);
    bytes[kTextOffset] = std::byte{0x90};
    bytes[kTextOffset + 1] = std::byte{0x90};
    bytes[kTextOffset + 2] = std::byte{0x90};
    bytes[kTextOffset + 3] = std::byte{0x90};
    put32(bytes, kSymtabOffset + 24, 1);
    bytes[kSymtabOffset + 28] = std::byte{0x12};
    put16(bytes, kSymtabOffset + 30, raw_shndx);
    put64(bytes, kSymtabOffset + 32, 2);
    put64(bytes, kSymtabOffset + 40, 1);
    put_literal(bytes, kStrtabOffset, kStrtab);
    put32(bytes, kShndxOffset + 4, extended_index);
    put_literal(bytes, kShstrOffset, kShstr);
    put_elf64_shdr(bytes, kShoff + 64, 1, 1, 0x6, 0,
                   kTextOffset, 4, 0, 0, 4);
    put_elf64_shdr(bytes, kShoff + 2 * 64, 7, 2, 0, 0,
                   kSymtabOffset, 48, 3, 1, 8, 24);
    put_elf64_shdr(bytes, kShoff + 3 * 64, 15, 3, 0, 0,
                   kStrtabOffset, sizeof(kStrtab) - 1);
    put_elf64_shdr(bytes, kShoff + 4 * 64, 23, 3, 0, 0,
                   kShstrOffset, sizeof(kShstr) - 1);
    put_elf64_shdr(bytes, kShoff + 5 * 64, 33, 18, 0, 0,
                   kShndxOffset, companion_size, companion_link, 0, 4,
                   companion_entsize);
    return bytes;
}

std::vector<std::byte> elf64_fully_extended_numbering() {
    constexpr spelunk::u32 kPhnum = 0x10000;
    constexpr spelunk::u32 kShstrIndex = 0x10000;
    constexpr spelunk::u32 kTextIndex = kFullyExtendedTextSectionIndex;
    constexpr spelunk::u32 kShnum = kFullyExtendedSectionCount;
    constexpr std::size_t kPhoff = 64;
    constexpr std::size_t kShoff =
        kPhoff + static_cast<std::size_t>(kPhnum) * 56;
    constexpr std::size_t kDataOffset =
        kShoff + static_cast<std::size_t>(kShnum) * 64;
    constexpr std::size_t kTextOffset = kDataOffset;
    constexpr std::size_t kSymtabOffset = kTextOffset + 8;
    constexpr std::size_t kStrtabOffset = kSymtabOffset + 48;
    constexpr std::size_t kShndxOffset = kStrtabOffset + 8;
    constexpr std::size_t kShstrOffset = kShndxOffset + 8;
    constexpr char kStrtab[] = "\0symbol\0";
    constexpr char kShstr[] =
        "\0.text\0.symtab\0.strtab\0.shstrtab\0.symtab_shndx\0";
    std::vector<std::byte> bytes(kShstrOffset + sizeof(kShstr) - 1);
    init_elf64_header(bytes, 1, 62, 0, kPhoff, 0xffff,
                      kShoff, 0, 0xffff);

    const std::size_t last_phdr =
        kPhoff + (static_cast<std::size_t>(kPhnum) - 1) * 56;
    put32(bytes, last_phdr, 1);      // PT_LOAD, reached only via PN_XNUM
    put32(bytes, last_phdr + 4, 4);  // PF_R, zero-sized and not stored

    put_elf64_shdr(bytes, kShoff, 0, 0, 0, 0, 0, kShnum,
                   kShstrIndex, kPhnum, 0);
    put_elf64_shdr(bytes, kShoff + 2 * 64, 7, 2, 0, 0,
                   kSymtabOffset, 48, 3, 1, 8, 24);
    put_elf64_shdr(bytes, kShoff + 3 * 64, 15, 3, 0, 0,
                   kStrtabOffset, sizeof(kStrtab) - 1);
    put_elf64_shdr(bytes, kShoff + 4 * 64, 33, 18, 0, 0,
                   kShndxOffset, 8, 2, 0, 4, 4);
    put_elf64_shdr(bytes,
                   kShoff + static_cast<std::size_t>(kShstrIndex) * 64,
                   23, 3, 0, 0, kShstrOffset, sizeof(kShstr) - 1);
    put_elf64_shdr(bytes,
                   kShoff + static_cast<std::size_t>(kTextIndex) * 64,
                   1, 1, 0x6, 0, kTextOffset, 4, 0, 0, 4);

    bytes[kTextOffset] = std::byte{0x90};
    bytes[kTextOffset + 1] = std::byte{0x90};
    bytes[kTextOffset + 2] = std::byte{0x90};
    bytes[kTextOffset + 3] = std::byte{0x90};
    put32(bytes, kSymtabOffset + 24, 1);
    bytes[kSymtabOffset + 28] = std::byte{0x12};
    put16(bytes, kSymtabOffset + 30, 0xffff);  // SHN_XINDEX
    put64(bytes, kSymtabOffset + 32, 2);
    put64(bytes, kSymtabOffset + 40, 1);
    put_literal(bytes, kStrtabOffset, kStrtab);
    put32(bytes, kShndxOffset + 4, kTextIndex);
    put_literal(bytes, kShstrOffset, kShstr);
    return bytes;
}

std::vector<std::byte> elf32_with_wrapping_alloc_section() {
    constexpr std::size_t kTextOffset = 0x34;
    constexpr std::size_t kShstrOffset = 0x38;
    constexpr std::size_t kShoff = 0x70;
    constexpr char kShstr[] = "\0.text\0.shstrtab\0";
    std::vector<std::byte> bytes(kShoff + 3 * 40);
    init_elf32_header(bytes, 1, 3, 0, 0, kShoff, 3, 2);
    bytes[kTextOffset] = std::byte{0x90};
    bytes[kTextOffset + 1] = std::byte{0x90};
    put_literal(bytes, kShstrOffset, kShstr);
    put_elf32_shdr(bytes, kShoff + 40, 1, 1, 0x6,
                   std::numeric_limits<spelunk::u32>::max(), kTextOffset, 2, 1);
    put_elf32_shdr(bytes, kShoff + 2 * 40, 7, 3, 0,
                   0, kShstrOffset, sizeof(kShstr) - 1);
    return bytes;
}

std::vector<std::byte> elf64_non_x86_sectioned_got_relocation() {
    constexpr std::size_t kDynsymOffset = 0x40;
    constexpr std::size_t kDynstrOffset = 0x70;
    constexpr std::size_t kRelaOffset = 0x78;
    constexpr std::size_t kShstrOffset = 0x90;
    constexpr std::size_t kShoff = 0xb8;
    constexpr char kDynstr[] = "\0foo\0";
    constexpr char kShstr[] =
        "\0.dynsym\0.dynstr\0.rela.dyn\0.shstrtab\0";
    std::vector<std::byte> bytes(kShoff + 5 * 64);
    init_elf64_header(bytes, 3, 21, 0, 0, 0, kShoff, 5, 4);
    put32(bytes, kDynsymOffset + 24, 1);
    bytes[kDynsymOffset + 28] = std::byte{0x12};
    put64(bytes, kRelaOffset, 0x2000);
    put64(bytes, kRelaOffset + 8, (spelunk::u64{1} << 32) | 6);  // not R_X86_64_GLOB_DAT
    put_literal(bytes, kDynstrOffset, kDynstr);
    put_literal(bytes, kShstrOffset, kShstr);
    put_elf64_shdr(bytes, kShoff + 64, 1, 11, 0, 0,
                   kDynsymOffset, 48, 2, 0, 8, 24);
    put_elf64_shdr(bytes, kShoff + 2 * 64, 9, 3, 0, 0,
                   kDynstrOffset, sizeof(kDynstr) - 1);
    put_elf64_shdr(bytes, kShoff + 3 * 64, 17, 4, 0, 0,
                   kRelaOffset, 24, 1, 0, 8, 24);
    put_elf64_shdr(bytes, kShoff + 4 * 64, 27, 3, 0, 0,
                   kShstrOffset, sizeof(kShstr) - 1);
    return bytes;
}

std::vector<std::byte> elf64_non_x86_phdr_got_relocation() {
    constexpr spelunk::u64 kBase = 0x400000;
    constexpr std::size_t kDynamicOffset = 0x100;
    constexpr std::size_t kDynsymOffset = 0x180;
    constexpr std::size_t kDynstrOffset = 0x1b0;
    constexpr std::size_t kHashOffset = 0x1b8;
    constexpr std::size_t kRelaOffset = 0x1d0;
    constexpr std::size_t kFileSize = 0x1e8;
    constexpr char kDynstr[] = "\0foo\0";
    std::vector<std::byte> bytes(kFileSize);
    init_elf64_header(bytes, 3, 183, 0, 64, 2, 0, 0, 0);

    put32(bytes, 64, 1);      // PT_LOAD
    put32(bytes, 68, 4);      // PF_R
    put64(bytes, 72, 0);
    put64(bytes, 80, kBase);
    put64(bytes, 96, kFileSize);
    put64(bytes, 104, kFileSize);
    put64(bytes, 112, 0x1000);

    put32(bytes, 120, 2);     // PT_DYNAMIC
    put32(bytes, 124, 4);
    put64(bytes, 128, kDynamicOffset);
    put64(bytes, 136, kBase + kDynamicOffset);
    put64(bytes, 152, 0x80);
    put64(bytes, 160, 0x80);
    put64(bytes, 168, 8);

    auto put_dynamic = [&](std::size_t index, spelunk::u64 tag, spelunk::u64 val) {
        put64(bytes, kDynamicOffset + index * 16, tag);
        put64(bytes, kDynamicOffset + index * 16 + 8, val);
    };
    put_dynamic(0, 5, kBase + kDynstrOffset);  // DT_STRTAB
    put_dynamic(1, 6, kBase + kDynsymOffset);  // DT_SYMTAB
    put_dynamic(2, 10, sizeof(kDynstr) - 1);   // DT_STRSZ
    put_dynamic(3, 11, 24);                    // DT_SYMENT
    put_dynamic(4, 4, kBase + kHashOffset);    // DT_HASH
    put_dynamic(5, 7, kBase + kRelaOffset);    // DT_RELA
    put_dynamic(6, 8, 24);                     // DT_RELASZ
    put_dynamic(7, 0, 0);                      // DT_NULL

    put32(bytes, kDynsymOffset + 24, 1);
    bytes[kDynsymOffset + 28] = std::byte{0x12};
    put_literal(bytes, kDynstrOffset, kDynstr);
    put32(bytes, kHashOffset, 1);       // nbucket
    put32(bytes, kHashOffset + 4, 2);   // nchain / dynsym count
    put64(bytes, kRelaOffset, 0x500000);
    put64(bytes, kRelaOffset + 8, (spelunk::u64{1} << 32) | 7);  // not R_X86_64_JUMP_SLOT
    return bytes;
}

std::vector<std::byte> elf64_ppc_descriptor_to_highest_address() {
    constexpr std::size_t kTextOffset = 0x40;
    constexpr std::size_t kOpdOffset = 0x48;
    constexpr std::size_t kShstrOffset = 0x50;
    constexpr std::size_t kShoff = 0x68;
    constexpr char kShstr[] = "\0.text\0.opd\0.shstrtab\0";
    std::vector<std::byte> bytes(kShoff + 4 * 64);
    bytes[0] = std::byte{0x7f};
    bytes[1] = std::byte{'E'};
    bytes[2] = std::byte{'L'};
    bytes[3] = std::byte{'F'};
    bytes[4] = std::byte{2};  // ELFCLASS64
    bytes[5] = std::byte{2};  // ELFDATA2MSB
    bytes[6] = std::byte{1};  // EV_CURRENT
    put16_be(bytes, 16, 2);   // ET_EXEC
    put16_be(bytes, 18, 21);  // EM_PPC64
    put32_be(bytes, 20, 1);
    put64_be(bytes, 24, 0x1000);
    put64_be(bytes, 40, kShoff);
    put16_be(bytes, 52, 64);
    put16_be(bytes, 54, 56);
    put16_be(bytes, 58, 64);
    put16_be(bytes, 60, 4);
    put16_be(bytes, 62, 3);
    bytes[kTextOffset] = std::byte{0x4e};
    put64_be(bytes, kOpdOffset, std::numeric_limits<spelunk::u64>::max());
    put_literal(bytes, kShstrOffset, kShstr);
    put_elf64_be_shdr(bytes, kShoff + 64, 1, 1, 0x6,
                      std::numeric_limits<spelunk::u64>::max(), kTextOffset, 1);
    put_elf64_be_shdr(bytes, kShoff + 2 * 64, 7, 1, 0x2,
                      0x1000, kOpdOffset, 8, 8);
    put_elf64_be_shdr(bytes, kShoff + 3 * 64, 12, 3, 0,
                      0, kShstrOffset, sizeof(kShstr) - 1);
    return bytes;
}

std::vector<std::byte> elf64_ppc_descriptor_outside_load_segment() {
    constexpr std::size_t kOpdOffset = 0x80;
    constexpr std::size_t kTextOffset = 0x88;
    constexpr std::size_t kShstrOffset = 0x90;
    constexpr std::size_t kShoff = 0xb0;
    constexpr char kShstr[] = "\0.text\0.opd\0.shstrtab\0";
    std::vector<std::byte> bytes(kShoff + 4 * 64);
    bytes[0] = std::byte{0x7f};
    bytes[1] = std::byte{'E'};
    bytes[2] = std::byte{'L'};
    bytes[3] = std::byte{'F'};
    bytes[4] = std::byte{2};  // ELFCLASS64
    bytes[5] = std::byte{2};  // ELFDATA2MSB
    bytes[6] = std::byte{1};  // EV_CURRENT
    put16_be(bytes, 16, 2);   // ET_EXEC
    put16_be(bytes, 18, 21);  // EM_PPC64
    put32_be(bytes, 20, 1);
    put64_be(bytes, 24, 0x1000);
    put64_be(bytes, 32, 64);
    put64_be(bytes, 40, kShoff);
    put16_be(bytes, 52, 64);
    put16_be(bytes, 54, 56);
    put16_be(bytes, 56, 1);
    put16_be(bytes, 58, 64);
    put16_be(bytes, 60, 4);
    put16_be(bytes, 62, 3);

    put32_be(bytes, 64, 1);   // PT_LOAD
    put32_be(bytes, 68, 4);   // PF_R
    put64_be(bytes, 72, kOpdOffset);
    put64_be(bytes, 80, 0x1000);
    put64_be(bytes, 96, 8);
    put64_be(bytes, 104, 8);
    put64_be(bytes, 112, 8);

    put64_be(bytes, kOpdOffset, 0x2000);
    bytes[kTextOffset] = std::byte{0x4e};
    put_literal(bytes, kShstrOffset, kShstr);
    put_elf64_be_shdr(bytes, kShoff + 64, 1, 1, 0x6,
                      0x2000, kTextOffset, 4, 4);
    put_elf64_be_shdr(bytes, kShoff + 2 * 64, 7, 1, 0x2,
                      0x1000, kOpdOffset, 8, 8);
    put_elf64_be_shdr(bytes, kShoff + 3 * 64, 12, 3, 0,
                      0, kShstrOffset, sizeof(kShstr) - 1);
    return bytes;
}

}  // namespace elf_test
