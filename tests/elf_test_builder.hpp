#pragma once

#include <cstddef>
#include <vector>

#include <spelunk/common/types.hpp>

namespace elf_test {

inline constexpr spelunk::u64 kExtendedSectionCountMinimum = 0xff00;
inline constexpr spelunk::u32 kExtendedProgramHeaderCountMinimum = 0xffff;
inline constexpr std::size_t kFullyExtendedTextSectionIndex = 0x10001;
inline constexpr std::size_t kFullyExtendedSectionCount = 0x10002;

void zero_elf64_load_sizes(std::vector<std::byte>& bytes);
void zero_elf64_be_load_sizes(std::vector<std::byte>& bytes);
void declare_elf64_extended_section_count(std::vector<std::byte>& bytes,
                                          spelunk::u64 count);
void mark_elf64_extended_section_name_index(std::vector<std::byte>& bytes);
void mark_elf64_extended_program_header_count(std::vector<std::byte>& bytes);
void declare_elf64_extended_program_header_count(
    std::vector<std::byte>& bytes, spelunk::u32 count);

[[nodiscard]] std::vector<std::byte>
elf64_load(spelunk::u64 file_offset, spelunk::u64 vaddr,
           spelunk::u64 filesz, spelunk::u64 memsz);
[[nodiscard]] std::vector<std::byte>
elf32_load(spelunk::u32 file_offset, spelunk::u32 vaddr,
           spelunk::u32 filesz, spelunk::u32 memsz);
[[nodiscard]] std::vector<std::byte>
elf64_with_alloc_section(spelunk::u64 section_vaddr, spelunk::u64 section_size,
                         bool with_load, spelunk::u16 elf_type = 2);
[[nodiscard]] std::vector<std::byte>
elf64_relocatable_symbol(spelunk::u16 shndx, spelunk::u64 value,
                         spelunk::u64 size, spelunk::u64 text_alignment = 4);
[[nodiscard]] std::vector<std::byte>
elf64_relocatable_xindex(spelunk::u64 companion_entsize = 4,
                         spelunk::u64 companion_size = 8,
                         spelunk::u32 companion_link = 2,
                         spelunk::u32 extended_index = 1,
                         spelunk::u16 raw_shndx = 0xffff);
[[nodiscard]] std::vector<std::byte> elf64_fully_extended_numbering();
[[nodiscard]] std::vector<std::byte> elf32_with_wrapping_alloc_section();
[[nodiscard]] std::vector<std::byte>
elf64_non_x86_sectioned_got_relocation();
[[nodiscard]] std::vector<std::byte>
elf64_non_x86_phdr_got_relocation();
[[nodiscard]] std::vector<std::byte>
elf64_ppc_descriptor_to_highest_address();
[[nodiscard]] std::vector<std::byte>
elf64_ppc_descriptor_outside_load_segment();

}  // namespace elf_test
