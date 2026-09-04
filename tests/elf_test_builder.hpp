#pragma once

#include <cstddef>
#include <vector>

#include <ember/common/types.hpp>

namespace elf_test {

inline constexpr ember::u64 kExtendedSectionCountMinimum = 0xff00;
inline constexpr ember::u32 kExtendedProgramHeaderCountMinimum = 0xffff;
inline constexpr std::size_t kFullyExtendedTextSectionIndex = 0x10001;
inline constexpr std::size_t kFullyExtendedSectionCount = 0x10002;

void zero_elf64_load_sizes(std::vector<std::byte>& bytes);
void zero_elf64_be_load_sizes(std::vector<std::byte>& bytes);
void declare_elf64_extended_section_count(std::vector<std::byte>& bytes,
                                          ember::u64 count);
void mark_elf64_extended_section_name_index(std::vector<std::byte>& bytes);
void mark_elf64_extended_program_header_count(std::vector<std::byte>& bytes);
void declare_elf64_extended_program_header_count(
    std::vector<std::byte>& bytes, ember::u32 count);

[[nodiscard]] std::vector<std::byte>
elf64_load(ember::u64 file_offset, ember::u64 vaddr,
           ember::u64 filesz, ember::u64 memsz);
[[nodiscard]] std::vector<std::byte>
elf32_load(ember::u32 file_offset, ember::u32 vaddr,
           ember::u32 filesz, ember::u32 memsz);
[[nodiscard]] std::vector<std::byte>
elf64_with_alloc_section(ember::u64 section_vaddr, ember::u64 section_size,
                         bool with_load, ember::u16 elf_type = 2);
[[nodiscard]] std::vector<std::byte>
elf64_relocatable_symbol(ember::u16 shndx, ember::u64 value,
                         ember::u64 size, ember::u64 text_alignment = 4);
[[nodiscard]] std::vector<std::byte>
elf64_relocatable_xindex(ember::u64 companion_entsize = 4,
                         ember::u64 companion_size = 8,
                         ember::u32 companion_link = 2,
                         ember::u32 extended_index = 1,
                         ember::u16 raw_shndx = 0xffff);
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
