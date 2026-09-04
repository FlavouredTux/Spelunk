#include <ember/binary/elf.hpp>

#include <cstddef>
#include <cstdio>
#include <limits>
#include <utility>

#include "elf_test_builder.hpp"

namespace {

using namespace elf_test;

int fails = 0;

void check(bool condition, const char* message) {
    if (condition) return;
    std::fprintf(stderr, "FAIL: %s\n", message);
    ++fails;
}

void test_elf_rejects_invalid_load_intervals() {
    auto rejects_as_invalid_format = [](const auto& loaded) {
        return !loaded && loaded.error().kind == ember::ErrorKind::InvalidFormat;
    };

    auto filesz_exceeds_memsz =
        ember::ElfBinary::load_from_buffer(elf64_load(0, 0x1000, 2, 1));
    check(rejects_as_invalid_format(filesz_exceeds_memsz),
          "ELF rejects PT_LOAD file bytes larger than its memory image");
    auto elf64_virtual_wrap = ember::ElfBinary::load_from_buffer(elf64_load(
        0, std::numeric_limits<ember::u64>::max(), 0, 1));
    check(rejects_as_invalid_format(elf64_virtual_wrap),
          "ELF64 rejects a wrapping PT_LOAD virtual interval");
    auto elf64_file_wrap = ember::ElfBinary::load_from_buffer(elf64_load(
        std::numeric_limits<ember::u64>::max(), 0x1000, 1, 1));
    check(rejects_as_invalid_format(elf64_file_wrap),
          "ELF64 rejects a wrapping PT_LOAD file interval");
    auto elf32_virtual_wrap = ember::ElfBinary::load_from_buffer(elf32_load(
        0, std::numeric_limits<ember::u32>::max(), 0, 1));
    check(rejects_as_invalid_format(elf32_virtual_wrap),
          "ELF32 rejects a virtual interval that only fits after widening");
    auto elf32_file_wrap = ember::ElfBinary::load_from_buffer(elf32_load(
        std::numeric_limits<ember::u32>::max(), 0x1000, 1, 1));
    check(rejects_as_invalid_format(elf32_file_wrap),
          "ELF32 rejects a file interval that only fits after widening");
}

void test_elf_load_segments_are_authoritative() {
    auto loaded = ember::ElfBinary::load_from_buffer(
        elf64_with_alloc_section(0x2000, 4, true));
    check(loaded.has_value(), "ELF with a valid PT_LOAD and section table loads");
    if (!loaded) return;
    check((*loaded)->bytes_at(0x1000).size() == 4,
          "ELF exposes file-backed PT_LOAD bytes");
    check((*loaded)->bytes_at(0x1004).empty(),
          "ELF does not expose the PT_LOAD zero-fill tail as file bytes");
    check((*loaded)->bytes_at(0x2000).empty(),
          "ELF does not fall back to a section outside all PT_LOAD segments");

    auto zero_load_bytes = elf64_with_alloc_section(0x2000, 4, true);
    zero_elf64_load_sizes(zero_load_bytes);
    auto zero_load = ember::ElfBinary::load_from_buffer(std::move(zero_load_bytes));
    check(zero_load.has_value(), "ELF with a zero-sized PT_LOAD still loads");
    if (zero_load) {
        check((*zero_load)->segments().empty() &&
                  (*zero_load)->bytes_at(0x2000).empty() &&
                  (*zero_load)->preferred_load_base() == 0 &&
                  (*zero_load)->mapped_size() == 0,
              "zero-sized PT_LOAD suppresses every section mapping fallback");
    }
}

void test_elf_mapped_size_handles_wrapping_section_end() {
    auto loaded = ember::ElfBinary::load_from_buffer(elf64_with_alloc_section(
        std::numeric_limits<ember::u64>::max(), 1, false));
    check(loaded.has_value(), "section-only ELF with the highest virtual byte loads");
    if (!loaded) return;
    check((*loaded)->mapped_size() == 1,
          "ELF mapped size does not wrap a highest-address section to zero");
    check((*loaded)->bytes_at(std::numeric_limits<ember::u64>::max()).size() == 1,
          "section-only ELF still maps its highest virtual byte");

    auto elf64_wrap = ember::ElfBinary::load_from_buffer(elf64_with_alloc_section(
        std::numeric_limits<ember::u64>::max(), 2, false, 1));
    check(!elf64_wrap &&
              elf64_wrap.error().kind == ember::ErrorKind::InvalidFormat,
          "ELF64 rejects an allocated section whose last address wraps");
    auto elf32_wrap = ember::ElfBinary::load_from_buffer(
        elf32_with_wrapping_alloc_section());
    check(!elf32_wrap &&
              elf32_wrap.error().kind == ember::ErrorKind::InvalidFormat,
          "ELF32 rejects an allocated section whose last address wraps");
}

void test_elf_executable_membership_handles_wrapping_section_end() {
    auto loaded = ember::ElfBinary::load_from_buffer(
        elf64_ppc_descriptor_to_highest_address());
    check(loaded.has_value(), "PPC64 highest-address descriptor fixture loads");
    if (!loaded) return;
    check((*loaded)->entry_point() == std::numeric_limits<ember::u64>::max(),
          "ELF executable membership recognizes a section ending past UINT64_MAX");

    auto mixed = ember::ElfBinary::load_from_buffer(
        elf64_ppc_descriptor_outside_load_segment());
    check(mixed.has_value(), "mixed PPC64 segment/section fixture loads");
    if (!mixed) return;
    check((*mixed)->bytes_at(0x2000).empty(),
          "mixed PPC64 fixture does not map section-only target bytes");
    check((*mixed)->entry_point() == 0x1000,
          "PT_LOAD permissions remain authoritative for descriptor targets");

    auto zero_load_descriptor = elf64_ppc_descriptor_outside_load_segment();
    zero_elf64_be_load_sizes(zero_load_descriptor);
    auto zero_mixed = ember::ElfBinary::load_from_buffer(
        std::move(zero_load_descriptor));
    check(zero_mixed.has_value(), "zero-sized mixed PPC64 PT_LOAD fixture loads");
    if (zero_mixed) {
        check((*zero_mixed)->segments().empty() &&
                  (*zero_mixed)->bytes_at(0x1000).empty() &&
                  (*zero_mixed)->entry_point() == 0x1000 &&
                  (*zero_mixed)->preferred_load_base() == 0 &&
                  (*zero_mixed)->mapped_size() == 0,
              "zero-sized PT_LOAD blocks section bytes and execute permissions");
    }
}

void test_elf_relocatable_symbol_bounds() {
    check(!ember::ElfBinary::load_from_buffer(
              elf64_relocatable_symbol(5, 0, 0)),
          "ET_REL rejects an ordinary symbol section index past e_shnum");
    check(!ember::ElfBinary::load_from_buffer(
              elf64_relocatable_symbol(1, 5, 0)),
          "ET_REL rejects a symbol value past its defining section");
    check(!ember::ElfBinary::load_from_buffer(
              elf64_relocatable_symbol(1, 3, 2)),
          "ET_REL rejects a symbol extent past its defining section");

    auto endpoint = ember::ElfBinary::load_from_buffer(
        elf64_relocatable_symbol(1, 4, 0));
    check(endpoint.has_value(),
          "ET_REL accepts a zero-sized symbol at its section endpoint");

    auto absolute = ember::ElfBinary::load_from_buffer(
        elf64_relocatable_symbol(0xfff1, 0x1234, 0));  // SHN_ABS
    check(absolute.has_value(), "ET_REL preserves SHN_ABS symbol semantics");
    if (absolute) {
        const auto* symbol = (*absolute)->find_by_name("symbol");
        check(symbol && symbol->addr == 0x1234,
              "ET_REL does not rebase an SHN_ABS symbol");
    }

    auto common = ember::ElfBinary::load_from_buffer(
        elf64_relocatable_symbol(0xfff2, 16, 8));
    check(common.has_value(), "ET_REL allocates SHN_COMMON storage");
    if (common) {
        const auto* symbol = (*common)->find_by_name("symbol");
        check(symbol && symbol->addr != 16 && symbol->addr % 16 == 0 &&
                  symbol->size == 8,
              "SHN_COMMON value is alignment, not the exposed symbol address");
    }
    check(!ember::ElfBinary::load_from_buffer(
              elf64_relocatable_symbol(
                  0xfff2, ember::u64{0x100000000}, 1)),
          "ET_REL rejects COMMON alignment beyond the PPC32 address space");
    check(!ember::ElfBinary::load_from_buffer(
              elf64_relocatable_symbol(0xfff2, 1, 0xffffffff)),
          "ET_REL rejects COMMON storage extending beyond PPC32");
    check(!ember::ElfBinary::load_from_buffer(
              elf64_relocatable_symbol(0xfff2, 3, 8)),
          "ET_REL rejects non-power-of-two COMMON alignment");
    check(!ember::ElfBinary::load_from_buffer(
              elf64_relocatable_symbol(1, 0, 1, 3)),
          "ET_REL rejects non-power-of-two section alignment");
}

void test_elf_extended_symbol_indices() {
    auto fully_extended = ember::ElfBinary::load_from_buffer(
        elf64_fully_extended_numbering());
    check(fully_extended.has_value(),
          "ELF resolves extended section, shstrtab, phdr, and symbol indices");
    if (fully_extended) {
        const auto sections = (*fully_extended)->sections();
        check(sections.size() == kFullyExtendedSectionCount,
              "section-zero sh_size supplies the full section count");
        if (sections.size() == kFullyExtendedSectionCount) {
            check(sections[kFullyExtendedTextSectionIndex].name == ".text",
                  "section-zero sh_link supplies the extended shstrtab index");
        }
        const auto* symbol = (*fully_extended)->find_by_name("symbol");
        check(symbol && symbol->addr == 0x10000002,
              "SHN_XINDEX resolves a genuine greater-than-16-bit index");
        check((*fully_extended)->segments().empty() && symbol &&
                  (*fully_extended)->bytes_at(symbol->addr).empty(),
              "PN_XNUM reaches the final zero-sized PT_LOAD and preserves authority");
    }

    check(!ember::ElfBinary::load_from_buffer(
              elf64_relocatable_symbol(0xffff, 2, 1)),
          "ET_REL rejects SHN_XINDEX without a companion table");
    check(!ember::ElfBinary::load_from_buffer(
              elf64_relocatable_xindex(8, 8, 2)),
          "ET_REL rejects a SYMTAB_SHNDX entry-size mismatch");
    check(!ember::ElfBinary::load_from_buffer(
              elf64_relocatable_xindex(4, 4, 2)),
          "ET_REL rejects a SYMTAB_SHNDX symbol-count mismatch");
    check(!ember::ElfBinary::load_from_buffer(
              elf64_relocatable_xindex(4, 8, 3)),
          "ET_REL rejects SYMTAB_SHNDX linked to a non-symbol section");
    check(!ember::ElfBinary::load_from_buffer(
              elf64_relocatable_xindex(4, 8, 2, 6)),
          "ET_REL rejects an out-of-range extended section index");
    check(!ember::ElfBinary::load_from_buffer(
              elf64_relocatable_xindex(4, 8, 2, 1, 1)),
          "ET_REL rejects a nonzero companion entry without SHN_XINDEX");

    auto small_extended_count = elf64_with_alloc_section(0x2000, 4, false);
    declare_elf64_extended_section_count(small_extended_count, 3);
    check(!ember::ElfBinary::load_from_buffer(std::move(small_extended_count)),
          "ELF rejects nonconforming small extended section counts");

    auto truncated_extended_table = elf64_with_alloc_section(0x2000, 4, false);
    declare_elf64_extended_section_count(
        truncated_extended_table, kExtendedSectionCountMinimum);
    check(!ember::ElfBinary::load_from_buffer(std::move(truncated_extended_table)),
          "ELF bounds-checks a section-zero extended section count");

    auto no_section_zero = elf64_load(0, 0x1000, 0, 1);
    mark_elf64_extended_section_name_index(no_section_zero);
    check(!ember::ElfBinary::load_from_buffer(std::move(no_section_zero)),
          "ELF rejects extended shstrtab numbering without section zero");

    auto no_section_zero_phnum = elf64_load(0, 0x1000, 0, 1);
    mark_elf64_extended_program_header_count(no_section_zero_phnum);
    check(!ember::ElfBinary::load_from_buffer(std::move(no_section_zero_phnum)),
          "ELF rejects PN_XNUM without section zero");

    auto truncated_extended_phdrs = elf64_with_alloc_section(0x2000, 4, false);
    declare_elf64_extended_program_header_count(
        truncated_extended_phdrs, kExtendedProgramHeaderCountMinimum);
    check(!ember::ElfBinary::load_from_buffer(std::move(truncated_extended_phdrs)),
          "ELF bounds-checks the PN_XNUM program-header count");
}

void test_elf_x86_got_relocations_are_arch_specific() {
    auto sectioned = ember::ElfBinary::load_from_buffer(
        elf64_non_x86_sectioned_got_relocation());
    check(sectioned.has_value(), "non-x86 sectioned ELF relocation fixture loads");
    if (sectioned) {
        const auto* symbol = (*sectioned)->find_by_name("foo");
        check(symbol && symbol->is_import && symbol->got_addr == 0,
              "sectioned non-x86 relocation 6 is not treated as R_X86_64_GLOB_DAT");
    }

    auto phdr_only = ember::ElfBinary::load_from_buffer(
        elf64_non_x86_phdr_got_relocation());
    check(phdr_only.has_value(), "non-x86 program-header ELF fixture loads");
    if (phdr_only) {
        const auto* symbol = (*phdr_only)->find_by_name("foo");
        check(symbol && symbol->is_import && symbol->got_addr == 0,
              "phdr-only non-x86 relocation 7 is not treated as R_X86_64_JUMP_SLOT");
    }
}

}  // namespace

int main() {
    test_elf_rejects_invalid_load_intervals();
    test_elf_load_segments_are_authoritative();
    test_elf_mapped_size_handles_wrapping_section_end();
    test_elf_executable_membership_handles_wrapping_section_end();
    test_elf_relocatable_symbol_bounds();
    test_elf_extended_symbol_indices();
    test_elf_x86_got_relocations_are_arch_specific();
    return fails == 0 ? 0 : 1;
}
