#include <cstdlib>
#include <iostream>
#include <span>
#include <string_view>

#include <spelunk/binary/binary.hpp>
#include <spelunk/common/bytes.hpp>
#include <spelunk/disasm/decoder.hpp>

namespace {

using namespace spelunk;

void check(bool ok, std::string_view message) {
    if (ok) return;
    std::cerr << "elf_ppc_reloc_test: " << message << "\n";
    std::exit(1);
}

u32 be_word(const Binary& binary, addr_t address) {
    const auto bytes = binary.bytes_at(address);
    check(bytes.size() >= 4, "expected four mapped bytes");
    return read_be_at<u32>(bytes.data());
}

const Relocation* find_relocation(std::span<const Relocation> relocations,
                                  addr_t site, u32 type,
                                  std::string_view symbol_name) {
    for (const auto& relocation : relocations) {
        if (relocation.site == site && relocation.type == type &&
            relocation.symbol_name == symbol_name) {
            return &relocation;
        }
    }
    return nullptr;
}

const Relocation& require_relocation(
    std::span<const Relocation> relocations, addr_t site, u32 type,
    std::string_view symbol_name, std::string_view failure_message) {
    const Relocation* relocation =
        find_relocation(relocations, site, type, symbol_name);
    check(relocation != nullptr, failure_message);
    return *relocation;
}

}  // namespace

int main(int argc, char** argv) {
    check(argc == 2, "expected fixture path");
    auto loaded = load_binary(argv[1]);
    check(loaded.has_value(), "PPC32 relocatable object should load");
    const auto& binary = **loaded;

    check(binary.arch() == Arch::Ppc32, "architecture should be PPC32");
    check(binary.endian() == Endian::Big, "fixture should be big-endian");
    check(binary.preferred_load_base() == 0x10000000,
          "allocated-section layout should use the synthetic base");

    const auto* local_entry = binary.find_by_name("local_entry");
    const auto* local_global = binary.find_by_name("local_global");
    const auto* external_call = binary.find_by_name("external_call");
    const auto* absolute_far = binary.find_by_name("absolute_far");
    const auto* negative_far24 = binary.find_by_name("negative_far24");
    const auto* negative_far16 = binary.find_by_name("negative_far16");
    const auto* high_valid24 = binary.find_by_name("high_valid24");
    const auto* high_valid16 = binary.find_by_name("high_valid16");
    const auto* wrap_base = binary.find_by_name("wrap_base");
    const auto* common_global = binary.find_by_name("common_global");
    const auto* positive_far16 = binary.find_by_name("positive_far16");
    const auto* absolute_zero = binary.find_by_name("absolute_zero");
    check(local_entry && local_entry->addr == 0x10000000,
          "function symbol should be rebased into .text");
    check(local_global && local_global->addr == 0x10000038,
          "object symbol should be rebased into .data");
    check(external_call && external_call->is_import && external_call->addr != 0,
          "undefined branch symbol should receive an import stub address");
    check(absolute_far && absolute_far->addr == 0x02000000,
          "SHN_ABS symbol should retain its absolute value");
    check(negative_far24 && negative_far24->addr == 0xfdfffffc,
          "negative ADDR24 test symbol should retain its bit pattern");
    check(negative_far16 && negative_far16->addr == 0xffff7fff,
          "negative ADDR16 test symbol should retain its bit pattern");
    check(high_valid24 && high_valid24->addr == 0xfe000000,
          "signed ADDR24 boundary symbol should retain its bit pattern");
    check(high_valid16 && high_valid16->addr == 0xffff8000,
          "signed ADDR16 boundary symbol should retain its bit pattern");
    check(wrap_base && wrap_base->addr == 0xfffffff0,
          "wraparound relocation symbol should retain its bit pattern");
    check(common_global && common_global->addr != 32 &&
              common_global->addr % 32 == 0 && common_global->size == 12,
          "SHN_COMMON should receive aligned synthetic storage");
    const Section* common_section = nullptr;
    for (const auto& section : binary.sections()) {
        if (section.name == ".common") common_section = &section;
    }
    check(common_section && common_section->flags.allocated &&
              common_section->flags.writable &&
              common_global->addr >= common_section->vaddr &&
              common_global->addr + common_global->size <=
                  common_section->vaddr + common_section->size,
          "synthetic COMMON storage should be represented as writable memory");
    check(positive_far16 && positive_far16->addr == 0x8000,
          "positive ADDR16 bit-15 boundary symbol should retain its value");
    check(absolute_zero && absolute_zero->addr == 0 && !absolute_zero->is_import,
          "defined SHN_ABS:0 symbol should remain distinct from an import");
    check(external_call->addr >= common_global->addr + common_global->size,
          "external stubs should not overlap synthetic COMMON storage");
    check(binary.import_at_plt(external_call->addr) == external_call,
          "synthetic external target should participate in import lookup");

    const auto relocs = binary.relocations();
    check(relocs.size() == 17, "all code and data relocations should be retained");
    for (const auto& reloc : relocs) {
        check(!reloc.type_name.empty(), "relocation should expose a type name");
        check(!reloc.symbol_name.empty(), "relocation should expose its symbol");
    }

    const auto* external_rel24 = &require_relocation(
        relocs, local_entry->addr, 10, "external_call",
        "missing external_call REL24 relocation");
    const auto* local_addr16_ha = &require_relocation(
        relocs, local_entry->addr + 6, 6, "local_global",
        "missing local_global ADDR16_HA relocation");
    const auto* local_addr16_lo = &require_relocation(
        relocs, local_entry->addr + 10, 4, "local_global",
        "missing local_global ADDR16_LO relocation");
    const auto* positive_far_addr24 = &require_relocation(
        relocs, local_entry->addr + 16, 2, "absolute_far",
        "missing positive-overflow ADDR24 relocation");
    const auto* positive_far_addr16 = &require_relocation(
        relocs, local_entry->addr + 22, 3, "positive_far16",
        "missing positive-overflow ADDR16 relocation");
    const auto* negative_far_addr24 = &require_relocation(
        relocs, local_entry->addr + 24, 2, "negative_far24",
        "missing negative-overflow ADDR24 relocation");
    const auto* negative_far_addr16 = &require_relocation(
        relocs, local_entry->addr + 30, 3, "negative_far16",
        "missing negative-overflow ADDR16 relocation");
    const auto* high_valid_addr24 = &require_relocation(
        relocs, local_entry->addr + 32, 2, "high_valid24",
        "missing high-boundary ADDR24 relocation");
    const auto* high_valid_addr16 = &require_relocation(
        relocs, local_entry->addr + 38, 3, "high_valid16",
        "missing high-boundary ADDR16 relocation");
    const auto* wrapped_addr16 = &require_relocation(
        relocs, local_entry->addr + 42, 3, "wrap_base",
        "missing wrapped ADDR16 relocation");
    const auto* wrapped_addr24 = &require_relocation(
        relocs, local_entry->addr + 44, 2, "wrap_base",
        "missing wrapped ADDR24 relocation");
    const auto* wrapped_rel24 = &require_relocation(
        relocs, local_entry->addr + 48, 10, "wrap_base",
        "missing wrapped REL24 relocation");
    const auto* wrapped_rel14 = &require_relocation(
        relocs, local_entry->addr + 52, 11, "wrap_base",
        "missing wrapped REL14 relocation");
    const auto* local_addr32 = &require_relocation(
        relocs, local_global->addr, 1, "local_entry",
        "missing local-entry ADDR32 relocation");
    const auto* common_addr32 = &require_relocation(
        relocs, local_global->addr + 4, 1, "common_global",
        "missing COMMON ADDR32 relocation");
    const auto* absolute_zero_addr32 = &require_relocation(
        relocs, local_global->addr + 8, 1, "absolute_zero",
        "missing SHN_ABS:0 ADDR32 relocation");
    const auto* unaligned_addr32 = &require_relocation(
        relocs, local_global->addr + 13, 1, "local_entry",
        "missing unaligned local-entry ADDR32 relocation");

    check(external_rel24->applied && local_addr16_ha->applied &&
              local_addr16_lo->applied && high_valid_addr24->applied &&
              high_valid_addr16->applied && wrapped_addr16->applied &&
              wrapped_addr24->applied && wrapped_rel24->applied &&
              wrapped_rel14->applied && local_addr32->applied &&
              common_addr32->applied && absolute_zero_addr32->applied,
          "in-range fixture relocations should be applied");
    check(external_rel24->target == external_call->addr &&
              external_rel24->width == 4 && external_rel24->pc_relative &&
              external_rel24->section_name == ".text",
          "REL24 record should preserve site, target, width, and section");
    check(local_addr16_ha->target == local_global->addr &&
              local_addr16_ha->type_name == "R_PPC_ADDR16_HA" &&
              local_addr16_ha->width == 2 && !local_addr16_ha->pc_relative,
          "ADDR16_HA record should describe the immediate field");
    check(local_addr16_lo->target == local_global->addr &&
              local_addr16_lo->type_name == "R_PPC_ADDR16_LO",
          "ADDR16_LO record should describe the immediate field");
    check(positive_far_addr24->target == absolute_far->addr &&
              positive_far_addr24->type_name == "R_PPC_ADDR24" &&
              !positive_far_addr24->applied,
          "ADDR24 should reject a target outside its signed 26-bit range");
    check(positive_far_addr16->target == positive_far16->addr &&
              positive_far_addr16->type_name == "R_PPC_ADDR16" &&
              !positive_far_addr16->applied,
          "ADDR16 should reject 0x8000 when bit 15 is not sign-extended");
    check(negative_far_addr24->target == negative_far24->addr &&
              negative_far_addr24->type_name == "R_PPC_ADDR24" &&
              !negative_far_addr24->applied,
          "ADDR24 should reject a negative target below its signed range");
    check(negative_far_addr16->target == negative_far16->addr &&
              negative_far_addr16->type_name == "R_PPC_ADDR16" &&
              !negative_far_addr16->applied,
          "ADDR16 should reject a negative target below its signed range");
    check(high_valid_addr24->target == high_valid24->addr &&
              high_valid_addr24->type_name == "R_PPC_ADDR24",
          "ADDR24 should accept its high signed encoding boundary");
    check(high_valid_addr16->target == high_valid16->addr &&
              high_valid_addr16->type_name == "R_PPC_ADDR16",
          "ADDR16 should accept its high signed encoding boundary");
    check(wrapped_addr16->target == 0x10 &&
              wrapped_addr16->type_name == "R_PPC_ADDR16",
          "ADDR16 should range-check the modulo-32-bit S+A result");
    check(wrapped_addr24->target == 0x10 &&
              wrapped_addr24->type_name == "R_PPC_ADDR24",
          "ADDR24 should range-check the modulo-32-bit S+A result");
    check(wrapped_rel24->target == 0x10000040 &&
              wrapped_rel24->pc_relative &&
              wrapped_rel24->type_name == "R_PPC_REL24",
          "REL24 should form modulo-32-bit S+A-P before range checking");
    check(wrapped_rel14->target == local_global->addr &&
              wrapped_rel14->pc_relative &&
              wrapped_rel14->type_name == "R_PPC_REL14",
          "REL14 should form modulo-32-bit S+A-P before range checking");
    check(local_addr32->target == local_entry->addr &&
              local_addr32->type_name == "R_PPC_ADDR32",
          "ADDR32 record should preserve the data-pointer edge");
    check(common_addr32->target == common_global->addr &&
              common_addr32->type_name == "R_PPC_ADDR32",
          "COMMON-backed ADDR32 relocation should use synthetic storage");
    check(absolute_zero_addr32->target == 0x12345678 &&
              absolute_zero_addr32->addend == 0x12345678 &&
              absolute_zero_addr32->type_name == "R_PPC_ADDR32",
          "defined SHN_ABS:0 relocation should remain available");
    check(unaligned_addr32->target == local_entry->addr &&
              !unaligned_addr32->applied &&
              unaligned_addr32->type_name == "R_PPC_ADDR32",
          "ordinary ADDR32 should reject an unaligned relocation site");

    auto decoder = make_decoder(binary);
    check(decoder.has_value(), "PPC decoder should be available");
    auto call = (*decoder)->decode(binary.bytes_at(local_entry->addr), local_entry->addr);
    check(call.has_value() && call->mnemonic == Mnemonic::Call,
          "relocated branch should decode as a call");
    check(branch_target(*call) == external_call->addr,
          "REL24 should point at the synthetic external target");

    const u32 lis = be_word(binary, local_entry->addr + 4);
    const u32 addi = be_word(binary, local_entry->addr + 8);
    const i64 rebuilt = static_cast<i64>((lis & 0xffffu) << 16) +
                        static_cast<i64>(static_cast<i16>(addi & 0xffffu));
    check(static_cast<addr_t>(rebuilt) == local_global->addr,
          "ADDR16_HA/LO should rebuild the local object address");
    check(be_word(binary, local_entry->addr + 16) == 0x49abcde3,
          "overflowing ADDR24 should leave the instruction bytes unchanged");
    check(be_word(binary, local_entry->addr + 20) == 0x38a55a5a,
          "overflowing ADDR16 should leave the immediate bytes unchanged");
    check(be_word(binary, local_entry->addr + 24) == 0x49bcdef3,
          "negative-overflow ADDR24 should leave instruction bytes unchanged");
    check(be_word(binary, local_entry->addr + 28) == 0x38c66b6b,
          "negative-overflow ADDR16 should leave immediate bytes unchanged");
    check(be_word(binary, local_entry->addr + 32) == 0x4a000003,
          "ADDR24 should encode the valid high signed boundary");
    check(be_word(binary, local_entry->addr + 36) == 0x38e78000,
          "ADDR16 should encode the valid high signed boundary");
    check(be_word(binary, local_entry->addr + 40) == 0x39080010,
          "ADDR16 should apply after S+A wraps to a low value");
    check(be_word(binary, local_entry->addr + 44) == 0x48000013,
          "ADDR24 should apply after S+A wraps to a low value");
    check(be_word(binary, local_entry->addr + 48) == 0x48000011,
          "REL24 should apply after modular S+A-P wraparound");
    check(be_word(binary, local_entry->addr + 52) == 0x41820004,
          "REL14 should apply after modular S+A-P wraparound");
    check(be_word(binary, local_global->addr) == local_entry->addr,
          "ADDR32 should patch the data pointer to the local function");
    check(be_word(binary, local_global->addr + 4) == common_global->addr,
          "ADDR32 should patch a pointer to synthetic COMMON storage");
    check(be_word(binary, local_global->addr + 8) == 0x12345678,
          "ADDR32 should apply a nonzero addend to defined SHN_ABS:0");
    check(be_word(binary, local_global->addr + 13) == 0xb2c3d45a,
          "rejected unaligned ADDR32 should leave its bytes unchanged");

    return 0;
}
