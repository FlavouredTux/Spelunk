#include <cstdlib>
#include <iostream>
#include <string_view>

#include <ember/binary/binary.hpp>
#include <ember/common/bytes.hpp>
#include <ember/disasm/decoder.hpp>

namespace {

using namespace ember;

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
    check(local_entry && local_entry->addr == 0x10000000,
          "function symbol should be rebased into .text");
    check(local_global && local_global->addr == 0x10000010,
          "object symbol should be rebased into .data");
    check(external_call && external_call->is_import && external_call->addr != 0,
          "undefined branch symbol should receive an import stub address");
    check(binary.import_at_plt(external_call->addr) == external_call,
          "synthetic external target should participate in import lookup");

    const auto relocs = binary.relocations();
    check(relocs.size() == 4, "all code and data relocations should be retained");
    for (const auto& reloc : relocs) {
        check(reloc.applied, "supported fixture relocation should be applied");
        check(!reloc.type_name.empty(), "relocation should expose a type name");
        check(!reloc.symbol_name.empty(), "relocation should expose its symbol");
    }
    check(relocs[0].site == local_entry->addr &&
              relocs[0].target == external_call->addr &&
              relocs[0].type == 10 && relocs[0].width == 4 &&
              relocs[0].pc_relative && relocs[0].section_name == ".text",
          "REL24 record should preserve site, target, width, and section");
    check(relocs[1].site == local_entry->addr + 6 &&
              relocs[1].target == local_global->addr &&
              relocs[1].type_name == "R_PPC_ADDR16_HA" &&
              relocs[1].width == 2 && !relocs[1].pc_relative,
          "ADDR16_HA record should describe the immediate field");
    check(relocs[2].site == local_entry->addr + 10 &&
              relocs[2].target == local_global->addr &&
              relocs[2].type_name == "R_PPC_ADDR16_LO",
          "ADDR16_LO record should describe the immediate field");
    check(relocs[3].site == local_global->addr &&
              relocs[3].target == local_entry->addr &&
              relocs[3].type_name == "R_PPC_ADDR32",
          "ADDR32 record should preserve the data-pointer edge");

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
    check(be_word(binary, local_global->addr) == local_entry->addr,
          "ADDR32 should patch the data pointer to the local function");

    return 0;
}
