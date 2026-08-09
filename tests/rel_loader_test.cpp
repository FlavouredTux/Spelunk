#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <string_view>
#include <vector>

#include <ember/binary/binary.hpp>
#include <ember/binary/rel.hpp>
#include <ember/common/bytes.hpp>
#include <ember/disasm/decoder.hpp>

namespace {

using namespace ember;

void check(bool condition, std::string_view message) {
    if (condition) return;
    std::cerr << "rel_loader_test: " << message << "\n";
    std::exit(1);
}

u32 word_at(const Binary& binary, addr_t address) {
    const auto bytes = binary.bytes_at(address);
    check(bytes.size() >= 4, "expected mapped word");
    return read_be_at<u32>(bytes.data());
}

std::vector<std::byte> read_fixture(const char* path) {
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

}  // namespace

int main(int argc, char** argv) {
    check(argc == 3, "expected fixture and DTK symbols paths");
    auto loaded = load_binary(argv[1]);
    check(loaded.has_value(), "Wii REL fixture should load");
    const auto& binary = **loaded;
    const auto* rel = dynamic_cast<const RelBinary*>(&binary);

    check(rel != nullptr && binary.format() == Format::Rel,
          "loader should select RelBinary");
    check(rel->module_id() == 5 && rel->version() == 3,
          "REL header identity should be retained");
    check(binary.arch() == Arch::Ppc32 && binary.endian() == Endian::Big,
          "REL should use big-endian PPC32");
    check(binary.preferred_load_base() == 0x80500000 &&
              binary.mapped_size() == 0x1c,
          "REL sections should receive a deterministic Wii-range layout");

    const auto* prolog = binary.find_by_name("_prolog");
    const auto* self_data = binary.find_by_name("rel5_s2_00000000");
    const auto* dol_import = binary.find_by_name("dol_80001200");
    const auto* external = binary.find_by_name("rel7_s2_00000010");
    check(prolog && prolog->addr == 0x80500000 &&
              binary.entry_point() == prolog->addr,
          "prolog should define the REL entry point");
    check(self_data && self_data->addr == 0x80500010,
          "self relocation should synthesize a local data symbol");
    check(dol_import && dol_import->is_import && dol_import->addr == 0x80001200,
          "DOL relocation should synthesize a resolved import");
    check(external && external->is_import && external->addr == 0,
          "cross-REL target should remain explicitly unresolved");

    const auto relocations = binary.relocations();
    check(relocations.size() == 5, "all REL relocation edges should be retained");
    check(relocations[0].site == prolog->addr + 6 &&
              relocations[0].target == self_data->addr && relocations[0].applied &&
              relocations[0].type_name == "R_PPC_ADDR16_HA",
          "self HA relocation should patch and retain evidence");
    check(relocations[1].site == prolog->addr + 10 &&
              relocations[1].target == self_data->addr && relocations[1].applied,
          "self LO relocation should patch and retain evidence");
    check(relocations[2].site == self_data->addr &&
              relocations[2].target == prolog->addr && relocations[2].applied,
          "self ADDR32 relocation should patch the data pointer");
    check(relocations[3].site == prolog->addr &&
              relocations[3].target == dol_import->addr &&
              relocations[3].pc_relative && relocations[3].applied,
          "DOL REL24 relocation should resolve and patch");
    check(relocations[4].site == self_data->addr + 4 &&
              relocations[4].target == 0 && !relocations[4].applied &&
              relocations[4].symbol_name == "rel7_s2_00000010",
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
    check(word_at(binary, self_data->addr + 4) == 0,
          "unresolved cross-REL pointer should remain untouched");

    auto invalid_section = read_fixture(argv[1]);
    invalid_section[0xb3] = std::byte{9};
    check(!RelBinary::load_from_buffer(std::move(invalid_section)),
          "out-of-range R_DOLPHIN_SECTION should be rejected");

    auto missing_end = read_fixture(argv[1]);
    missing_end[0x10a] = std::byte{1};
    check(!RelBinary::load_from_buffer(std::move(missing_end)),
          "relocation stream without R_DOLPHIN_END should be rejected");

    LoadOptions options;
    options.dol_symbols_path = argv[2];
    auto named = load_binary(argv[1], options);
    check(named.has_value(), "REL should load with DTK section-relative symbols");
    const auto* named_prolog = (*named)->find_by_name("fixture_prolog");
    const auto* named_data = (*named)->find_by_name("fixture_data");
    const auto* named_bss = (*named)->find_by_name("fixture_bss");
    check(named_prolog && named_prolog->addr == 0x80500000 &&
              named_prolog->size == 0x10 && named_prolog->kind == SymbolKind::Function,
          "DTK .text function should map from its section-relative offset");
    check(named_data && named_data->addr == 0x80500010 && named_data->size == 8,
          "DTK .data object should map from its section-relative offset");
    check(named_bss && named_bss->addr == 0x80500018 && !named_bss->is_export,
          "DTK .bss local should preserve its scope and synthetic address");
    return 0;
}
