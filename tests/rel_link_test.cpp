#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <string_view>
#include <vector>

#include <ember/binary/rel.hpp>
#include <ember/common/bytes.hpp>
#include <ember/disasm/decoder.hpp>

namespace {

using namespace ember;

void check(bool condition, std::string_view message) {
    if (condition) return;
    std::cerr << "rel_link_test: " << message << "\n";
    std::exit(1);
}

std::vector<std::byte> read_file(const char* path) {
    const auto size = std::filesystem::file_size(path);
    check(size <= std::numeric_limits<std::size_t>::max(), "fixture is too large");
    std::vector<std::byte> bytes(static_cast<std::size_t>(size));
    std::ifstream input(path, std::ios::binary);
    input.read(reinterpret_cast<char*>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
    check(input.good(), "fixture should be read completely");
    return bytes;
}

u32 word_at(const Binary& binary, addr_t address) {
    const auto bytes = binary.bytes_at(address);
    check(bytes.size() >= 4, "expected a mapped word");
    return read_be_at<u32>(bytes.data());
}

}  // namespace

int main(int argc, char** argv) {
    check(argc == 5, "expected source, peer, and two symbol paths");
    auto source = RelBinary::load_from_buffer(read_file(argv[1]));
    auto peer = RelBinary::load_from_buffer(read_file(argv[2]), 0x80510000);
    check(source.has_value() && peer.has_value(), "both REL modules should load");
    check((*source)->module_id() == 9 && (*peer)->module_id() == 10,
          "fixture module IDs should be distinct");
    check((*source)->attach_dtk_symbols_from_path(argv[3]).has_value() &&
              (*peer)->attach_dtk_symbols_from_path(argv[4]).has_value(),
          "both module symbol maps should attach");

    auto before = (*source)->relocations();
    check(before.size() == 2 && !before[0].applied && !before[1].applied,
          "cross-module relocations should begin unresolved");
    check(before[0].target_module == 10 && before[0].target_section == 1 &&
              before[0].source_section == 1,
          "REL24 should retain native module and section coordinates");

    std::vector<RelLinkModule> modules{
        {source->get(), "source"},
        {peer->get(), "peer"},
    };
    auto linked = link_rel_modules(modules);
    check(linked.has_value() && *linked == 2,
          "the peer should resolve both external relocation edges");

    const auto* peer_entry_import = (*source)->find_by_name("peer_entry");
    const auto* peer_value_import = (*source)->find_by_name("peer_value");
    check(peer_entry_import && peer_entry_import->is_import &&
              peer_entry_import->addr == 0x80510000,
          "peer function name should replace the synthetic REL import");
    check(peer_value_import && peer_value_import->is_import &&
              peer_value_import->addr == 0x80510004,
          "peer global name should replace the synthetic REL import");
    check((*source)->find_by_name("rel10_s1_00000000") == nullptr &&
              (*source)->find_by_name("rel10_s2_00000000") == nullptr,
          "resolved imports should not retain raw coordinate names");

    auto after = (*source)->relocations();
    check(after[0].applied && after[0].target == peer_entry_import->addr &&
              after[0].symbol_name == "peer_entry",
          "cross-module REL24 should be patched and named");
    check(after[1].applied && after[1].target == peer_value_import->addr &&
              after[1].symbol_name == "peer_value",
          "cross-module ADDR32 should be patched and named");
    check(word_at(**source, 0x80500008) == peer_value_import->addr,
          "source data pointer should contain the peer synthetic VA");

    auto decoder = make_decoder(**source);
    check(decoder.has_value(), "PPC decoder should be available");
    auto call = (*decoder)->decode((*source)->bytes_at(0x80500000), 0x80500000);
    check(call.has_value() && call->mnemonic == Mnemonic::Call &&
              branch_target(*call) == peer_entry_import->addr,
          "linked REL24 should decode as a call into the peer module");
    check((*source)->import_at_plt(peer_entry_import->addr) == peer_entry_import,
          "linked peer function should participate in named-call lookup");

    std::unique_ptr<Binary> peer_owner = std::move(*peer);
    (*source)->adopt_linked_binary(std::move(peer_owner), "peer");
    const auto* peer_entry = (*source)->find_by_name("peer_entry");
    const auto* peer_value = (*source)->find_by_name("peer_value");
    check(peer_entry && !peer_entry->is_import && peer_entry->addr == 0x80510000 &&
              !(*source)->bytes_at(peer_entry->addr).empty(),
          "adopted peer function should be directly analyzable");
    check(peer_value && !peer_value->is_import && peer_value->addr == 0x80510004 &&
              word_at(**source, peer_value->addr) == 0x12345678,
          "adopted peer data should be mapped in the shared analysis context");

    std::vector<RelLinkModule> duplicate{
        {source->get(), "first"},
        {source->get(), "duplicate"},
    };
    check(!link_rel_modules(duplicate), "duplicate REL module IDs should be rejected");
    return 0;
}
