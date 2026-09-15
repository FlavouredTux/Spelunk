// libFuzzer harness for the Nintendo GameCube/Wii REL loader. A successful
// load is followed by reads of the REL-specific metadata and relocation
// evidence, plus a short decode from the module entry point.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <utility>
#include <vector>

#include <spelunk/binary/rel.hpp>
#include <spelunk/disasm/decoder.hpp>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    std::vector<std::byte> buffer(size);
    if (size != 0) std::memcpy(buffer.data(), data, size);

    auto loaded = spelunk::RelBinary::load_from_buffer(std::move(buffer));
    if (!loaded) return 0;
    const spelunk::RelBinary& rel = **loaded;

    std::size_t touched = static_cast<std::size_t>(rel.module_id()) +
                          static_cast<std::size_t>(rel.version());
    for (const auto& section : rel.sections()) {
        touched += section.data.size() + section.name.size();
    }
    for (const auto& symbol : rel.symbols()) {
        touched += symbol.name.size() + (symbol.is_import ? 1u : 0u);
    }
    for (const auto& relocation : rel.relocations()) {
        touched += relocation.type_name.size() + relocation.symbol_name.size() +
                   relocation.section_name.size() +
                   (relocation.applied ? 1u : 0u);
        touched += static_cast<std::size_t>(
            relocation.site ^ relocation.target ^
            static_cast<spelunk::u64>(relocation.addend));
        touched += static_cast<std::size_t>(
            relocation.type + relocation.source_section +
            relocation.target_module + relocation.target_section +
            relocation.width + (relocation.pc_relative ? 1u : 0u));
    }
    touched += static_cast<std::size_t>(rel.preferred_load_base() +
                                        rel.mapped_size());

    const spelunk::addr_t entry = rel.entry_point();
    if (entry != 0) {
        if (auto decoder = spelunk::make_decoder(rel)) {
            spelunk::addr_t pc = entry;
            for (int i = 0; i < 32; ++i) {
                auto code = rel.bytes_at(pc);
                if (code.empty()) break;
                auto insn = (*decoder)->decode(code, pc);
                if (!insn || insn->length == 0) break;
                pc += insn->length;
            }
        }
    }
    // Keep metadata traversal observable under optimized fuzz builds.
    volatile const std::size_t touched_sink = touched;
    (void)touched_sink;
    return 0;
}
