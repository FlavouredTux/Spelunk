// libFuzzer harness for one binary loader. EMBER_FUZZ_LOADER names the
// class (ElfBinary, PeBinary, MachOBinary, MinidumpBinary, DolBinary);
// each target is this file compiled with a different definition.
//
// A successful load is followed by the reads the CLI would do first:
// the section and symbol tables, the entry point, and a short decode
// from it, so bugs in the parsed data surface too, not only in parsing.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include <ember/binary/dol.hpp>
#include <ember/binary/elf.hpp>
#include <ember/binary/macho.hpp>
#include <ember/binary/minidump.hpp>
#include <ember/binary/pe.hpp>
#include <ember/disasm/decoder.hpp>

#ifndef EMBER_FUZZ_LOADER
#error "define EMBER_FUZZ_LOADER to the loader class under test"
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    std::vector<std::byte> buffer(size);
    if (size != 0) std::memcpy(buffer.data(), data, size);

    auto loaded = ember::EMBER_FUZZ_LOADER::load_from_buffer(std::move(buffer));
    if (!loaded) return 0;
    const ember::Binary& b = **loaded;

    std::size_t touched = 0;
    for (const auto& s : b.sections()) touched += s.data.size() + s.name.size();
    for (const auto& s : b.symbols()) touched += s.name.size() + (s.is_import ? 1u : 0u);
    touched += static_cast<std::size_t>(b.preferred_load_base() + b.mapped_size());

    const ember::addr_t entry = b.entry_point();
    if (entry != 0) {
        if (auto decoder = ember::make_decoder(b)) {
            ember::addr_t pc = entry;
            for (int i = 0; i < 32; ++i) {
                auto code = b.bytes_at(pc);
                if (code.empty()) break;
                auto insn = (*decoder)->decode(code, pc);
                if (!insn || insn->length == 0) break;
                pc += insn->length;
            }
        }
    }
    volatile const std::size_t touched_sink = touched;
    (void)touched_sink;
    return 0;
}
