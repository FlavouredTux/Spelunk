#include <ember/binary/pe.hpp>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace {

int failures = 0;

void check(bool condition, const char* message) {
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", message);
        ++failures;
    }
}

template <typename T>
void put(std::vector<std::byte>& bytes, std::size_t offset, T value) {
    std::memcpy(bytes.data() + offset, &value, sizeof(value));
}

}  // namespace

int main() {
    std::vector<std::byte> bytes(0x380, std::byte{0});
    bytes[0] = std::byte{'M'};
    bytes[1] = std::byte{'Z'};
    put<ember::u32>(bytes, 0x3c, 0x80);
    bytes[0x80] = std::byte{'P'};
    bytes[0x81] = std::byte{'E'};
    constexpr std::size_t coff = 0x84;
    put<ember::u16>(bytes, coff + 0x00, 0x8664);
    put<ember::u16>(bytes, coff + 0x02, 1);
    put<ember::u32>(bytes, coff + 0x08, 0x300);
    put<ember::u32>(bytes, coff + 0x0c, 2);
    put<ember::u16>(bytes, coff + 0x10, 0xf0);
    constexpr std::size_t optional = coff + 20;
    put<ember::u16>(bytes, optional + 0x00, 0x20b);
    put<ember::u32>(bytes, optional + 0x10, 0x1000);
    put<ember::u64>(bytes, optional + 0x18, 0x140000000ull);
    put<ember::u32>(bytes, optional + 0x6c, 0);
    constexpr std::size_t section = optional + 0xf0;
    std::memcpy(bytes.data() + section, ".text", 5);
    put<ember::u32>(bytes, section + 0x08, 0x20);
    put<ember::u32>(bytes, section + 0x0c, 0x1000);
    put<ember::u32>(bytes, section + 0x10, 0x20);
    put<ember::u32>(bytes, section + 0x14, 0x200);
    put<ember::u32>(bytes, section + 0x24, 0x60000020);
    bytes[0x200] = std::byte{0xc3};

    // Long-name COFF function symbol plus one function-definition aux record.
    put<ember::u32>(bytes, 0x300, 0);
    put<ember::u32>(bytes, 0x304, 4);
    put<ember::u32>(bytes, 0x308, 0);
    put<ember::i16>(bytes, 0x30c, 1);
    put<ember::u16>(bytes, 0x30e, 0x20);
    bytes[0x310] = std::byte{2};
    bytes[0x311] = std::byte{1};
    put<ember::u32>(bytes, 0x312 + 4, 1);
    constexpr char name[] = "coff_main";
    put<ember::u32>(bytes, 0x324, 4 + sizeof(name));
    std::memcpy(bytes.data() + 0x328, name, sizeof(name));

    auto binary = ember::PeBinary::load_from_buffer(std::move(bytes));
    check(binary.has_value(), "minimal PE with COFF table loads");
    if (binary) {
        const ember::Symbol* symbol = (*binary)->find_by_name("coff_main");
        check(symbol != nullptr, "COFF long function name imported");
        if (symbol) {
            check(symbol->addr == 0x140001000ull, "COFF section-relative VA resolved");
            check(symbol->size == 1, "COFF auxiliary total size imported");
            check(symbol->kind == ember::SymbolKind::Function,
                  "COFF function type retained");
        }
    }
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
