#include <ember/binary/binary.hpp>
#include <ember/binary/dwarf.hpp>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <span>
#include <vector>

namespace {

int failures = 0;

void check(bool condition, const char* message) {
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", message);
        ++failures;
    }
}

void put_u16(std::vector<std::byte>& bytes, ember::u16 value) {
    bytes.push_back(static_cast<std::byte>(value));
    bytes.push_back(static_cast<std::byte>(value >> 8));
}

void put_u32(std::vector<std::byte>& bytes, ember::u32 value) {
    for (unsigned shift = 0; shift < 32; shift += 8) {
        bytes.push_back(static_cast<std::byte>(value >> shift));
    }
}

void put_u64(std::vector<std::byte>& bytes, ember::u64 value) {
    for (unsigned shift = 0; shift < 64; shift += 8) {
        bytes.push_back(static_cast<std::byte>(value >> shift));
    }
}

void patch_u32(std::vector<std::byte>& bytes, std::size_t offset,
               ember::u32 value) {
    for (unsigned index = 0; index < 4; ++index) {
        bytes[offset + index] = static_cast<std::byte>(value >> (index * 8));
    }
}

void put_uleb(std::vector<std::byte>& bytes, ember::u64 value) {
    do {
        ember::u8 byte = static_cast<ember::u8>(value & 0x7fu);
        value >>= 7;
        if (value != 0) byte |= 0x80u;
        bytes.push_back(static_cast<std::byte>(byte));
    } while (value != 0);
}

void put_string(std::vector<std::byte>& bytes, const char* value) {
    while (*value != '\0') bytes.push_back(static_cast<std::byte>(*value++));
    bytes.push_back(std::byte{0});
}

class DwarfBinary final : public ember::Binary {
public:
    DwarfBinary() {
        // Abbrev 1: compile unit with children, no attributes.
        put_uleb(abbrev_, 1); put_uleb(abbrev_, 0x11); abbrev_.push_back(std::byte{1});
        put_uleb(abbrev_, 0); put_uleb(abbrev_, 0);
        // Abbrev 2: base type {name:string, byte_size:data1}.
        put_uleb(abbrev_, 2); put_uleb(abbrev_, 0x24); abbrev_.push_back(std::byte{0});
        put_uleb(abbrev_, 0x03); put_uleb(abbrev_, 0x08);
        put_uleb(abbrev_, 0x0b); put_uleb(abbrev_, 0x0b);
        put_uleb(abbrev_, 0); put_uleb(abbrev_, 0);
        // Abbrev 3: pointer type {type:ref4}.
        put_uleb(abbrev_, 3); put_uleb(abbrev_, 0x0f); abbrev_.push_back(std::byte{0});
        put_uleb(abbrev_, 0x49); put_uleb(abbrev_, 0x13);
        put_uleb(abbrev_, 0); put_uleb(abbrev_, 0);
        // Abbrev 4: subprogram with one child.
        put_uleb(abbrev_, 4); put_uleb(abbrev_, 0x2e); abbrev_.push_back(std::byte{1});
        put_uleb(abbrev_, 0x03); put_uleb(abbrev_, 0x08);
        put_uleb(abbrev_, 0x11); put_uleb(abbrev_, 0x01);
        put_uleb(abbrev_, 0x12); put_uleb(abbrev_, 0x06);
        put_uleb(abbrev_, 0x49); put_uleb(abbrev_, 0x13);
        put_uleb(abbrev_, 0); put_uleb(abbrev_, 0);
        // Abbrev 5: formal parameter {name:string, type:ref4}.
        put_uleb(abbrev_, 5); put_uleb(abbrev_, 0x05); abbrev_.push_back(std::byte{0});
        put_uleb(abbrev_, 0x03); put_uleb(abbrev_, 0x08);
        put_uleb(abbrev_, 0x49); put_uleb(abbrev_, 0x13);
        put_uleb(abbrev_, 0); put_uleb(abbrev_, 0);
        put_uleb(abbrev_, 0);

        const std::size_t length_at = info_.size();
        put_u32(info_, 0);                  // unit length
        put_u16(info_, 4);                  // DWARF v4
        put_u32(info_, 0);                  // abbrev offset
        info_.push_back(std::byte{8});       // address size
        put_uleb(info_, 1);                 // compile unit
        const ember::u32 base_offset = static_cast<ember::u32>(info_.size());
        put_uleb(info_, 2); put_string(info_, "int"); info_.push_back(std::byte{4});
        const ember::u32 pointer_offset = static_cast<ember::u32>(info_.size());
        put_uleb(info_, 3); put_u32(info_, base_offset);
        put_uleb(info_, 4); put_string(info_, "main");
        put_u64(info_, 0x401000); put_u32(info_, 0x20); put_u32(info_, base_offset);
        put_uleb(info_, 5); put_string(info_, "argv"); put_u32(info_, pointer_offset);
        put_uleb(info_, 0);                 // end subprogram children
        put_uleb(info_, 0);                 // end CU children
        patch_u32(info_, length_at,
                  static_cast<ember::u32>(info_.size() - length_at - 4));

        sections_[0].name = ".debug_info";
        sections_[0].size = info_.size();
        sections_[0].data = info_;
        sections_[1].name = ".debug_abbrev";
        sections_[1].size = abbrev_.size();
        sections_[1].data = abbrev_;
    }

    [[nodiscard]] ember::Format format() const noexcept override { return ember::Format::Elf; }
    [[nodiscard]] ember::Arch arch() const noexcept override { return ember::Arch::X86_64; }
    [[nodiscard]] ember::Endian endian() const noexcept override { return ember::Endian::Little; }
    [[nodiscard]] ember::addr_t entry_point() const noexcept override { return 0x401000; }
    [[nodiscard]] std::span<const ember::Section> sections() const noexcept override {
        return sections_;
    }
    [[nodiscard]] std::span<const ember::Symbol> symbols() const noexcept override { return {}; }
    [[nodiscard]] std::span<const std::byte> image() const noexcept override { return {}; }

protected:
    [[nodiscard]] std::vector<ember::Symbol>& mutable_symbols() noexcept override {
        return symbols_;
    }

private:
    std::vector<std::byte> info_;
    std::vector<std::byte> abbrev_;
    std::array<ember::Section, 2> sections_{};
    std::vector<ember::Symbol> symbols_;
};

}  // namespace

int main() {
    DwarfBinary binary;
    const auto functions = ember::parse_dwarf_functions(binary);
    auto main_function = functions.find(0x401000);
    check(main_function != functions.end(), "DWARF subprogram address imported");
    if (main_function != functions.end()) {
        check(main_function->second.name == "main", "DWARF function name imported");
        check(main_function->second.size == 0x20, "DWARF high_pc offset becomes size");
        check(main_function->second.signature.return_type == "int",
              "DWARF return type resolved");
        check(main_function->second.signature.params.size() == 1 &&
              main_function->second.signature.params[0].type == "int*" &&
              main_function->second.signature.params[0].name == "argv",
              "DWARF parameter pointer depth and name resolved");
    }
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
