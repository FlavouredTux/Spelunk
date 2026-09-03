// Focused coverage for the emitter's private binary string decoder.
#include "emitter_string_literals.hpp"

#include <ember/binary/binary.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

constexpr ember::addr_t kText = 0x1000;
constexpr ember::addr_t kRodata = 0x2000;
constexpr ember::addr_t kCfstrings = 0x3000;
constexpr ember::addr_t kCfdata = 0x4000;

int failures = 0;

void check(bool condition, const char* context) {
    if (condition) return;
    std::fprintf(stderr, "FAIL: %s\n", context);
    ++failures;
}

void check_string(const std::optional<std::string>& actual,
                  std::string_view expected,
                  const char* context) {
    if (actual && *actual == expected) return;
    std::fprintf(stderr, "FAIL: %s (got %s)\n", context,
                 actual ? actual->c_str() : "<null>");
    ++failures;
}

template <std::size_t N>
void write_bytes(std::array<std::byte, N>& destination,
                 std::size_t offset,
                 std::initializer_list<unsigned int> bytes) {
    for (const unsigned int byte : bytes) {
        destination[offset++] = static_cast<std::byte>(byte);
    }
}

template <std::size_t N, typename T>
void write_native(std::array<std::byte, N>& destination,
                  std::size_t offset,
                  const T& value) {
    std::memcpy(destination.data() + offset, &value, sizeof(value));
}

class MockBinary final : public ember::Binary {
public:
    explicit MockBinary(ember::Format format = ember::Format::MachO)
        : format_(format) {
        text_.fill(std::byte{0});
        rodata_.fill(static_cast<std::byte>('Q'));
        cfstrings_.fill(std::byte{0});
        cfdata_.fill(std::byte{0});

        write_bytes(text_, 0, {'C', 'O', 'D', 'E', 0});
        write_bytes(rodata_, 0, {'h', 'e', 'l', 'l', 'o', 0});
        write_bytes(rodata_, 8, {'A', '\n', '"', '\\', 0x80, 'B', 0});
        write_bytes(rodata_, 0x18, {'A', 0});

        write_bytes(cfdata_, 0, {'h', 0xc3, 0xa9});
        write_bytes(cfdata_, 0x10,
                    {0x41, 0x00, 0x3d, 0xd8, 0x00, 0xde, 0x5a, 0x00});
        write_bytes(cfdata_, 0x20, {0x3d, 0xd8});

        write_cfstring_record(0, kCfdata, 3);
        write_cfstring_record(1, kCfdata + 0x10, 4);
        write_cfstring_record(2, kCfdata + 0x20, 1);

        configure_section(sections_[0], ".text", kText, text_, true);
        configure_section(sections_[1], ".rodata", kRodata, rodata_, false);
        configure_section(sections_[2], "__DATA,__cfstring", kCfstrings,
                          cfstrings_, false);
        configure_section(sections_[3], "__TEXT,__cstring", kCfdata,
                          cfdata_, false);
    }

    [[nodiscard]] ember::Format format() const noexcept override {
        return format_;
    }
    [[nodiscard]] ember::Arch arch() const noexcept override {
        return ember::Arch::X86_64;
    }
    [[nodiscard]] ember::Endian endian() const noexcept override {
        return ember::Endian::Little;
    }
    [[nodiscard]] ember::addr_t entry_point() const noexcept override {
        return kText;
    }
    [[nodiscard]] std::span<const ember::Section>
    sections() const noexcept override {
        return sections_;
    }
    [[nodiscard]] std::span<const ember::Symbol>
    symbols() const noexcept override {
        return symbols_;
    }
    [[nodiscard]] std::span<const std::byte> image() const noexcept override {
        return {};
    }
    [[nodiscard]] std::span<const std::byte>
    bytes_at(ember::addr_t address) const noexcept override {
        ++byte_reads_[address];
        return Binary::bytes_at(address);
    }

    [[nodiscard]] std::size_t byte_reads_at(ember::addr_t address) const {
        auto it = byte_reads_.find(address);
        return it == byte_reads_.end() ? 0 : it->second;
    }

protected:
    [[nodiscard]] std::vector<ember::Symbol>&
    mutable_symbols() noexcept override {
        return symbols_;
    }

private:
    template <std::size_t N>
    static void configure_section(ember::Section& section,
                                  std::string name,
                                  ember::addr_t address,
                                  const std::array<std::byte, N>& bytes,
                                  bool executable) {
        section.name = std::move(name);
        section.vaddr = address;
        section.size = bytes.size();
        section.flags.readable = true;
        section.flags.executable = executable;
        section.data = bytes;
    }

    void write_cfstring_record(std::size_t index,
                               ember::addr_t data_address,
                               ember::u64 length) {
        const std::size_t offset = index * 32;
        write_native(cfstrings_, offset + 16,
                     static_cast<ember::u64>(data_address));
        write_native(cfstrings_, offset + 24, length);
    }

    ember::Format format_;
    std::array<std::byte, 0x20> text_{};
    std::array<std::byte, 0x40> rodata_{};
    std::array<std::byte, 0x80> cfstrings_{};
    std::array<std::byte, 0x40> cfdata_{};
    std::array<ember::Section, 4> sections_{};
    std::vector<ember::Symbol> symbols_;
    mutable std::map<ember::addr_t, std::size_t> byte_reads_;
};

void test_null_binary() {
    const ember::emit::BinaryStringLiterals strings(nullptr);
    check(!strings.try_c_string_at(kRodata), "null binary rejects C string");
    check(!strings.try_cfstring_at(kCfstrings), "null binary rejects CFString");
}

void test_c_strings() {
    MockBinary binary;
    const ember::emit::BinaryStringLiterals strings(&binary);

    check_string(strings.try_c_string_at(kRodata), "hello",
                 "non-executable C string");
    check(!strings.try_c_string_at(kText),
          "executable bytes are not C strings");
    check(binary.byte_reads_at(kText) == 0,
          "executable rejection avoids reading code bytes");
    check_string(strings.try_c_string_at(kRodata + 8),
                 "A\\n\\\"\\\\\\x80" "B",
                 "C string escaping remains unchanged");
    check(!strings.try_c_string_at(kRodata + 0x30),
          "unterminated C string is rejected");

    const ember::addr_t short_string = kRodata + 0x18;
    check(!strings.try_c_string_at(short_string),
          "default printable minimum rejects one character");
    check(binary.byte_reads_at(short_string) == 1,
          "default rejection performs one read");
    check(!strings.try_c_string_at(short_string),
          "default rejection is cached");
    check(binary.byte_reads_at(short_string) == 1,
          "cached rejection performs no second read");
    check_string(strings.try_c_string_at(short_string, 1), "A",
                 "explicit printable minimum accepts one character");
    check(binary.byte_reads_at(short_string) == 2,
          "non-default threshold bypasses the default cache");

    check(binary.byte_reads_at(kRodata) == 1,
          "first successful default lookup performs one read");
    check_string(strings.try_c_string_at(kRodata), "hello",
                 "successful default lookup is cached");
    check(binary.byte_reads_at(kRodata) == 1,
          "cached success performs no second read");
}

void test_cfstrings() {
    MockBinary binary;
    const ember::emit::BinaryStringLiterals strings(&binary);

    check_string(strings.try_cfstring_at(kCfstrings), "h\xc3\xa9",
                 "UTF-8 CFString");
    check_string(strings.try_cfstring_at(kCfstrings + 32),
                 "A\xf0\x9f\x98\x80Z", "UTF-16 CFString surrogate pair");
    check(!strings.try_cfstring_at(kCfstrings + 64),
          "malformed UTF-16 high surrogate is rejected");
    check(!strings.try_cfstring_at(kCfstrings - 1),
          "address below CFString section is rejected");
    check(!strings.try_cfstring_at(kCfstrings + 0x80),
          "address above CFString section is rejected");

    MockBinary elf_binary(ember::Format::Elf);
    const ember::emit::BinaryStringLiterals elf_strings(&elf_binary);
    check(!elf_strings.try_cfstring_at(kCfstrings),
          "non-Mach-O __cfstring section is ignored");
}

}  // namespace

int main() {
    test_null_binary();
    test_c_strings();
    test_cfstrings();

    if (failures != 0) {
        std::fprintf(stderr, "%d emitter string literal test(s) failed\n",
                     failures);
        return 1;
    }
    std::puts("emitter string literal tests passed");
    return 0;
}
