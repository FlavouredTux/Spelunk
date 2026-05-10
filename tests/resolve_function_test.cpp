#include <ember/analysis/pipeline.hpp>
#include <ember/binary/binary.hpp>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <span>
#include <string_view>
#include <vector>

namespace {

int fails = 0;

void check(bool cond, const char* ctx) {
    if (!cond) {
        std::fprintf(stderr, "FAIL: %s\n", ctx);
        ++fails;
    }
}

void check_eq(ember::addr_t got, ember::addr_t want, const char* ctx) {
    if (got != want) {
        std::fprintf(stderr, "FAIL: %s (got %#llx, want %#llx)\n",
                     ctx,
                     static_cast<unsigned long long>(got),
                     static_cast<unsigned long long>(want));
        ++fails;
    }
}

void check_eq_u64(ember::u64 got, ember::u64 want, const char* ctx) {
    if (got != want) {
        std::fprintf(stderr, "FAIL: %s (got %#llx, want %#llx)\n",
                     ctx,
                     static_cast<unsigned long long>(got),
                     static_cast<unsigned long long>(want));
        ++fails;
    }
}

constexpr ember::addr_t kTextBase = 0x401000;
constexpr ember::addr_t kDataBase = 0x402000;

class MockBinary final : public ember::Binary {
public:
    MockBinary() {
        text_.fill(static_cast<std::byte>(0x90u));
        text_[0] = static_cast<std::byte>(0xC3u);  // ret

        const std::string_view msg = "AroupUpJoinTimeMs";
        for (std::size_t i = 0; i < msg.size(); ++i) {
            data_[i] = static_cast<std::byte>(static_cast<unsigned char>(msg[i]));
        }

        sections_[0].name = ".text";
        sections_[0].vaddr = kTextBase;
        sections_[0].size = text_.size();
        sections_[0].flags.readable = true;
        sections_[0].flags.executable = true;
        sections_[0].flags.allocated = true;
        sections_[0].data = std::span<const std::byte>(text_.data(), text_.size());

        sections_[1].name = ".rodata";
        sections_[1].vaddr = kDataBase;
        sections_[1].size = data_.size();
        sections_[1].flags.readable = true;
        sections_[1].flags.allocated = true;
        sections_[1].data = std::span<const std::byte>(data_.data(), data_.size());

        ember::Symbol fn;
        fn.name = "entry";
        fn.addr = kTextBase;
        fn.size = 1;
        fn.kind = ember::SymbolKind::Function;
        syms_.push_back(std::move(fn));
    }

    [[nodiscard]] ember::Format format() const noexcept override {
        return ember::Format::Elf;
    }
    [[nodiscard]] ember::Arch arch() const noexcept override {
        return ember::Arch::X86_64;
    }
    [[nodiscard]] ember::Endian endian() const noexcept override {
        return ember::Endian::Little;
    }
    [[nodiscard]] ember::addr_t entry_point() const noexcept override {
        return kTextBase;
    }
    [[nodiscard]] std::span<const ember::Section> sections() const noexcept override {
        return sections_;
    }
    [[nodiscard]] std::span<const ember::Symbol> symbols() const noexcept override {
        return syms_;
    }
    [[nodiscard]] std::span<const std::byte> image() const noexcept override {
        return {};
    }

protected:
    [[nodiscard]] std::vector<ember::Symbol>& mutable_symbols() noexcept override {
        return syms_;
    }

private:
    std::array<std::byte, 0x20>      text_{};
    std::array<std::byte, 0x40>      data_{};
    std::array<ember::Section, 2>    sections_{};
    std::vector<ember::Symbol>       syms_{};
};

void test_literal_sub_must_be_code() {
    MockBinary b;

    auto text = ember::resolve_function(b, "sub_401000");
    check(text.has_value(), "sub_ literal in .text resolves");
    if (text) {
        check_eq(text->start, kTextBase, "text start");
        check_eq_u64(text->size, 1, "text function size is preserved");
    }

    auto data_sub = ember::resolve_function(b, "sub_402000");
    check(!data_sub.has_value(), "sub_ literal in .rodata is rejected");

    auto data_hex = ember::resolve_function(b, "0x402000");
    check(!data_hex.has_value(), "hex literal in .rodata is rejected");
}

}  // namespace

int main() {
    test_literal_sub_must_be_code();
    return fails == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
