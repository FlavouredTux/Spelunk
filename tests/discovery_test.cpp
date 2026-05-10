#include <ember/analysis/discovery.hpp>
#include <ember/binary/binary.hpp>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <span>
#include <vector>

namespace {

int fails = 0;

void check(bool cond, const char* ctx) {
    if (!cond) {
        std::fprintf(stderr, "FAIL: %s\n", ctx);
        ++fails;
    }
}

class MockBinary final : public ember::Binary {
public:
    MockBinary() {
        text_.fill(static_cast<std::byte>(0x90u));

        // A normal frame-using function:
        //   push rbp; mov rbp, rsp; sub rsp, 0x400; leave; ret
        // The prologue sweep must report only 0x401000, not the inner
        // stack-allocation instruction at 0x401004.
        const std::array<unsigned char, 13> framed{
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x81, 0xec,
            0x00, 0x04, 0x00, 0x00, 0xc9, 0xc3,
        };
        for (std::size_t i = 0; i < framed.size(); ++i) {
            text_[i] = static_cast<std::byte>(framed[i]);
        }

        // A frameless function that genuinely starts with `sub rsp`.
        const std::array<unsigned char, 8> frameless{
            0x48, 0x83, 0xec, 0x20, 0x48, 0x83, 0xc4, 0x20,
        };
        for (std::size_t i = 0; i < frameless.size(); ++i) {
            text_[0x40 + i] = static_cast<std::byte>(frameless[i]);
        }
        text_[0x48] = static_cast<std::byte>(0xc3u);

        section_.name = ".text";
        section_.vaddr = kBase;
        section_.size = text_.size();
        section_.flags.readable = true;
        section_.flags.executable = true;
        section_.flags.allocated = true;
        section_.data = std::span<const std::byte>(text_.data(), text_.size());
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
        return kBase;
    }
    [[nodiscard]] std::span<const ember::Section> sections() const noexcept override {
        return std::span<const ember::Section>(&section_, 1);
    }
    [[nodiscard]] std::span<const ember::Symbol> symbols() const noexcept override {
        return {};
    }
    [[nodiscard]] std::span<const std::byte> image() const noexcept override {
        return {};
    }

protected:
    [[nodiscard]] std::vector<ember::Symbol>& mutable_symbols() noexcept override {
        return syms_;
    }

private:
    static constexpr ember::addr_t kBase = 0x401000;

    std::array<std::byte, 0x80> text_{};
    ember::Section             section_{};
    std::vector<ember::Symbol>  syms_{};
};

void test_stack_alloc_after_frame_setup_not_split() {
    MockBinary b;
    auto hits = ember::discover_from_prologues(b);
    std::ranges::sort(hits);

    check(std::ranges::find(hits, 0x401000) != hits.end(),
          "framed function start discovered");
    check(std::ranges::find(hits, 0x401004) == hits.end(),
          "stack allocation after frame setup is not a new function");
    check(std::ranges::find(hits, 0x401040) != hits.end(),
          "frameless sub-rsp function is still discovered");
}

}  // namespace

int main() {
    test_stack_alloc_after_frame_setup_not_split();
    return fails == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
