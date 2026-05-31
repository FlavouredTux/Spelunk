#include <ember/analysis/discovery.hpp>
#include <ember/binary/binary.hpp>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
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

class Arm64MockBinary final : public ember::Binary {
public:
    Arm64MockBinary() {
        text_.fill(std::byte{0});
        rodata_.fill(std::byte{0});

        // paciasp; stp x29, x30, [sp, #-16]!; mov x29, sp; ret
        put32(text_, 0x00, 0xd503233fu);
        put32(text_, 0x04, 0xa9bf7bfdu);
        put32(text_, 0x08, 0x910003fdu);
        put32(text_, 0x0c, 0xd65f03c0u);

        // Frameless Apple/clang leaf: sub sp, sp, #0x20; mov x0, x0; ret
        put32(text_, 0x40, 0xd10083ffu);
        put32(text_, 0x44, 0xaa0003e0u);
        put32(text_, 0x48, 0xd65f03c0u);

        // Same bytes at an unaligned address must not be considered.
        put32(text_, 0x61, 0xd10083ffu);
        put32(text_, 0x65, 0xaa0003e0u);
        put32(text_, 0x69, 0xd65f03c0u);

        // Same bytes in non-code data must not be considered.
        put32(rodata_, 0x00, 0xa9bf7bfdu);
        put32(rodata_, 0x04, 0x910003fdu);
        put32(rodata_, 0x08, 0xd65f03c0u);

        text_section_.name = "__text";
        text_section_.vaddr = kBase;
        text_section_.size = text_.size();
        text_section_.flags.readable = true;
        text_section_.flags.executable = true;
        text_section_.flags.allocated = true;
        text_section_.data = std::span<const std::byte>(text_.data(), text_.size());

        data_section_.name = "__const";
        data_section_.vaddr = kDataBase;
        data_section_.size = rodata_.size();
        data_section_.flags.readable = true;
        data_section_.flags.allocated = true;
        data_section_.data = std::span<const std::byte>(rodata_.data(), rodata_.size());

        sections_[0] = text_section_;
        sections_[1] = data_section_;
    }

    [[nodiscard]] ember::Format format() const noexcept override {
        return ember::Format::MachO;
    }
    [[nodiscard]] ember::Arch arch() const noexcept override {
        return ember::Arch::Arm64;
    }
    [[nodiscard]] ember::Endian endian() const noexcept override {
        return ember::Endian::Little;
    }
    [[nodiscard]] ember::addr_t entry_point() const noexcept override {
        return kBase;
    }
    [[nodiscard]] std::span<const ember::Section> sections() const noexcept override {
        return std::span<const ember::Section>(sections_.data(), sections_.size());
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
    template <std::size_t N>
    static void put32(std::array<std::byte, N>& dst, std::size_t off, std::uint32_t v) {
        dst[off + 0] = static_cast<std::byte>(v & 0xffu);
        dst[off + 1] = static_cast<std::byte>((v >> 8) & 0xffu);
        dst[off + 2] = static_cast<std::byte>((v >> 16) & 0xffu);
        dst[off + 3] = static_cast<std::byte>((v >> 24) & 0xffu);
    }

    static constexpr ember::addr_t kBase = 0x100000000;
    static constexpr ember::addr_t kDataBase = 0x100001000;

    std::array<std::byte, 0x80> text_{};
    std::array<std::byte, 0x20> rodata_{};
    ember::Section             text_section_{};
    ember::Section             data_section_{};
    std::array<ember::Section, 2> sections_{};
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

void test_arm64_prologue_discovery() {
    Arm64MockBinary b;
    auto hits = ember::discover_from_prologues(b);
    std::ranges::sort(hits);

    check(std::ranges::find(hits, ember::addr_t{0x100000000}) != hits.end(),
          "arm64 hint plus framed function start discovered");
    check(std::ranges::find(hits, ember::addr_t{0x100000040}) != hits.end(),
          "arm64 frameless sub-sp function start discovered");
    check(std::ranges::find(hits, ember::addr_t{0x100000061}) == hits.end(),
          "arm64 unaligned prologue-shaped bytes are ignored");
    check(std::ranges::find(hits, ember::addr_t{0x100001000}) == hits.end(),
          "arm64 prologue-shaped bytes in data are ignored");
}

}  // namespace

int main() {
    test_stack_alloc_after_frame_setup_not_split();
    test_arm64_prologue_discovery();
    return fails == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
