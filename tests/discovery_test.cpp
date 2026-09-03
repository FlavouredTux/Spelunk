#include <ember/analysis/discovery.hpp>
#include <ember/analysis/indirect_calls.hpp>
#include <ember/analysis/pipeline.hpp>
#include <ember/analysis/vtables.hpp>
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

        // A two-byte jump whose displacement byte (0x55) begins a valid
        // prologue-shaped byte stream. The heuristic sweep will nominate
        // kBase+0x21, but it is inside the jump at kBase+0x20 and must be
        // rejected by final function enumeration.
        const std::array<unsigned char, 8> overlapping{
            0xeb, 0x55, 0x48, 0x89, 0xe5, 0x90, 0x90, 0xc3,
        };
        for (std::size_t i = 0; i < overlapping.size(); ++i) {
            text_[0x20 + i] = static_cast<std::byte>(overlapping[i]);
        }
        ember::Symbol overlap_owner;
        overlap_owner.name = "overlap_owner";
        overlap_owner.addr = kBase + 0x20;
        // Leave the owner unsized so this specifically exercises the
        // instruction-overlap filter rather than sized-symbol containment.
        overlap_owner.size = 0;
        overlap_owner.kind = ember::SymbolKind::Function;
        syms_.push_back(std::move(overlap_owner));

        // A CET-enabled function:
        //   endbr64; push rbp; mov rbp, rsp; ret
        // Discovery must keep the start at ENDBR, not split at 0x401064.
        const std::array<unsigned char, 9> cet_framed{
            0xf3, 0x0f, 0x1e, 0xfa, 0x55, 0x48, 0x89, 0xe5, 0xc3,
        };
        for (std::size_t i = 0; i < cet_framed.size(); ++i) {
            text_[0x60 + i] = static_cast<std::byte>(cet_framed[i]);
        }

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

class NamedCodeTargetBinary final : public ember::Binary {
public:
    static constexpr ember::addr_t kCaller = 0x401000;
    static constexpr ember::addr_t kSlot   = 0x402000;
    static constexpr ember::addr_t kTarget = 0x403000;
    static constexpr ember::addr_t kUnrelated = 0x404000;

    NamedCodeTargetBinary() {
        caller_.fill(std::byte{0x90});
        slot_.fill(std::byte{0});
        target_.fill(std::byte{0x90});
        unrelated_.fill(std::byte{0x90});

        // call qword ptr [rip + 0xffa]; ret
        caller_[0] = std::byte{0xff};
        caller_[1] = std::byte{0x15};
        put32(caller_, 2, static_cast<std::uint32_t>(kSlot - (kCaller + 6)));
        caller_[6] = std::byte{0xc3};
        put64(slot_, 0, kTarget);
        put64(slot_, 8, kTarget);
        target_[0] = std::byte{0xc3};

        // An unrelated executable function containing `call rax`. This keeps
        // the x64 FF-prefilter active while the scoped caller below lives in a
        // canonical, non-executable code section.
        unrelated_[0] = std::byte{0xff};
        unrelated_[1] = std::byte{0xd0};
        unrelated_[2] = std::byte{0xc3};

        sections_[0].name = ".text";
        sections_[0].vaddr = kCaller;
        sections_[0].size = caller_.size();
        sections_[0].flags.readable = true;
        sections_[0].flags.executable = false;
        sections_[0].flags.allocated = true;
        sections_[0].data = caller_;

        sections_[1].name = ".rdata";
        sections_[1].vaddr = kSlot;
        sections_[1].size = slot_.size();
        sections_[1].flags.readable = true;
        sections_[1].flags.allocated = true;
        sections_[1].data = slot_;

        sections_[2].name = ".text";
        sections_[2].vaddr = kTarget;
        sections_[2].size = target_.size();
        sections_[2].flags.readable = true;
        sections_[2].flags.executable = false;
        sections_[2].flags.allocated = true;
        sections_[2].data = target_;

        sections_[3].name = ".noise";
        sections_[3].vaddr = kUnrelated;
        sections_[3].size = unrelated_.size();
        sections_[3].flags.readable = true;
        sections_[3].flags.executable = true;
        sections_[3].flags.allocated = true;
        sections_[3].data = unrelated_;

        ember::Symbol caller;
        caller.name = "caller";
        caller.addr = kCaller;
        caller.size = 7;
        caller.kind = ember::SymbolKind::Function;
        symbols_.push_back(std::move(caller));

        ember::Symbol target;
        target.name = "target";
        target.addr = kTarget;
        target.size = 1;
        target.kind = ember::SymbolKind::Function;
        symbols_.push_back(std::move(target));

        ember::Symbol unrelated;
        unrelated.name = "unrelated_indirect";
        unrelated.addr = kUnrelated;
        unrelated.size = 3;
        unrelated.kind = ember::SymbolKind::Function;
        symbols_.push_back(std::move(unrelated));
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
        return kCaller;
    }
    [[nodiscard]] std::span<const ember::Section> sections() const noexcept override {
        return sections_;
    }
    [[nodiscard]] std::span<const ember::Symbol> symbols() const noexcept override {
        return symbols_;
    }
    [[nodiscard]] std::span<const std::byte> image() const noexcept override {
        return {};
    }

protected:
    [[nodiscard]] std::vector<ember::Symbol>& mutable_symbols() noexcept override {
        return symbols_;
    }

private:
    template <std::size_t N>
    static void put32(std::array<std::byte, N>& dst, std::size_t off,
                      std::uint32_t value) {
        for (std::size_t i = 0; i < 4; ++i) {
            dst[off + i] = static_cast<std::byte>((value >> (i * 8)) & 0xffu);
        }
    }

    template <std::size_t N>
    static void put64(std::array<std::byte, N>& dst, std::size_t off,
                      std::uint64_t value) {
        for (std::size_t i = 0; i < 8; ++i) {
            dst[off + i] = static_cast<std::byte>((value >> (i * 8)) & 0xffu);
        }
    }

    std::array<std::byte, 0x10> caller_{};
    std::array<std::byte, 0x10> slot_{};
    std::array<std::byte, 0x10> target_{};
    std::array<std::byte, 0x10> unrelated_{};
    std::array<ember::Section, 4> sections_{};
    std::vector<ember::Symbol> symbols_{};
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
    check(std::ranges::find(hits, 0x401060) != hits.end(),
          "x64 endbr64-prefixed function start discovered at entry hint");
    check(std::ranges::find(hits, 0x401064) == hits.end(),
          "x64 endbr64-prefixed function is not split after entry hint");
}

void test_candidate_inside_instruction_is_rejected() {
    MockBinary binary;
    auto functions = ember::enumerate_functions(binary);
    check(std::ranges::find_if(functions, [](const auto& function) {
              return function.addr == 0x401020;
          }) != functions.end(),
          "authoritative owner function retained");
    check(std::ranges::find_if(functions, [](const auto& function) {
              return function.addr == 0x401021;
          }) == functions.end(),
          "prologue-shaped displacement byte rejected as function start");
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

void test_named_code_addresses_without_executable_flags() {
    NamedCodeTargetBinary binary;
    check(!binary.sections()[0].flags.executable,
          "named code caller fixture has no executable flag");
    check(ember::addr_in_code_section(binary, NamedCodeTargetBinary::kCaller),
          "canonical predicate accepts a non-executable .text caller");
    check(!binary.sections()[2].flags.executable,
          "named code target fixture has no executable flag");
    check(ember::addr_in_code_section(binary, NamedCodeTargetBinary::kTarget),
          "canonical predicate accepts a non-executable .text address");

    const auto vtables = ember::discover_runtime_vtables(binary);
    check(vtables.size() == 1 &&
              vtables.front().vaddr == NamedCodeTargetBinary::kSlot &&
              vtables.front().methods.size() == 2 &&
              vtables.front().methods[0] == NamedCodeTargetBinary::kTarget &&
              vtables.front().methods[1] == NamedCodeTargetBinary::kTarget,
          "runtime vtable accepts methods in non-executable .text");

    const auto classified = ember::compute_classified_callees(
        binary, NamedCodeTargetBinary::kCaller);
    check(std::ranges::find_if(classified, [](const auto& edge) {
              return edge.target == NamedCodeTargetBinary::kTarget &&
                     edge.kind == ember::CalleeKind::IndirectConst &&
                     edge.site == NamedCodeTargetBinary::kCaller;
          }) != classified.end(),
          "static function pointer resolves from non-executable .text");

    const std::array scope{NamedCodeTargetBinary::kCaller};
    const auto statically_resolved =
        ember::resolve_indirect_calls(binary, nullptr, scope);
    const auto static_it =
        statically_resolved.find(NamedCodeTargetBinary::kCaller);
    check(static_it != statically_resolved.end() &&
              static_it->second == NamedCodeTargetBinary::kTarget,
          "static resolver accepts code addresses without executable flags");
    check(statically_resolved.size() == 1,
          "scoped resolution ignores the unrelated executable FF hit");

    binary.record_indirect_edge(NamedCodeTargetBinary::kCaller,
                                NamedCodeTargetBinary::kTarget);
    const auto traced_resolved =
        ember::resolve_indirect_calls(binary, nullptr, scope);
    const auto traced_it =
        traced_resolved.find(NamedCodeTargetBinary::kCaller);
    check(traced_it != traced_resolved.end() &&
              traced_it->second == NamedCodeTargetBinary::kTarget,
          "traced resolver accepts code addresses without executable flags");
}

}  // namespace

int main() {
    test_stack_alloc_after_frame_setup_not_split();
    test_candidate_inside_instruction_is_rejected();
    test_arm64_prologue_discovery();
    test_named_code_addresses_without_executable_flags();
    return fails == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
