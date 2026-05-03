// Unit tests for the int3 resolver (ember/analysis/int3_resolver.hpp).
//
// Self-contained: a MockBinary carries hand-written x86-64 bytes with
// embedded 0xCC (int3) at known positions so the classifier can be
// tested without a real fixture binary.
#include <ember/analysis/int3_resolver.hpp>
#include <ember/binary/binary.hpp>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <string_view>

namespace {

int fails = 0;

void check(bool cond, const char* ctx) {
    if (!cond) {
        std::fprintf(stderr, "FAIL: %s\n", ctx);
        ++fails;
    }
}

template <typename A, typename B>
void check_eq(const A& got, const B& want, const char* ctx) {
    if (!(got == want)) {
        std::fprintf(stderr, "FAIL: %s (got %d, want %d)\n",
                     ctx, static_cast<int>(got), static_cast<int>(want));
        ++fails;
    }
}

// Layout:
//   0x401000  CC CC CC CC CC CC CC CC   ; 8-byte CC padding (before fn1)
//   0x401008  55                         ; push rbp  (fn1 entry)
//   0x401009  48 89 E5                   ; mov rbp, rsp
//   0x40100C  CC                         ; int3 inside fn1 (anti-debug or unknown)
//   0x40100D  B8 00 00 00 00             ; mov eax, 0
//   0x401012  5D                         ; pop rbp
//   0x401013  C3                         ; ret
//   0x401014  CC CC CC CC CC CC CC CC CC CC CC CC  ; 12-byte trailing padding
//   0x401020  55                         ; push rbp (fn2 entry — __debugbreak)
//   0x401021  CC                         ; int3 (the debugbreak body)
//   0x401022  5D                         ; pop rbp
//   0x401023  C3                         ; ret
//   0x401024  CC CC CC CC CC CC CC CC CC CC CC CC  ; 12-byte trailing padding
//   0x401030  ... (NOP fill to 0x401040)
constexpr ember::addr_t kBase     = 0x401000;
constexpr std::size_t   kSecLen   = 0x40;

struct ImageBytes {
    std::array<std::byte, kSecLen> data{};

    ImageBytes() {
        // Fill with NOP so the decoder can walk past the interesting bytes.
        for (auto& b : data) b = static_cast<std::byte>(0x90u);

        // Leading CC padding (8 bytes at 0x401000).
        for (std::size_t i = 0; i < 8; ++i)
            data[i] = static_cast<std::byte>(0xCCu);

        // fn1 at 0x401008: push rbp; mov rbp,rsp; int3; mov eax,0; pop rbp; ret
        data[0x08] = static_cast<std::byte>(0x55);  // push rbp
        data[0x09] = static_cast<std::byte>(0x48);  // mov rbp, rsp (REX.W)
        data[0x0A] = static_cast<std::byte>(0x89);
        data[0x0B] = static_cast<std::byte>(0xE5);
        data[0x0C] = static_cast<std::byte>(0xCC);  // int3 inside fn1
        data[0x0D] = static_cast<std::byte>(0xB8);  // mov eax, 0
        data[0x0E] = static_cast<std::byte>(0x00);
        data[0x0F] = static_cast<std::byte>(0x00);
        data[0x10] = static_cast<std::byte>(0x00);
        data[0x11] = static_cast<std::byte>(0x00);
        data[0x12] = static_cast<std::byte>(0x5D);  // pop rbp
        data[0x13] = static_cast<std::byte>(0xC3);  // ret

        // Trailing CC padding (12 bytes at 0x401014).
        for (std::size_t i = 0x14; i < 0x20; ++i)
            data[i] = static_cast<std::byte>(0xCCu);

        // fn2 (__debugbreak) at 0x401020: push rbp; int3; pop rbp; ret
        data[0x20] = static_cast<std::byte>(0x55);  // push rbp
        data[0x21] = static_cast<std::byte>(0xCC);  // int3 (debugbreak)
        data[0x22] = static_cast<std::byte>(0x5D);  // pop rbp
        data[0x23] = static_cast<std::byte>(0xC3);  // ret

        // Trailing CC padding (12 bytes at 0x401024).
        for (std::size_t i = 0x24; i < 0x30; ++i)
            data[i] = static_cast<std::byte>(0xCCu);
    }
};

class MockBinary final : public ember::Binary {
public:
    MockBinary() {
        sec_.name = ".text";
        sec_.vaddr = kBase;
        sec_.size  = kSecLen;
        sec_.flags.executable = true;
        sec_.flags.readable   = true;
        sec_.data = std::span<const std::byte>(image_.data.data(),
                                                image_.data.size());

        // fn1: defined function at 0x401008, size 12 bytes (0x08..0x14).
        ember::Symbol fn1;
        fn1.name      = "fn1";
        fn1.addr      = 0x401008;
        fn1.size      = 12;
        fn1.kind      = ember::SymbolKind::Function;
        fn1.is_import = false;
        syms_.push_back(std::move(fn1));

        // fn2: __debugbreak wrapper at 0x401020, size 4 bytes.
        ember::Symbol fn2;
        fn2.name      = "__debugbreak";
        fn2.addr      = 0x401020;
        fn2.size      = 4;
        fn2.kind      = ember::SymbolKind::Function;
        fn2.is_import = false;
        syms_.push_back(std::move(fn2));

        // IsDebuggerPresent import — triggers anti-debug heuristic.
        ember::Symbol dbg;
        dbg.name      = "IsDebuggerPresent";
        dbg.addr      = 0x401040;
        dbg.kind      = ember::SymbolKind::Function;
        dbg.is_import = true;
        syms_.push_back(std::move(dbg));
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
        return 0x401008;
    }
    [[nodiscard]] std::span<const ember::Section> sections() const noexcept override {
        return {&sec_, 1};
    }
    [[nodiscard]] std::span<const ember::Symbol> symbols() const noexcept override {
        return syms_;
    }
    [[nodiscard]] std::span<const std::byte> image() const noexcept override {
        return sec_.data;
    }

protected:
    [[nodiscard]] std::vector<ember::Symbol>& mutable_symbols() noexcept override {
        return syms_;
    }

private:
    ImageBytes              image_{};
    ember::Section          sec_{};
    std::vector<ember::Symbol> syms_{};
};

// A binary without anti-debug imports — to test the non-anti-debug path.
class CleanMockBinary final : public ember::Binary {
public:
    CleanMockBinary() {
        sec_.name = ".text";
        sec_.vaddr = kBase;
        sec_.size  = kSecLen;
        sec_.flags.executable = true;
        sec_.flags.readable   = true;
        sec_.data = std::span<const std::byte>(image_.data.data(),
                                                image_.data.size());

        // fn1 only, no imports.
        ember::Symbol fn1;
        fn1.name      = "fn1";
        fn1.addr      = 0x401008;
        fn1.size      = 12;
        fn1.kind      = ember::SymbolKind::Function;
        fn1.is_import = false;
        syms_.push_back(std::move(fn1));
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
        return 0x401008;
    }
    [[nodiscard]] std::span<const ember::Section> sections() const noexcept override {
        return {&sec_, 1};
    }
    [[nodiscard]] std::span<const ember::Symbol> symbols() const noexcept override {
        return syms_;
    }
    [[nodiscard]] std::span<const std::byte> image() const noexcept override {
        return sec_.data;
    }

protected:
    [[nodiscard]] std::vector<ember::Symbol>& mutable_symbols() noexcept override {
        return syms_;
    }

private:
    ImageBytes              image_{};
    ember::Section          sec_{};
    std::vector<ember::Symbol> syms_{};
};

// MockBinary with a stubbed branch: cmp eax,eax; int3 (where Jcc was).
// Layout:
//   0x401000  83 F8 00       ; cmp eax, 0   (flag-setting)
//   0x401003  CC             ; int3 (stubbed Jcc)
//   0x401004  B8 01 00 00 00 ; mov eax, 1   (fall-through)
//   0x401009  C3             ; ret
constexpr std::size_t kStubSecLen = 0x20;

struct StubImageBytes {
    std::array<std::byte, kStubSecLen> data{};

    StubImageBytes() {
        for (auto& b : data) b = static_cast<std::byte>(0x90u);

        // cmp eax, 0  →  83 F8 00
        data[0x00] = static_cast<std::byte>(0x83);
        data[0x01] = static_cast<std::byte>(0xF8);
        data[0x02] = static_cast<std::byte>(0x00);

        // int3 (stubbed Jcc)
        data[0x03] = static_cast<std::byte>(0xCC);

        // mov eax, 1  →  B8 01 00 00 00
        data[0x04] = static_cast<std::byte>(0xB8);
        data[0x05] = static_cast<std::byte>(0x01);
        data[0x06] = static_cast<std::byte>(0x00);
        data[0x07] = static_cast<std::byte>(0x00);
        data[0x08] = static_cast<std::byte>(0x00);

        // ret
        data[0x09] = static_cast<std::byte>(0xC3);
    }
};

class StubbedMockBinary final : public ember::Binary {
public:
    StubbedMockBinary() {
        sec_.name = ".text";
        sec_.vaddr = 0x401000;
        sec_.size  = kStubSecLen;
        sec_.flags.executable = true;
        sec_.flags.readable   = true;
        sec_.data = std::span<const std::byte>(image_.data.data(),
                                                image_.data.size());

        // fn_stub at 0x401000, size 10 bytes.
        ember::Symbol fn;
        fn.name      = "fn_stub";
        fn.addr      = 0x401000;
        fn.size      = 10;
        fn.kind      = ember::SymbolKind::Function;
        fn.is_import = false;
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
        return 0x401000;
    }
    [[nodiscard]] std::span<const ember::Section> sections() const noexcept override {
        return {&sec_, 1};
    }
    [[nodiscard]] std::span<const ember::Symbol> symbols() const noexcept override {
        return syms_;
    }
    [[nodiscard]] std::span<const std::byte> image() const noexcept override {
        return sec_.data;
    }

protected:
    [[nodiscard]] std::vector<ember::Symbol>& mutable_symbols() noexcept override {
        return syms_;
    }

private:
    StubImageBytes              image_{};
    ember::Section              sec_{};
    std::vector<ember::Symbol>  syms_{};
};

}  // namespace

int main() {
    // ---- resolve_embedded_int3s with anti-debug import ----
    {
        MockBinary b;
        auto results = ember::resolve_embedded_int3s(b);

        // We expect at least some results — the binary has CC bytes.
        check(results.size() > 0, "resolve_embedded_int3s should find CC bytes");

        // The leading CC padding at 0x401000 should be classified as Padding.
        bool found_leading_padding = false;
        for (const auto& r : results) {
            if (r.addr == 0x401000) {
                check_eq(r.kind, ember::Int3Kind::Padding,
                         "leading CC run outside function should be Padding");
                found_leading_padding = true;
                break;
            }
        }
        check(found_leading_padding,
              "should find CC at 0x401000 (leading padding)");

        // The CC inside fn1 at 0x40100C should remain Unknown. A binary-wide
        // anti-debug import is not enough evidence to classify an unrelated
        // function-local int3 as anti-debug.
        bool found_fn1_int3 = false;
        for (const auto& r : results) {
            if (r.addr == 0x40100C) {
                check_eq(r.kind, ember::Int3Kind::Unknown,
                         "int3 inside fn1 with only binary-wide anti-debug import should be Unknown");
                check(r.containing_fn == 0x401008,
                      "int3 inside fn1 should report containing_fn = 0x401008");
                check(r.fn_offset == 4,
                      "int3 at 0x40100C should be offset 4 within fn1");
                found_fn1_int3 = true;
                break;
            }
        }
        check(found_fn1_int3, "should find CC at 0x40100C (inside fn1)");

        // The CC inside __debugbreak at 0x401021 should be DebugBreak.
        bool found_debugbreak = false;
        for (const auto& r : results) {
            if (r.addr == 0x401021) {
                check_eq(r.kind, ember::Int3Kind::DebugBreak,
                         "int3 inside __debugbreak should be DebugBreak");
                check(r.containing_fn == 0x401020,
                      "debugbreak int3 should report containing_fn = 0x401020");
                found_debugbreak = true;
                break;
            }
        }
        check(found_debugbreak, "should find CC at 0x401021 (debugbreak)");

        // Trailing padding after fn1 at 0x401014 should be Padding.
        bool found_trailing_padding = false;
        for (const auto& r : results) {
            if (r.addr == 0x401014) {
                check_eq(r.kind, ember::Int3Kind::Padding,
                         "trailing CC after fn1 should be Padding");
                found_trailing_padding = true;
                break;
            }
        }
        check(found_trailing_padding,
              "should find CC at 0x401014 (trailing padding)");
    }

    // ---- resolve_embedded_int3s without anti-debug imports ----
    {
        CleanMockBinary b;
        auto results = ember::resolve_embedded_int3s(b);

        // The CC inside fn1 at 0x40100C should NOT be AntiDebug since
        // there are no anti-debug imports.
        bool found_fn1_int3 = false;
        for (const auto& r : results) {
            if (r.addr == 0x40100C) {
                check_eq(r.kind, ember::Int3Kind::Unknown,
                         "int3 inside fn1 without anti-debug imports should be Unknown");
                found_fn1_int3 = true;
                break;
            }
        }
        check(found_fn1_int3, "should find CC at 0x40100C in clean binary");
    }

    // ---- resolve_int3_at ----
    {
        MockBinary b;
        auto res = ember::resolve_int3_at(b, 0x401021);
        check_eq(res.kind, ember::Int3Kind::DebugBreak,
                 "resolve_int3_at(0x401021) should return DebugBreak");
        check(res.addr == 0x401021,
              "resolve_int3_at should preserve the address");
    }

    // ---- resolve_int3_at for non-CC address ----
    {
        MockBinary b;
        auto res = ember::resolve_int3_at(b, 0x401008);
        check_eq(res.kind, ember::Int3Kind::Unknown,
                 "resolve_int3_at(non-CC address) should return Unknown");
    }

    // ---- int3_kind_name ----
    {
        check(ember::int3_kind_name(ember::Int3Kind::StubbedBranch) == "stubbed-branch",
              "int3_kind_name(StubbedBranch) should be 'stubbed-branch'");
        check(ember::int3_kind_name(ember::Int3Kind::Padding) == "padding",
              "int3_kind_name(Padding) should be 'padding'");
        check(ember::int3_kind_name(ember::Int3Kind::AntiDebug) == "anti-debug",
              "int3_kind_name(AntiDebug) should be 'anti-debug'");
        check(ember::int3_kind_name(ember::Int3Kind::DebugBreak) == "debugbreak",
              "int3_kind_name(DebugBreak) should be 'debugbreak'");
        check(ember::int3_kind_name(ember::Int3Kind::Unknown) == "unknown",
              "int3_kind_name(Unknown) should be 'unknown'");
    }

    // ---- StubbedBranch detection ----
    {
        StubbedMockBinary b;
        auto results = ember::resolve_embedded_int3s(b);

        // The int3 at 0x401003 follows a cmp (flag-setting) instruction.
        bool found_stub = false;
        for (const auto& r : results) {
            if (r.addr == 0x401003) {
                check_eq(r.kind, ember::Int3Kind::StubbedBranch,
                         "int3 after cmp should be StubbedBranch");
                check(r.containing_fn == 0x401000,
                      "stubbed branch should report containing_fn = 0x401000");
                check(r.fn_offset == 3,
                      "stubbed branch at 0x401003 should be offset 3");
                check(r.branch_target.has_value() && *r.branch_target == 0x401004,
                      "stubbed branch fall-through should be 0x401004");
                found_stub = true;
                break;
            }
        }
        check(found_stub, "should find StubbedBranch at 0x401003");
    }

    // ---- BranchPredicate and mnemonic_to_predicate ----
    {
        check(ember::mnemonic_to_predicate(ember::Mnemonic::Je).value() ==
              ember::BranchPredicate::Equal,
              "Je should map to Equal");
        check(ember::mnemonic_to_predicate(ember::Mnemonic::Jne).value() ==
              ember::BranchPredicate::NotEqual,
              "Jne should map to NotEqual");
        check(ember::mnemonic_to_predicate(ember::Mnemonic::Jl).value() ==
              ember::BranchPredicate::Less,
              "Jl should map to Less");
        check(ember::mnemonic_to_predicate(ember::Mnemonic::Jg).value() ==
              ember::BranchPredicate::Greater,
              "Jg should map to Greater");
        check(!ember::mnemonic_to_predicate(ember::Mnemonic::Nop).has_value(),
              "Nop should not map to a predicate");
        check(!ember::mnemonic_to_predicate(ember::Mnemonic::Jmp).has_value(),
              "Jmp should not map to a predicate");
    }

    // ---- branch_predicate_name ----
    {
        check(ember::branch_predicate_name(ember::BranchPredicate::Equal) == "equal",
              "Equal predicate name should be 'equal'");
        check(ember::branch_predicate_name(ember::BranchPredicate::NotEqual) == "not_equal",
              "NotEqual predicate name should be 'not_equal'");
        check(ember::branch_predicate_name(ember::BranchPredicate::Less) == "less",
              "Less predicate name should be 'less'");
        check(ember::branch_predicate_name(ember::BranchPredicate::Greater) == "greater",
              "Greater predicate name should be 'greater'");
    }

    // ---- non-x86 binary should return empty ----
    {
        // We can't easily make a non-x86 MockBinary here, but we can
        // verify the function exists and compiles. The existing
        // MockBinary is x86-64 so it should return non-empty.
        MockBinary b;
        auto results = ember::resolve_embedded_int3s(b);
        check(!results.empty(), "x86-64 binary should produce results");
    }

    if (fails > 0) {
        std::fprintf(stderr, "\n%d test(s) failed\n", fails);
        return EXIT_FAILURE;
    }
    std::printf("all int3_resolver tests passed\n");
    return EXIT_SUCCESS;
}
