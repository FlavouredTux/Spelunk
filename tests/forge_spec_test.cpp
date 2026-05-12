// Unit tests for the forge-spec inferencer
// (ember/analysis/forge_spec.hpp).
//
// Self-contained: a MockBinary holds hand-encoded x86-64 bytes for a
// shape equivalent to `if (p->magic == 0x1234) goto target;` so the
// extractor can be exercised without depending on a system C compiler.

#include <ember/analysis/forge_spec.hpp>
#include <ember/binary/binary.hpp>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <span>
#include <string>
#include <vector>

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
        std::fprintf(stderr, "FAIL: %s\n", ctx);
        ++fails;
    }
}

// Single-block fixture: one fn whose entry compares *(u32*)(rdi+0) to 0x1234
// and conditionally branches to a "winning" block.
//
// 0x401000: 31 c0                 xor eax, eax
// 0x401002: 81 3f 34 12 00 00     cmp dword [rdi], 0x1234
// 0x401008: 74 06                 je  0x401010
// 0x40100a: c3                    ret
// 0x40100b: 0f 1f 44 00 00        nop  ; alignment filler
// 0x401010: 8b 47 04              mov eax, dword [rdi+4]
// 0x401013: 03 47 08              add eax, dword [rdi+8]
// 0x401016: c3                    ret
constexpr ember::addr_t kBase = 0x401000;
constexpr std::size_t   kLen  = 0x40;

struct ImageBytes {
    std::array<std::byte, kLen> data{};
    ImageBytes() {
        for (auto& b : data) b = static_cast<std::byte>(0x90u);

        const std::array<unsigned char, 0x17> code = {
            0x31, 0xC0,                          // xor eax, eax
            0x81, 0x3F, 0x34, 0x12, 0x00, 0x00,  // cmp [rdi], 0x1234
            0x74, 0x06,                          // je +6
            0xC3,                                // ret
            0x0F, 0x1F, 0x44, 0x00, 0x00,        // nop
            0x8B, 0x47, 0x04,                    // mov eax, [rdi+4]
            0x03, 0x47, 0x08,                    // add eax, [rdi+8]
            0xC3,                                // ret
        };
        for (std::size_t i = 0; i < code.size(); ++i) {
            data[i] = static_cast<std::byte>(code[i]);
        }
    }
};

class MockBinary final : public ember::Binary {
public:
    MockBinary() {
        sec_.name  = ".text";
        sec_.vaddr = kBase;
        sec_.size  = kLen;
        sec_.flags.executable = true;
        sec_.flags.readable   = true;
        sec_.data = std::span<const std::byte>(image_.data.data(),
                                                image_.data.size());

        ember::Symbol fn;
        fn.name      = "inspect_packet";
        fn.addr      = 0x401000;
        fn.size      = 0x17;
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
    ImageBytes                  image_{};
    ember::Section              sec_{};
    std::vector<ember::Symbol>  syms_{};
};

void test_basic_field_constraint() {
    MockBinary b;
    auto spec = ember::infer_forge_spec(b, 0x401000, 0x401010);
    check(spec.has_value(), "infer_forge_spec returns success");
    if (!spec) return;

    check(spec->reachable, "reach the target block");
    check_eq(spec->call_chain.size(), std::size_t{1}, "call chain length");
    if (!spec->call_chain.empty()) {
        check_eq(spec->call_chain[0], ember::addr_t{0x401000}, "chain head");
    }

    check_eq(spec->branches.size(), std::size_t{1}, "one branch on path");
    if (!spec->branches.empty()) {
        const auto& d = spec->branches[0];
        check(d.went_taken,                    "branch went taken");
        check_eq(d.taken_target, ember::addr_t{0x401010}, "taken target");
    }

    check_eq(spec->fields.size(), std::size_t{1}, "one field requirement");
    if (!spec->fields.empty()) {
        const auto& f = spec->fields[0];
        check_eq(f.param_index, 0,            "param is arg0 (rdi)");
        check_eq(f.offset_chain.size(), std::size_t{1}, "offset chain has one hop");
        if (!f.offset_chain.empty()) {
            check_eq(f.offset_chain[0], ember::i64{0}, "offset is 0");
        }
        check_eq(static_cast<int>(f.cmp_op),
                 static_cast<int>(ember::IrOp::CmpEq), "cmp op is ==");
        check_eq(static_cast<int>(f.rhs.kind),
                 static_cast<int>(ember::ForgeExpr::Kind::Imm), "rhs is imm");
        check_eq(f.rhs.imm, ember::i64{0x1234}, "rhs imm value");
    }
}

void test_unreachable_target() {
    MockBinary b;
    // 0x401005 is mid-instruction; not a function entry. Expect a clean
    // "out of bounds"-style error rather than a crash.
    auto spec = ember::infer_forge_spec(b, 0x401000, 0x4FFFFF);
    // 0x4FFFFF is outside any function - expect an Error.
    check(!spec.has_value(), "out-of-range target rejected");
}

void test_target_in_entry_block() {
    MockBinary b;
    // Targeting the entry block itself is reachable with no constraints.
    auto spec = ember::infer_forge_spec(b, 0x401000, 0x401002);
    check(spec.has_value(), "entry-block target succeeds");
    if (!spec) return;
    check(spec->reachable,                   "reachable");
    check_eq(spec->branches.size(), std::size_t{0},
             "no branches required to reach entry block");
    check_eq(spec->fields.size(), std::size_t{0},
             "no field requirements");
}

void test_format_round_trips() {
    MockBinary b;
    auto spec = ember::infer_forge_spec(b, 0x401000, 0x401010);
    check(spec.has_value(), "spec built for format check");
    if (!spec) return;

    const std::string text = ember::format_forge_spec(*spec);
    check(text.find("0x1234") != std::string::npos,
          "text mentions the magic constant");
    check(text.find("arg0")   != std::string::npos,
          "text mentions arg0");

    const std::string json = ember::format_forge_spec_json(*spec);
    check(json.find("\"reachable\":true") != std::string::npos,
          "json reports reachable=true");
    check(json.find("\"fields\":")        != std::string::npos,
          "json has fields key");
    check(json.find("\"branches\":")      != std::string::npos,
          "json has branches key");
}

}  // namespace

int main() {
    test_basic_field_constraint();
    test_unreachable_target();
    test_target_in_entry_block();
    test_format_round_trips();

    if (fails != 0) {
        std::fprintf(stderr, "forge_spec_test: %d failure(s)\n", fails);
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
