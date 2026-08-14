#include <ember/analysis/arity.hpp>
#include <ember/binary/binary.hpp>

#include <array>
#include <cstdio>
#include <span>
#include <vector>

namespace {

class PpcArityBinary final : public ember::Binary {
public:
    PpcArityBinary() {
        // one_arg: cmpwi r3,0; beq return; li r3,1; blr
        put(0x00, 0x2c030000);
        put(0x04, 0x41820008);
        put(0x08, 0x38600001);
        put(0x0c, 0x4e800020);

        // two_args_after_save: bl _savegpr_27; stw r3,0(r4); blr
        put(0x20, 0x480000e1);
        put(0x24, 0x90640000);
        put(0x28, 0x4e800020);

        // no_args: li r3,42; blr.  The implicit r3 read attached to Return
        // must not manufacture a parameter.
        put(0x40, 0x3860002a);
        put(0x44, 0x4e800020);

        // mixed_args: the first-use order deliberately alternates the two
        // independent PPC argument banks: f1, r3, f2, r4.
        put(0x60, 0xd02b0000);  // stfs f1,0(r11)
        put(0x64, 0x906b0000);  // stw  r3,0(r11)
        put(0x68, 0xd04b0004);  // stfs f2,4(r11)
        put(0x6c, 0x908b0008);  // stw  r4,8(r11)
        put(0x70, 0x4e800020);  // blr

        // call_then_f1: f1 after an ordinary call is a clobbered return lane,
        // not a live-in floating argument.
        put(0x80, 0x4bffffc1);  // bl no_args
        put(0x84, 0xd02b0000);  // stfs f1,0(r11)
        put(0x88, 0x4e800020);  // blr

        // pointer_callee: r3 is used as a memory base.
        put(0xa0, 0x80630000);  // lwz r3,0(r3)
        put(0xa4, 0x4e800020);  // blr

        // forwarded_pointer: source argument r4 becomes callee argument r3.
        put(0xc0, 0x7c832378);  // mr r3,r4
        put(0xc4, 0x4bffffdd);  // bl pointer_callee
        put(0xc8, 0x4e800020);  // blr

        // paired_pointer: Wii paired-single load uses r3 as its address.
        put(0xe0, 0xe3e30000);  // psq_l f31,0(r3),0,0
        put(0xe4, 0x4e800020);  // blr

        // Compiler helper target used by the first call above.
        put(0x100, 0x4e800020);

        section_.name = ".text";
        section_.vaddr = kBase;
        section_.size = text_.size();
        section_.flags.readable = true;
        section_.flags.executable = true;
        section_.flags.allocated = true;
        section_.data = text_;

        add_symbol("one_arg", kBase + 0x00, 0x10);
        add_symbol("two_args_after_save", kBase + 0x20, 0x0c);
        add_symbol("no_args", kBase + 0x40, 0x08);
        add_symbol("mixed_args", kBase + 0x60, 0x14);
        add_symbol("call_then_f1", kBase + 0x80, 0x0c);
        add_symbol("pointer_callee", kBase + 0xa0, 0x08);
        add_symbol("forwarded_pointer", kBase + 0xc0, 0x0c);
        add_symbol("paired_pointer", kBase + 0xe0, 0x08);
        add_symbol("_savegpr_27", kBase + 0x100, 0x04);
    }

    [[nodiscard]] ember::Format format() const noexcept override {
        return ember::Format::Dol;
    }
    [[nodiscard]] ember::Arch arch() const noexcept override {
        return ember::Arch::Ppc32;
    }
    [[nodiscard]] ember::Endian endian() const noexcept override {
        return ember::Endian::Big;
    }
    [[nodiscard]] ember::addr_t entry_point() const noexcept override {
        return kBase;
    }
    [[nodiscard]] std::span<const ember::Section> sections() const noexcept override {
        return std::span<const ember::Section>(&section_, 1);
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
    static constexpr ember::addr_t kBase = 0x80001000;

    void put(std::size_t off, ember::u32 word) {
        text_[off + 0] = static_cast<std::byte>(word >> 24);
        text_[off + 1] = static_cast<std::byte>(word >> 16);
        text_[off + 2] = static_cast<std::byte>(word >> 8);
        text_[off + 3] = static_cast<std::byte>(word);
    }

    void add_symbol(const char* name, ember::addr_t addr, ember::u64 size) {
        ember::Symbol symbol;
        symbol.name = name;
        symbol.addr = addr;
        symbol.size = size;
        symbol.kind = ember::SymbolKind::Function;
        symbols_.push_back(std::move(symbol));
    }

    std::array<std::byte, 0x120> text_{};
    ember::Section section_{};
    std::vector<ember::Symbol> symbols_;
};

int failures = 0;

void check_eq(ember::u8 got, ember::u8 expected, const char* message) {
    if (got == expected) return;
    std::fprintf(stderr, "FAIL: %s (got %u, expected %u)\n",
                 message, static_cast<unsigned>(got),
                 static_cast<unsigned>(expected));
    ++failures;
}

void check_reg(const std::vector<ember::InferredArgument>& args,
               std::size_t index, ember::Reg expected, const char* message) {
    if (index < args.size() && args[index].reg == expected) return;
    std::fprintf(stderr, "FAIL: %s\n", message);
    ++failures;
}

void check_pointer(const std::vector<ember::InferredArgument>& args,
                   std::size_t index, const char* message) {
    if (index < args.size() && args[index].pointer_like) return;
    std::fprintf(stderr, "FAIL: %s\n", message);
    ++failures;
}

}  // namespace

int main() {
    PpcArityBinary binary;
    check_eq(ember::infer_arity(binary, 0x80001000), 1,
             "PPC direct live-in r3 read implies one parameter");
    check_eq(ember::infer_arity(binary, 0x80001020), 2,
             "Metrowerks save helper preserves incoming r3/r4 parameters");
    check_eq(ember::infer_arity(binary, 0x80001040), 0,
             "implicit PPC return-register read is not a parameter");
    const auto mixed = ember::infer_arguments(binary, 0x80001060);
    check_eq(static_cast<ember::u8>(mixed.size()), 4,
             "mixed PPC signature counts both register banks");
    check_reg(mixed, 0, ember::Reg::PpcF1, "mixed arg 1 is f1");
    check_reg(mixed, 1, ember::Reg::PpcR3, "mixed arg 2 is r3");
    check_reg(mixed, 2, ember::Reg::PpcF2, "mixed arg 3 is f2");
    check_reg(mixed, 3, ember::Reg::PpcR4, "mixed arg 4 is r4");
    check_eq(ember::infer_arity(binary, 0x80001080), 0,
             "post-call f1 clobber is not a live-in argument");
    const auto pointer = ember::infer_arguments(binary, 0x800010a0);
    check_eq(static_cast<ember::u8>(pointer.size()), 1,
             "PPC memory-base parameter is recovered");
    check_pointer(pointer, 0, "direct PPC memory-base parameter is pointer-like");
    const auto forwarded = ember::infer_arguments(binary, 0x800010c0);
    check_eq(static_cast<ember::u8>(forwarded.size()), 2,
             "forwarded PPC second parameter preserves the ABI prefix");
    check_pointer(forwarded, 1,
                  "pointer evidence follows a PPC parameter through one direct call");
    const auto paired = ember::infer_arguments(binary, 0x800010e0);
    check_eq(static_cast<ember::u8>(paired.size()), 1,
             "paired-single PPC address parameter is recovered");
    check_pointer(paired, 0,
                  "paired-single PPC memory address is pointer-like");
    return failures == 0 ? 0 : 1;
}
