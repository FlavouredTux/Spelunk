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

}  // namespace

int main() {
    PpcArityBinary binary;
    check_eq(ember::infer_arity(binary, 0x80001000), 1,
             "PPC direct live-in r3 read implies one parameter");
    check_eq(ember::infer_arity(binary, 0x80001020), 2,
             "Metrowerks save helper preserves incoming r3/r4 parameters");
    check_eq(ember::infer_arity(binary, 0x80001040), 0,
             "implicit PPC return-register read is not a parameter");
    return failures == 0 ? 0 : 1;
}
