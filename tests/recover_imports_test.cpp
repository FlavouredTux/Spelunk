#include <ember/analysis/recover_imports.hpp>

#include <array>
#include <cstdio>
#include <span>
#include <vector>

namespace {

int fails = 0;

void check(bool condition, const char* message) {
    if (condition) return;
    std::fprintf(stderr, "FAIL: %s\n", message);
    ++fails;
}

class SlotBinary final : public ember::Binary {
public:
    explicit SlotBinary(std::span<const ember::addr_t> targets) {
        bytes_.resize(targets.size() * sizeof(ember::u64));
        for (std::size_t i = 0; i < targets.size(); ++i) {
            const ember::u64 value = targets[i];
            for (unsigned b = 0; b < 8; ++b) {
                bytes_[i * 8 + b] = static_cast<std::byte>((value >> (b * 8)) & 0xff);
            }
        }
        section_.name = ".data";
        section_.vaddr = 0x1000;
        section_.size = bytes_.size();
        section_.flags.readable = true;
        section_.flags.writable = true;
        section_.data = bytes_;
    }

    ember::Format format() const noexcept override { return ember::Format::RawRegions; }
    ember::Arch arch() const noexcept override { return ember::Arch::X86_64; }
    ember::Endian endian() const noexcept override { return ember::Endian::Little; }
    ember::addr_t entry_point() const noexcept override { return 0; }
    std::span<const ember::Section> sections() const noexcept override {
        return std::span<const ember::Section>(&section_, 1);
    }
    std::span<const ember::Symbol> symbols() const noexcept override { return {}; }
    std::span<const std::byte> image() const noexcept override { return bytes_; }

protected:
    std::vector<ember::Symbol>& mutable_symbols() noexcept override { return symbols_; }

private:
    std::vector<std::byte> bytes_;
    ember::Section section_;
    std::vector<ember::Symbol> symbols_;
};

ember::ReferenceExports ref(std::string name,
                            std::initializer_list<ember::u32> rvas) {
    ember::ReferenceExports out;
    out.module = std::move(name);
    unsigned n = 0;
    for (ember::u32 rva : rvas) out.by_rva.emplace(rva, "fn" + std::to_string(++n));
    return out;
}

void test_close_modules_are_peeled_apart() {
    constexpr ember::addr_t a = 0x00007ff100000000ull;
    constexpr ember::addr_t b = 0x00007ff100800000ull;  // only 8 MiB away
    const std::array targets{a + 0x1000, a + 0x2000, b + 0x3000, b + 0x4000};
    SlotBinary dump(targets);
    const std::array refs{ref("a.dll", {0x1000, 0x2000}),
                          ref("b.dll", {0x3000, 0x4000})};
    const auto result = ember::recover_imports(dump, refs);
    check(result.imports.size() == 4, "close modules retain all imports");
    check(result.clusters.size() == 2, "close modules produce two solved clusters");
}

void test_weak_and_ambiguous_matches_stay_unresolved() {
    constexpr ember::addr_t base = 0x00007ff200000000ull;
    {
        const std::array targets{base + 0x1000};
        SlotBinary dump(targets);
        const std::array refs{ref("one.dll", {0x1000})};
        check(ember::recover_imports(dump, refs).imports.empty(),
              "singleton match is not accepted");
    }
    {
        const std::array targets{base + 0x1000, base + 0x2000};
        SlotBinary dump(targets);
        const std::array refs{ref("one.dll", {0x1000, 0x2000}),
                              ref("two.dll", {0x1000, 0x2000})};
        check(ember::recover_imports(dump, refs).imports.empty(),
              "equally compatible modules stay ambiguous");
    }
}

}  // namespace

int main() {
    test_close_modules_are_peeled_apart();
    test_weak_and_ambiguous_matches_stay_unresolved();
    return fails == 0 ? 0 : 1;
}
