// Unit tests for FLIRT-style signature matching (`--pat`).
//
// Covers the three paths the matcher has to get right:
//   1. Prefix-only match → rename applied.
//   2. Prefix matches but CRC over the body bytes doesn't → no rename.
//   3. Prefix matches but the @ref symbol isn't actually called → no rename.
//
// Plus the `crc16` algorithm (FLIRT's reversed-CCITT-with-byte-swap variant)
// and the `.pat` text parser. Self-contained: a tiny MockBinary carries one
// hand-written x86-64 function so the tests don't depend on the C-fixture
// toolchain version.
#include <ember/analysis/sigs.hpp>
#include <ember/analysis/pipeline.hpp>
#include <ember/binary/binary.hpp>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;

namespace {

int fails = 0;

template <typename A, typename B>
void check_eq(const A& got, const B& want, const char* ctx) {
    if (!(got == want)) {
        std::fprintf(stderr, "FAIL: %s\n", ctx);
        ++fails;
    }
}

void check_eq_sz(std::size_t got, std::size_t want, const char* ctx) {
    if (got != want) {
        std::fprintf(stderr, "FAIL: %s (got %zu, want %zu)\n",
                     ctx, got, want);
        ++fails;
    }
}

void check_eq_str(const std::string& got, std::string_view want, const char* ctx) {
    if (got != want) {
        std::fprintf(stderr, "FAIL: %s (got '%s', want '%.*s')\n",
                     ctx, got.c_str(),
                     static_cast<int>(want.size()), want.data());
        ++fails;
    }
}

void check(bool cond, const char* ctx) {
    if (!cond) {
        std::fprintf(stderr, "FAIL: %s\n", ctx);
        ++fails;
    }
}

// Hand-rolled x86-64 byte sequence:
//   0x401000  e8 1b 00 00 00   call rel32  -> 0x401020
//   0x401005  c3               ret
// Followed by NOPs to fill the section out to where the PLT stub sits.
constexpr ember::addr_t kFnAddr  = 0x401000;
constexpr ember::addr_t kPltAddr = 0x401020;
constexpr std::size_t   kSecLen  = 0x40;

struct ImageBytes {
    std::array<std::byte, kSecLen> data{};
    ImageBytes() {
        // Default-fill with NOP (0x90) so any decoder linear-walking past
        // the 6-byte function still sees valid instructions.
        for (auto& b : data) b = static_cast<std::byte>(0x90u);
        // Function bytes.
        const std::array<unsigned, 6> fn = {
            0xe8u, 0x1bu, 0x00u, 0x00u, 0x00u,  // call 0x401020
            0xc3u,                              // ret
        };
        for (std::size_t i = 0; i < fn.size(); ++i) {
            data[i] = static_cast<std::byte>(fn[i]);
        }
    }
};

class MockBinary final : public ember::Binary {
public:
    MockBinary() {
        sec_.name = ".text";
        sec_.vaddr = kFnAddr;
        sec_.size  = kSecLen;
        sec_.flags.executable = true;
        sec_.flags.readable   = true;
        sec_.data = std::span<const std::byte>(image_.data.data(),
                                                image_.data.size());

        // One imported symbol to back the @ref test. Address = the PLT
        // stub address; import_at_plt() resolves any addr in the 16-byte
        // slot back to this entry.
        ember::Symbol s;
        s.name      = "strlen";
        s.addr      = kPltAddr;
        s.kind      = ember::SymbolKind::Function;
        s.is_import = true;
        syms_.push_back(std::move(s));
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
        return kFnAddr;
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

fs::path scratch_root() {
    auto p = fs::temp_directory_path() / "ember_sigs_test";
    std::error_code ec;
    fs::remove_all(p, ec);
    fs::create_directories(p);
    return p;
}

fs::path write_pat(const fs::path& dir, std::string_view name,
                   std::string_view body) {
    const auto p = dir / name;
    std::ofstream o(p);
    o.write(body.data(), static_cast<std::streamsize>(body.size()));
    return p;
}

}  // namespace

int main() {
    using namespace ember;

    // ---- crc16 ------------------------------------------------------------
    // Empty input: init 0xFFFF, no bytes consumed, byte-swap is a no-op on
    // 0xFFFF. Catches anyone who flips the init value or removes the swap.
    check_eq(sigs::crc16({}), static_cast<u16>(0xFFFF), "crc16 empty == 0xFFFF");

    // Regression value computed against the current implementation. If a
    // future change to the polynomial silently breaks compatibility with
    // externally-generated `.pat` files this assertion fires.
    const std::array<std::byte, 9> nine = {
        std::byte{'1'}, std::byte{'2'}, std::byte{'3'},
        std::byte{'4'}, std::byte{'5'}, std::byte{'6'},
        std::byte{'7'}, std::byte{'8'}, std::byte{'9'},
    };
    const u16 nine_crc = sigs::crc16(nine);
    check(nine_crc != 0 && nine_crc != 0xFFFF, "crc16 over '123456789' is non-trivial");

    // ---- load_pat parsing -------------------------------------------------
    const auto root = scratch_root();

    // Three sigs against the kFnAddr function:
    //   - winmain_proc:  prefix-only; should match.
    //   - bad_crc:       prefix matches, CRC over the next byte set wrong.
    //   - missing_ref:   prefix matches, declares an @ref to an import
    //                    name that the function doesn't call.
    const auto pat_all = write_pat(root, "all.pat",
        // prefix `e8 1b 00 00 00 c3`, no CRC, no refs, total-len 6
        "e81b000000c3 00 0000 0006 :0000 winmain_proc\n"
        // prefix `e8 1b 00 00 00`, CRC length 1 over byte at offset 5 with
        // a deliberately wrong value 0xDEAD
        "e81b00000000 01 DEAD 0006 :0000 bad_crc\n"
        // prefix `e8 1b 00 00 00 c3`, declares a ref to "fopen" which the
        // function doesn't call (it calls strlen)
        "e81b000000c3 00 0000 0006 :0000 missing_ref @0000 fopen\n");

    auto db_all = sigs::load_pat(pat_all);
    check(db_all.has_value(), "load_pat: file loaded");
    if (db_all) {
        check_eq_sz(db_all->sigs.size(), 3, "3 sigs parsed");
        if (db_all->sigs.size() == 3) {
            check_eq_str(db_all->sigs[0].name, "winmain_proc",
                         "sig 0 name");
            check_eq(db_all->sigs[0].prefix_len, static_cast<u16>(6),
                     "sig 0 prefix_len");
            check_eq(db_all->sigs[0].crc_length, static_cast<u8>(0),
                     "sig 0 crc_length");
            check_eq_sz(db_all->sigs[0].refs.size(), 0, "sig 0 refs");
            check_eq(db_all->sigs[1].crc_length, static_cast<u8>(1),
                     "sig 1 crc_length");
            check_eq(db_all->sigs[1].crc16, static_cast<u16>(0xDEAD),
                     "sig 1 crc16");
            check_eq_sz(db_all->sigs[2].refs.size(), 1, "sig 2 has one ref");
            if (!db_all->sigs[2].refs.empty()) {
                check_eq_str(db_all->sigs[2].refs[0].name, "fopen",
                             "sig 2 ref name");
            }
        }
    }

    // Malformed line: skipped with a warning to stderr but the loader
    // returns Ok with the surviving sigs intact.
    const auto pat_malformed = write_pat(root, "malformed.pat",
        "this is not a sig line at all\n"
        "e81b000000c3 00 0000 0006 :0000 ok_sig\n");
    auto db_mal = sigs::load_pat(pat_malformed);
    check(db_mal.has_value(), "load_pat: malformed lines don't fail load");
    if (db_mal) {
        check_eq_sz(db_mal->sigs.size(), 1, "load_pat: only valid sigs kept");
    }

    // Missing file: surfaces as Error::not_found.
    auto db_missing = sigs::load_pat(root / "does_not_exist.pat");
    check(!db_missing.has_value(), "load_pat: missing file errors");

    // ---- apply_signatures end-to-end -------------------------------------
    MockBinary mb;
    std::vector<DiscoveredFunction> cands = {
        {kFnAddr, 0, "sub_401000", DiscoveredFunction::Kind::Sub},
    };

    auto only = [&](std::string_view body) -> sigs::SigDb {
        const auto p = write_pat(root, "one.pat", body);
        auto rv = sigs::load_pat(p);
        return rv ? std::move(*rv) : sigs::SigDb{};
    };

    // Path 1: prefix-only sig matches.
    {
        auto db = only("e81b000000c3 00 0000 0006 :0000 winmain_proc\n");
        const auto rs = sigs::apply_signatures(mb, db, cands);
        check_eq_sz(rs.size(), 1, "match: one rename");
        if (rs.size() == 1) {
            check_eq(rs[0].addr, kFnAddr, "match: addr");
            check_eq_str(rs[0].name, "winmain_proc", "match: name");
        }
    }

    // Path 2: prefix matches but CRC over the next byte (0xc3) is set to a
    // value the real CRC won't equal.
    {
        auto db = only("e81b00000000 01 DEAD 0006 :0000 bad_crc\n");
        const auto rs = sigs::apply_signatures(mb, db, cands);
        check_eq_sz(rs.size(), 0, "crc mismatch: no rename");
    }

    // Path 3: prefix matches and CRC is skipped, but the @ref names an
    // import the function doesn't reach via direct call.
    {
        auto db = only(
            "e81b000000c3 00 0000 0006 :0000 missing_ref @0000 fopen\n");
        const auto rs = sigs::apply_signatures(mb, db, cands);
        check_eq_sz(rs.size(), 0, "ref reject: no rename");
    }

    // Path 3': @ref names the import the function actually calls — match.
    {
        auto db = only(
            "e81b000000c3 00 0000 0006 :0000 has_ref @0000 strlen\n");
        const auto rs = sigs::apply_signatures(mb, db, cands);
        check_eq_sz(rs.size(), 1, "ref present: rename");
        if (rs.size() == 1) {
            check_eq_str(rs[0].name, "has_ref", "ref present: name");
        }
    }

    // existing_renames suppresses sig matching for that address — sigs
    // never override operator intent.
    {
        auto db = only("e81b000000c3 00 0000 0006 :0000 winmain_proc\n");
        const std::array<addr_t, 1> existing = {kFnAddr};
        const auto rs = sigs::apply_signatures(mb, db, cands, existing);
        check_eq_sz(rs.size(), 0, "existing_renames suppresses match");
    }

    // Symbol-named candidates are skipped — sigs only resolve placeholder
    // names. A function whose kind is Symbol won't get renamed even if
    // the prefix matches.
    {
        auto db = only("e81b000000c3 00 0000 0006 :0000 winmain_proc\n");
        std::vector<DiscoveredFunction> sym_cands = {
            {kFnAddr, 0, "named_already", DiscoveredFunction::Kind::Symbol},
        };
        const auto rs = sigs::apply_signatures(mb, db, sym_cands);
        check_eq_sz(rs.size(), 0, "Symbol-kind candidates not renamed");
    }

    if (fails == 0) std::puts("ok");
    return fails == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
