#include "patches.hpp"

#include <cctype>
#include <charconv>
#include <cstddef>
#include <cstdlib>
#include <format>
#include <fstream>
#include <print>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <ember/binary/binary.hpp>
#include <ember/common/error.hpp>

#include "args.hpp"
#include "cli_error.hpp"

namespace ember::cli {

namespace {

struct Patch {
    addr_t                 vaddr = 0;
    std::vector<std::byte> bytes;
};

// Parse the patches file. One patch per line, `<vaddr_hex> <bytes_hex>`.
// `vaddr_hex` must be 0x-prefixed for clarity; `bytes_hex` is a contiguous
// hex string (whitespace tolerated, no embedded 0x). `#` comments and
// blank lines are skipped.
[[nodiscard]] Result<std::vector<Patch>>
parse_patches_file(const std::string& path) {
    std::ifstream f(path);
    if (!f) return std::unexpected(
        Error::io(std::format("cannot open patches file '{}'", path)));
    std::vector<Patch> out;
    std::string line;
    std::size_t line_no = 0;
    while (std::getline(f, line)) {
        ++line_no;
        std::size_t p = 0;
        while (p < line.size() && std::isspace(static_cast<unsigned char>(line[p]))) ++p;
        if (p == line.size() || line[p] == '#') continue;

        // Address token.
        std::size_t addr_end = p;
        while (addr_end < line.size() &&
               !std::isspace(static_cast<unsigned char>(line[addr_end]))) ++addr_end;
        std::string_view addr_tok(line.data() + p, addr_end - p);
        if (!addr_tok.starts_with("0x") && !addr_tok.starts_with("0X")) {
            return std::unexpected(Error::invalid_format(std::format(
                "patches '{}' line {}: vaddr must be 0x-prefixed", path, line_no)));
        }
        addr_tok.remove_prefix(2);
        u64 va = 0;
        auto ar = std::from_chars(addr_tok.data(), addr_tok.data() + addr_tok.size(), va, 16);
        if (ar.ec != std::errc{} || ar.ptr != addr_tok.data() + addr_tok.size()) {
            return std::unexpected(Error::invalid_format(std::format(
                "patches '{}' line {}: bad hex vaddr", path, line_no)));
        }

        // Bytes: pairs of hex digits, whitespace ignored.
        std::string hex;
        for (std::size_t i = addr_end; i < line.size(); ++i) {
            if (!std::isspace(static_cast<unsigned char>(line[i]))) hex.push_back(line[i]);
        }
        if (hex.empty()) {
            return std::unexpected(Error::invalid_format(std::format(
                "patches '{}' line {}: missing bytes", path, line_no)));
        }
        if (hex.size() % 2 != 0) {
            return std::unexpected(Error::invalid_format(std::format(
                "patches '{}' line {}: odd hex digit count", path, line_no)));
        }
        std::vector<std::byte> bytes;
        bytes.reserve(hex.size() / 2);
        for (std::size_t i = 0; i < hex.size(); i += 2) {
            unsigned b = 0;
            auto br = std::from_chars(hex.data() + i, hex.data() + i + 2, b, 16);
            if (br.ec != std::errc{} || br.ptr != hex.data() + i + 2) {
                return std::unexpected(Error::invalid_format(std::format(
                    "patches '{}' line {}: bad hex byte", path, line_no)));
            }
            bytes.push_back(static_cast<std::byte>(b));
        }
        out.push_back({static_cast<addr_t>(va), std::move(bytes)});
    }
    return out;
}

}  // namespace

int run_apply_patches(const Args& args) {
    if (args.output_path.empty()) {
        std::println(stderr, "ember: --apply-patches requires -o/--output PATH");
        return EXIT_FAILURE;
    }
    auto patches_r = parse_patches_file(args.apply_patches);
    if (!patches_r) {
        std::println(stderr, "ember: {}", patches_r.error().message);
        return EXIT_FAILURE;
    }
    auto bin = load_binary(args.binary);
    if (!bin) return report(bin.error());
    const auto sections = (**bin).sections();

    // Slurp the original binary file.
    std::ifstream src(args.binary, std::ios::binary | std::ios::ate);
    if (!src) {
        std::println(stderr, "ember: cannot read '{}'", args.binary);
        return EXIT_FAILURE;
    }
    const auto sz = src.tellg();
    src.seekg(0, std::ios::beg);
    std::vector<char> buf(static_cast<std::size_t>(sz));
    src.read(buf.data(), sz);

    // Apply each patch.
    std::size_t applied = 0;
    for (const auto& p : *patches_r) {
        const Section* host = nullptr;
        for (const auto& s : sections) {
            if (p.vaddr >= s.vaddr && p.vaddr < s.vaddr + s.size) {
                host = &s; break;
            }
        }
        if (!host) {
            std::println(stderr, "ember: patch @ 0x{:x}: no containing section", p.vaddr);
            return EXIT_FAILURE;
        }
        const auto file_off = host->file_offset + (p.vaddr - host->vaddr);
        if (file_off + p.bytes.size() > buf.size()) {
            std::println(stderr, "ember: patch @ 0x{:x}: extends past EOF", p.vaddr);
            return EXIT_FAILURE;
        }
        for (std::size_t i = 0; i < p.bytes.size(); ++i) {
            buf[file_off + i] = static_cast<char>(p.bytes[i]);
        }
        ++applied;
    }

    std::ofstream dst(args.output_path, std::ios::binary | std::ios::trunc);
    if (!dst) {
        std::println(stderr, "ember: cannot write '{}'", args.output_path);
        return EXIT_FAILURE;
    }
    dst.write(buf.data(), static_cast<std::streamsize>(buf.size()));
    if (!dst) {
        std::println(stderr, "ember: write failed for '{}'", args.output_path);
        return EXIT_FAILURE;
    }
    std::println(stderr, "ember: applied {} patch(es) -> {}", applied, args.output_path);
    return EXIT_SUCCESS;
}

}  // namespace ember::cli
