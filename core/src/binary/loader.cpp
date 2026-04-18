#include <ember/binary/binary.hpp>

#include <cstddef>
#include <format>
#include <fstream>
#include <system_error>
#include <utility>
#include <vector>

#include <ember/binary/elf.hpp>
#include <ember/binary/macho.hpp>
#include <ember/common/bytes.hpp>

namespace ember {

namespace {

[[nodiscard]] Result<std::vector<std::byte>>
read_file(const std::filesystem::path& path) {
    std::error_code ec;
    const auto size = std::filesystem::file_size(path, ec);
    if (ec) {
        return std::unexpected(Error::io(std::format(
            "cannot stat '{}': {}", path.string(), ec.message())));
    }

    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return std::unexpected(Error::io(std::format(
            "cannot open '{}'", path.string())));
    }

    std::vector<std::byte> buffer(static_cast<std::size_t>(size));
    if (size > 0) {
        file.read(reinterpret_cast<char*>(buffer.data()),
                  static_cast<std::streamsize>(size));
        if (!file) {
            return std::unexpected(Error::io(std::format(
                "short read on '{}'", path.string())));
        }
    }
    return buffer;
}

[[nodiscard]] bool looks_like_elf(std::span<const std::byte> b) noexcept {
    return b.size() >= 4
        && b[0] == std::byte{0x7f}
        && b[1] == std::byte{'E'}
        && b[2] == std::byte{'L'}
        && b[3] == std::byte{'F'};
}

[[nodiscard]] bool looks_like_macho_64(std::span<const std::byte> b) noexcept {
    // Little-endian 64-bit Mach-O magic: 0xFEEDFACF. We don't accept 32-bit
    // (FEEDFACE) or byte-swapped (CIGAM) — only LE 64-bit slices.
    return b.size() >= 4
        && b[0] == std::byte{0xCF}
        && b[1] == std::byte{0xFA}
        && b[2] == std::byte{0xED}
        && b[3] == std::byte{0xFE};
}

// CAFEBABE (32-bit fat) or CAFEBABF (64-bit fat) — the wrapper around a
// universal binary. Big-endian on disk regardless of host.
[[nodiscard]] bool looks_like_fat(std::span<const std::byte> b) noexcept {
    if (b.size() < 4) return false;
    return b[0] == std::byte{0xCA} && b[1] == std::byte{0xFE}
        && b[2] == std::byte{0xBA}
        && (b[3] == std::byte{0xBE} || b[3] == std::byte{0xBF});
}

[[nodiscard]] u32 read_be32(const std::byte* p) noexcept {
    return (static_cast<u32>(p[0]) << 24) |
           (static_cast<u32>(p[1]) << 16) |
           (static_cast<u32>(p[2]) << 8)  |
            static_cast<u32>(p[3]);
}

[[nodiscard]] u64 read_be64(const std::byte* p) noexcept {
    return (static_cast<u64>(read_be32(p)) << 32) | read_be32(p + 4);
}

// CPU types from <mach/machine.h>.
constexpr u32 CPU_TYPE_X86_64 = 0x01000007u;
constexpr u32 CPU_TYPE_ARM64  = 0x0100000Cu;

// Slice a fat wrapper down to a single architecture's bytes. We prefer
// x86_64 since that's what our decoder handles; if there's no x86_64
// slice we pick arm64 so at least symbols/sections still load (the
// decoder will fail on instructions but the binary is browsable).
[[nodiscard]] Result<std::vector<std::byte>>
slice_fat(std::vector<std::byte>& buf) {
    const bool is_64 = buf[3] == std::byte{0xBF};
    const std::byte* const p = buf.data();
    const u32 nfat = read_be32(p + 4);
    const std::size_t arch_size = is_64 ? 32u : 20u;
    const std::size_t hdr_size  = 8 + static_cast<std::size_t>(nfat) * arch_size;
    if (hdr_size > buf.size()) {
        return std::unexpected(Error::truncated(std::format(
            "fat: header claims {} arch entries, file only {} bytes", nfat, buf.size())));
    }

    struct Slice { u32 cputype; u64 offset; u64 size; };
    std::vector<Slice> slices;
    slices.reserve(nfat);
    for (u32 i = 0; i < nfat; ++i) {
        const std::byte* const a = p + 8 + i * arch_size;
        const u32 cputype = read_be32(a + 0);
        u64 offset, size;
        if (is_64) {
            offset = read_be64(a + 8);
            size   = read_be64(a + 16);
        } else {
            offset = read_be32(a + 8);
            size   = read_be32(a + 12);
        }
        slices.push_back({cputype, offset, size});
    }

    const Slice* pick = nullptr;
    for (const auto& s : slices) if (s.cputype == CPU_TYPE_X86_64) { pick = &s; break; }
    if (!pick) for (const auto& s : slices) if (s.cputype == CPU_TYPE_ARM64)  { pick = &s; break; }
    if (!pick && !slices.empty()) pick = &slices[0];
    if (!pick) {
        return std::unexpected(Error::invalid_format("fat: no arch slices"));
    }
    if (pick->offset + pick->size > buf.size()) {
        return std::unexpected(Error::truncated(std::format(
            "fat: arch slice [{:#x}, {:#x}) extends past {:#x}-byte file",
            pick->offset, pick->offset + pick->size, buf.size())));
    }
    std::vector<std::byte> out(buf.begin() + static_cast<std::ptrdiff_t>(pick->offset),
                               buf.begin() + static_cast<std::ptrdiff_t>(pick->offset + pick->size));
    return out;
}

}  // namespace

Result<std::unique_ptr<Binary>>
load_binary(const std::filesystem::path& path) {
    auto buffer = read_file(path);
    if (!buffer) return std::unexpected(std::move(buffer).error());

    // Unwrap a universal binary down to one architecture's bytes before
    // anything else. After this, *buffer looks like a plain Mach-O slice.
    if (looks_like_fat(*buffer)) {
        auto sliced = slice_fat(*buffer);
        if (!sliced) return std::unexpected(std::move(sliced).error());
        *buffer = std::move(*sliced);
    }

    if (looks_like_elf(*buffer)) {
        auto elf = ElfBinary::load_from_buffer(std::move(*buffer));
        if (!elf) return std::unexpected(std::move(elf).error());
        return std::unique_ptr<Binary>(std::move(*elf));
    }
    if (looks_like_macho_64(*buffer)) {
        auto m = MachOBinary::load_from_buffer(std::move(*buffer));
        if (!m) return std::unexpected(std::move(m).error());
        return std::unique_ptr<Binary>(std::move(*m));
    }

    return std::unexpected(Error::unsupported(
        "unrecognized binary format (only ELF and Mach-O 64-bit supported)"));
}

}  // namespace ember
