#include <spelunk/common/diagnostic.hpp>
#include <cstddef>
#include <cstdio>
#include <expected>
#include <filesystem>
#include <format>
#include <fstream>
#include <ios>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <spelunk/binary/binary.hpp>
#include <spelunk/binary/dol.hpp>
#include <spelunk/binary/dwarf.hpp>
#include <spelunk/binary/elf.hpp>
#include <spelunk/binary/macho.hpp>
#include <spelunk/binary/minidump.hpp>
#include <spelunk/binary/pe.hpp>
#include <spelunk/binary/rel.hpp>
#include <spelunk/common/bytes.hpp>
#include <spelunk/common/error.hpp>
#include <spelunk/common/types.hpp>
#include <spelunk/extension/loader_registry.hpp>

namespace spelunk {

namespace {

void attach_embedded_dwarf(Binary& binary) {
    Annotations types;
    for (auto& [address, function] : parse_dwarf_functions(binary, &types)) {
        binary.add_inferred_function_name(address, function.name);
        binary.add_debug_signature(address, function.signature);
    }
    binary.add_debug_types(std::move(types));
}

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
    // (FEEDFACE) or byte-swapped (CIGAM) - only LE 64-bit slices.
    return b.size() >= 4
        && b[0] == std::byte{0xCF}
        && b[1] == std::byte{0xFA}
        && b[2] == std::byte{0xED}
        && b[3] == std::byte{0xFE};
}

// MS minidump signature: ASCII "MDMP" at offset 0. The header version
// follow-up is checked by MinidumpBinary::parse(); the magic alone is
// distinctive enough to dispatch on.
[[nodiscard]] bool looks_like_minidump(std::span<const std::byte> b) noexcept {
    return b.size() >= 4
        && b[0] == std::byte{'M'}
        && b[1] == std::byte{'D'}
        && b[2] == std::byte{'M'}
        && b[3] == std::byte{'P'};
}

// PE starts with an MZ DOS stub whose `e_lfanew` field at offset 0x3C
// points at the real NT header ("PE\0\0"). Checking both hops avoids
// mis-firing on non-PE files that happen to start with the "MZ" magic
// (old DOS .COM/.EXE stubs, some batch files with MZ banners).
[[nodiscard]] bool looks_like_pe(std::span<const std::byte> b) noexcept {
    if (b.size() < 0x40) return false;
    if (b[0] != std::byte{'M'} || b[1] != std::byte{'Z'}) return false;
    const u32 e_lfanew = read_le_at<u32>(b.data() + 0x3C);
    if (e_lfanew + 4 > b.size()) return false;
    return b[e_lfanew + 0] == std::byte{'P'}
        && b[e_lfanew + 1] == std::byte{'E'}
        && b[e_lfanew + 2] == std::byte{0}
        && b[e_lfanew + 3] == std::byte{0};
}

// CAFEBABE (32-bit fat) or CAFEBABF (64-bit fat) - the wrapper around a
// universal binary. Big-endian on disk regardless of host.
[[nodiscard]] bool looks_like_fat(std::span<const std::byte> b) noexcept {
    if (b.size() < 4) return false;
    return b[0] == std::byte{0xCA} && b[1] == std::byte{0xFE}
        && b[2] == std::byte{0xBA}
        && (b[3] == std::byte{0xBE} || b[3] == std::byte{0xBF});
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
    const ByteReader r(buf);
    const bool is_64 = buf[3] == std::byte{0xBF};
    const std::size_t arch_size = is_64 ? 32u : 20u;

    auto nfat_r = r.read_be<u32>(4);
    if (!nfat_r) return std::unexpected(std::move(nfat_r).error());
    const u32 nfat = *nfat_r;

    // Reject nfat values that can't possibly fit - avoids a huge reserve()
    // on a corrupt header before the per-entry bounds checks run.
    if (nfat > (buf.size() - 8) / arch_size) {
        return std::unexpected(Error::truncated(std::format(
            "fat: header claims {} arch entries, file only {} bytes", nfat, buf.size())));
    }

    struct Slice { u32 cputype; u64 offset; u64 size; };
    std::vector<Slice> slices;
    slices.reserve(nfat);
    for (u32 i = 0; i < nfat; ++i) {
        const std::size_t a = 8 + static_cast<std::size_t>(i) * arch_size;
        auto cputype = r.read_be<u32>(a + 0);
        if (!cputype) return std::unexpected(std::move(cputype).error());
        u64 offset = 0, size = 0;
        if (is_64) {
            auto o = r.read_be<u64>(a + 8);
            if (!o) return std::unexpected(std::move(o).error());
            auto s = r.read_be<u64>(a + 16);
            if (!s) return std::unexpected(std::move(s).error());
            offset = *o; size = *s;
        } else {
            auto o = r.read_be<u32>(a + 8);
            if (!o) return std::unexpected(std::move(o).error());
            auto s = r.read_be<u32>(a + 12);
            if (!s) return std::unexpected(std::move(s).error());
            offset = *o; size = *s;
        }
        slices.push_back({*cputype, offset, size});
    }

    const Slice* pick = nullptr;
    for (const auto& s : slices) if (s.cputype == CPU_TYPE_X86_64) { pick = &s; break; }
    if (!pick) for (const auto& s : slices) if (s.cputype == CPU_TYPE_ARM64)  { pick = &s; break; }
    if (!pick && !slices.empty()) {
        pick = &slices[0];
        // The slice is browsable (symbols/sections still parse) but the
        // decoder will fail on instructions. Warn loudly so users don't
        // wonder why decompile/disasm output is empty.
        spelunk::diagnostic::printf("spelunk: fat binary has no x86_64 or arm64 slice; "
            "falling back to cputype %#x (instructions will not decode)\n",
            pick->cputype);
    }
    if (!pick) {
        return std::unexpected(Error::invalid_format("fat: no arch slices"));
    }
    // offset + size overflow guard, then end-of-file check.
    if (pick->offset > buf.size() || pick->size > buf.size() - pick->offset) {
        return std::unexpected(Error::truncated(std::format(
            "fat: arch slice [{:#x}, +{:#x}) extends past {:#x}-byte file",
            pick->offset, pick->size, buf.size())));
    }
    std::vector<std::byte> out(buf.begin() + static_cast<std::ptrdiff_t>(pick->offset),
                               buf.begin() + static_cast<std::ptrdiff_t>(pick->offset + pick->size));
    return out;
}

}  // namespace

Result<std::unique_ptr<Binary>>
load_binary(const std::filesystem::path& path) {
    return load_binary(path, LoadOptions{});
}

Result<std::unique_ptr<Binary>>
load_binary(const std::filesystem::path& path, const LoadOptions& opts) {
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
        attach_embedded_dwarf(**elf);
        return std::unique_ptr<Binary>(std::move(*elf));
    }
    if (looks_like_dol_path(path, *buffer)) {
        auto dol = DolBinary::load_from_buffer(std::move(*buffer));
        if (!dol) return std::unexpected(std::move(dol).error());
        if (!opts.dol_symbols_path.empty()) {
            auto loaded = (*dol)->attach_dtk_symbols_from_path(opts.dol_symbols_path);
            if (!loaded) return std::unexpected(std::move(loaded).error());
            return std::unique_ptr<Binary>(std::move(*dol));
        }
        std::error_code ec;
        auto try_map = [&](const std::filesystem::path& p) -> bool {
            if (p.empty()) return false;
            if (!std::filesystem::exists(p, ec) || ec) return false;
            auto loaded = (*dol)->attach_map_from_path(p);
            return loaded && *loaded != 0;
        };
        if (!try_map(path.string() + ".map")) {
            try_map(path.parent_path() / (path.stem().string() + ".map"));
        }
        return std::unique_ptr<Binary>(std::move(*dol));
    }
    if (looks_like_rel_path(path, *buffer)) {
        auto rel = RelBinary::load_from_buffer(
            std::move(*buffer), opts.rel_load_base.value_or(kDefaultRelLoadBase));
        if (!rel) return std::unexpected(std::move(rel).error());
        if (!opts.dol_symbols_path.empty()) {
            auto loaded = (*rel)->attach_dtk_symbols_from_path(opts.dol_symbols_path);
            if (!loaded) return std::unexpected(std::move(loaded).error());
        }
        return std::unique_ptr<Binary>(std::move(*rel));
    }
    if (looks_like_macho_64(*buffer)) {
        auto m = MachOBinary::load_from_buffer(std::move(*buffer));
        if (!m) return std::unexpected(std::move(m).error());
        attach_embedded_dwarf(**m);
        return std::unique_ptr<Binary>(std::move(*m));
    }
    if (looks_like_minidump(*buffer)) {
        auto md = MinidumpBinary::load_from_buffer(std::move(*buffer));
        if (!md) return std::unexpected(std::move(md).error());
        return std::unique_ptr<Binary>(std::move(*md));
    }
    if (looks_like_pe(*buffer)) {
        auto pe = PeBinary::load_from_buffer(std::move(*buffer));
        if (!pe) return std::unexpected(std::move(pe).error());

        // Three modes for PDB ingestion, in priority order:
        //   1. Explicit override (`--pdb PATH`): try that path; report
        //      success/failure but never fall back to auto-discovery -
        //      the user picked a specific file.
        //   2. Disabled (`--no-pdb`): skip entirely.
        //   3. Auto-discovery: try the basename of the embedded
        //      CodeView PDB filename first (`<binary_dir>/<basename>`),
        //      then `<binary>.pdb` and `<binary stem>.pdb`. Failures
        //      are silent - without a PDB the binary still loads with
        //      whatever names the PE itself carried.
        std::error_code ec;
        std::filesystem::path dir = path.parent_path();
        auto try_load = [&](const std::filesystem::path& p) -> bool {
            if (p.empty()) return false;
            if (!std::filesystem::exists(p, ec)) return false;
            auto added = (*pe)->attach_pdb_from_path(p);
            return added.has_value();
        };

        if (!opts.pdb_path.empty()) {
            if (!try_load(opts.pdb_path)) {
                spelunk::diagnostic::printf("spelunk: --pdb: cannot read '%s'; continuing without PDB info\n",
                    opts.pdb_path.string().c_str());
            }
        } else if (!opts.no_pdb) {
            const std::string_view embedded = (*pe)->pdb_filename();
            if (!embedded.empty()) {
                std::filesystem::path emb(embedded);
                if (try_load(dir / emb.filename())) {
                    /* loaded */
                } else {
                    try_load(dir / std::filesystem::path(std::string(embedded)));
                }
            }
            if ((*pe)->attached_pdb_path().empty()) {
                // Even without an embedded reference, try the
                // conventional name - split-debug builds drop
                // `<basename>.pdb` next to the binary.
                try_load(path.string() + ".pdb");
                try_load(path.parent_path() / (path.stem().string() + ".pdb"));
            }
        }

        attach_embedded_dwarf(**pe);

        return std::unique_ptr<Binary>(std::move(*pe));
    }

    for (const auto& entry : ext::registered_loaders()) {
        if (entry.sniff && entry.load && entry.sniff(*buffer)) {
            return entry.load(std::move(*buffer), opts);
        }
    }

    return std::unexpected(Error::unsupported(
        "unrecognized binary format (only ELF, DOL, REL, Mach-O 64-bit, and PE32+ supported)"));
}

}  // namespace spelunk
