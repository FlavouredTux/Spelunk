#include <ember/binary/binary.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <format>
#include <fstream>
#include <system_error>
#include <utility>
#include <vector>

#include <ember/binary/elf.hpp>
#include <ember/binary/macho.hpp>
#include <ember/binary/minidump.hpp>
#include <ember/binary/pe.hpp>
#include <ember/common/bytes.hpp>

namespace ember {

const Binary::LookupCaches& Binary::caches() const {
    if (caches_) return *caches_;
    caches_ = std::make_unique<LookupCaches>();
    auto& c = *caches_;

    const auto syms = symbols();
    c.imports_by_addr.reserve(syms.size());
    c.defined_objects_by_addr.reserve(syms.size());

    for (const auto& s : syms) {
        // Prefer defined symbols on name collision (imports have stub addrs
        // that callers expect to resolve to imports via import_at_plt, not
        // via find_by_name; find_by_name is for user intent like "resolve
        // this source-level name").
        auto [it, inserted] = c.by_name.try_emplace(s.name, &s);
        if (!inserted && it->second->is_import && !s.is_import) it->second = &s;

        if (s.is_import) {
            if (s.got_addr != 0) c.import_by_got.emplace(s.got_addr, &s);
            if (s.addr != 0)     c.imports_by_addr.push_back(&s);
        } else if (s.size != 0 &&
                   (s.kind == SymbolKind::Function || s.kind == SymbolKind::Object)) {
            c.defined_objects_by_addr.push_back(&s);
        }
    }

    // Sort both vectors by (addr, name, size) to match the loader's
    // symbols() sort order. defined_object_at must return the same alias the
    // original linear scan did when multiple symbols share a vaddr (e.g.
    // `stdout` + `stdout@GLIBC_2.2.5` on a copy-relocated import).
    auto by_addr_name_size = [](const Symbol* a, const Symbol* b) noexcept {
        if (a->addr != b->addr) return a->addr < b->addr;
        if (a->name != b->name) return a->name < b->name;
        return a->size < b->size;
    };
    std::ranges::sort(c.imports_by_addr, by_addr_name_size);
    std::ranges::sort(c.defined_objects_by_addr, by_addr_name_size);
    return c;
}

const Symbol* Binary::import_at_plt(addr_t plt_addr, unsigned slot_size) const noexcept {
    if (plt_addr == 0) return nullptr;
    const auto& c = caches();
    // Stubs are fixed-width slots — upper_bound on addr gives the slot whose
    // base is > plt_addr; step one back to get the slot that could contain it.
    auto it = std::upper_bound(
        c.imports_by_addr.begin(), c.imports_by_addr.end(), plt_addr,
        [](addr_t a, const Symbol* s) noexcept { return a < s->addr; });
    if (it == c.imports_by_addr.begin()) return nullptr;
    --it;
    // Rewind to the first entry with this addr so ties break the same way
    // the original linear scan did.
    while (it != c.imports_by_addr.begin() && (*(it - 1))->addr == (*it)->addr) --it;
    const Symbol* s = *it;
    if (plt_addr >= s->addr && plt_addr < s->addr + slot_size) return s;
    return nullptr;
}

const Symbol* Binary::import_at_got(addr_t got_addr) const noexcept {
    if (got_addr == 0) return nullptr;
    const auto& c = caches();
    auto it = c.import_by_got.find(got_addr);
    return it == c.import_by_got.end() ? nullptr : it->second;
}

const Symbol* Binary::defined_object_at(addr_t vaddr) const noexcept {
    const auto& c = caches();
    auto it = std::upper_bound(
        c.defined_objects_by_addr.begin(), c.defined_objects_by_addr.end(), vaddr,
        [](addr_t a, const Symbol* s) noexcept { return a < s->addr; });
    if (it == c.defined_objects_by_addr.begin()) return nullptr;
    --it;
    while (it != c.defined_objects_by_addr.begin() && (*(it - 1))->addr == (*it)->addr) --it;
    // Among aliases at the same addr, return the first that contains vaddr —
    // this preserves the (name, size)-sorted preference of the original
    // linear scan over symbols().
    const addr_t group_addr = (*it)->addr;
    for (; it != c.defined_objects_by_addr.end() && (*it)->addr == group_addr; ++it) {
        const Symbol* s = *it;
        if (vaddr >= s->addr && vaddr < s->addr + s->size) return s;
    }
    return nullptr;
}

const Symbol* Binary::find_by_name(std::string_view name) const noexcept {
    const auto& c = caches();
    auto it = c.by_name.find(name);
    return it == c.by_name.end() ? nullptr : it->second;
}

std::vector<const Symbol*>
Binary::find_all_by_name(std::string_view name) const {
    // Linear scan rather than a cached multimap: collision checks are
    // low-frequency (once per CLI invocation, once per project.rename)
    // and the single-winner cache still satisfies the hot path.
    std::vector<const Symbol*> out;
    for (const auto& s : symbols()) {
        if (s.is_import) continue;
        if (s.name == name) out.push_back(&s);
    }
    return out;
}

void Binary::record_indirect_edge(addr_t from, addr_t to) const {
    auto& vec = indirect_edges_[from];
    // Linear-scan dedupe — N is tiny per call site (a handful of
    // observed targets on real traces), and keeping the order means
    // downstream sees edges in the order they were learned.
    for (addr_t existing : vec) if (existing == to) return;
    vec.push_back(to);
}

std::span<const addr_t>
Binary::indirect_edges_from(addr_t from) const noexcept {
    auto it = indirect_edges_.find(from);
    if (it == indirect_edges_.end()) return {};
    return it->second;
}

std::size_t Binary::indirect_edge_count() const noexcept {
    std::size_t n = 0;
    for (const auto& [from, vec] : indirect_edges_) n += vec.size();
    return n;
}

void Binary::clear_indirect_edges() const noexcept {
    indirect_edges_.clear();
}

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

// CAFEBABE (32-bit fat) or CAFEBABF (64-bit fat) — the wrapper around a
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

    // Reject nfat values that can't possibly fit — avoids a huge reserve()
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
        std::fprintf(stderr,
            "ember: fat binary has no x86_64 or arm64 slice; "
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
    if (looks_like_minidump(*buffer)) {
        auto md = MinidumpBinary::load_from_buffer(std::move(*buffer));
        if (!md) return std::unexpected(std::move(md).error());
        return std::unique_ptr<Binary>(std::move(*md));
    }
    if (looks_like_pe(*buffer)) {
        auto pe = PeBinary::load_from_buffer(std::move(*buffer));
        if (!pe) return std::unexpected(std::move(pe).error());

        // Sidecar PDB ingestion — opt-in by file presence. Try the
        // basename of the embedded CodeView PDB filename first
        // (`<binary_dir>/<basename>`), then `<binary>.pdb` and
        // `<binary stem>.pdb`. MSVC bakes an absolute build-host path
        // into the .exe; the basename match is what end-user setups
        // ship. Failures are silent: if no PDB is found, the binary
        // loads with whatever names the PE itself carried (exports,
        // imports, PDATA-derived sub_<hex>).
        const std::string_view embedded = (*pe)->pdb_filename();
        std::error_code ec;
        std::filesystem::path dir = path.parent_path();
        auto try_load = [&](const std::filesystem::path& p) -> bool {
            if (p.empty()) return false;
            if (!std::filesystem::exists(p, ec)) return false;
            auto added = (*pe)->attach_pdb_from_path(p);
            return added.has_value();
        };
        if (!embedded.empty()) {
            std::filesystem::path emb(embedded);
            if (try_load(dir / emb.filename())) {
                /* loaded */
            } else {
                try_load(dir / std::filesystem::path(std::string(embedded)));
            }
        }
        if ((*pe)->pdb_filename().empty()) {
            // Even without an embedded reference, try the conventional
            // name — split debug builds drop `<basename>.pdb` next to
            // the binary.
            try_load(path.string() + ".pdb");
            try_load(path.parent_path() / (path.stem().string() + ".pdb"));
        }

        return std::unique_ptr<Binary>(std::move(*pe));
    }

    return std::unexpected(Error::unsupported(
        "unrecognized binary format (only ELF, Mach-O 64-bit, and PE32+ supported)"));
}

}  // namespace ember
