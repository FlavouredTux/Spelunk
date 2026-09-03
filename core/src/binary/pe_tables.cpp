#include <ember/binary/pe_view.hpp>

#include <cstddef>
#include <expected>
#include <format>
#include <span>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <ember/common/bytes.hpp>

namespace ember::pe {

namespace {

constexpr std::size_t kDdExport      = 0;
constexpr std::size_t kDdImport      = 1;
constexpr std::size_t kDdDelayImport = 13;

constexpr std::size_t kImportDescSize      = 20;
constexpr std::size_t kDelayImportDescSize = 32;
constexpr u32         kDelayAttrRvaBased   = 0x1;
constexpr u64         kOrdinalFlagBit      = 0x8000'0000'0000'0000ULL;
constexpr std::size_t kExportDirSize       = 40;

}  // namespace

Result<void>
collect_imports(const Binary& bin,
                addr_t image_base,
                std::span<const DataDirectory> dirs,
                std::vector<Symbol>& out,
                std::unordered_map<addr_t, std::string>* got_to_name) {
    if (dirs.size() <= kDdImport) return {};
    const auto& dd = dirs[kDdImport];
    if (dd.size == 0 || dd.virtual_address == 0) return {};
    if (!rva_is_mapped(bin, image_base, dd.virtual_address, kImportDescSize)) return {};

    // Array of IMAGE_IMPORT_DESCRIPTOR terminated by an all-zero record.
    // Cap the loop at dd.size / kImportDescSize so a malicious missing
    // terminator can't walk forever.
    const std::size_t max_descs = dd.size / kImportDescSize;
    u32 cur = dd.virtual_address;

    for (std::size_t i = 0; i < max_descs; ++i, cur += kImportDescSize) {
        const auto desc = bytes_at_rva(bin, image_base, cur);
        if (desc.size() < kImportDescSize) break;

        const u32 oft_rva     = read_le_at<u32>(desc.data() + 0x00);
        const u32 name_rva    = read_le_at<u32>(desc.data() + 0x0C);
        const u32 iat_rva     = read_le_at<u32>(desc.data() + 0x10);
        if ((oft_rva | name_rva | iat_rva) == 0) break;   // terminator
        if (!rva_is_mapped(bin, image_base, name_rva)) continue;

        // Walk INT and IAT in lockstep. INT gives us the hint/name; IAT
        // is the slot the loader overwrites with the resolved pointer.
        // If OriginalFirstThunk is zero (bound imports, older linkers),
        // fall back to FirstThunk for name lookup - the loader will
        // have overwritten it at runtime, but on the static image the
        // name entries are still intact.
        const u32 int_rva = (oft_rva != 0) ? oft_rva : iat_rva;

        for (u32 k = 0;; ++k) {
            const auto int_bytes = bytes_at_rva(bin, image_base, int_rva + k * 8);
            const auto iat_bytes = bytes_at_rva(bin, image_base, iat_rva + k * 8);
            if (int_bytes.size() < 8 || iat_bytes.size() < 8) break;
            const u64 thunk = read_le_at<u64>(int_bytes.data());
            if (thunk == 0) break;

            Symbol sym;
            sym.kind      = SymbolKind::Function;
            sym.is_import = true;
            sym.got_addr  = image_base + static_cast<addr_t>(iat_rva) + k * 8;

            if ((thunk & kOrdinalFlagBit) != 0) {
                const u16 ordinal = static_cast<u16>(thunk & 0xFFFFu);
                sym.name = std::format("Ordinal#{}", ordinal);
            } else {
                // IMAGE_IMPORT_BY_NAME: u16 hint, then C-string.
                const u32 hintname_rva = static_cast<u32>(thunk & 0xFFFF'FFFFULL);
                const auto nm = cstr_at_rva(bin, image_base, hintname_rva + 2);
                if (nm.empty()) continue;  // corrupt: no name, skip slot
                sym.name = std::string(nm);
            }

            if (got_to_name) got_to_name->emplace(sym.got_addr, sym.name);
            out.push_back(std::move(sym));
        }
    }
    return {};
}

// Delay-load descriptor format (ImgDelayDescr, 32 bytes):
//   u32 grAttrs;        // bit 0 set → all subsequent fields are RVAs
//   u32 rvaDLLName;
//   u32 rvaHmod;        // module-handle slot, populated at runtime
//   u32 rvaIAT;         // we treat this exactly like a regular IAT
//   u32 rvaINT;         // hint/name table, identical encoding to IMPORT
//   u32 rvaBoundIAT;    // pre-bound IAT (if linker bound at build time)
//   u32 rvaUnloadIAT;   // for FUnloadDelayLoadedDLL - we ignore
//   u32 dwTimeStamp;
// Walks identically to collect_imports once we've extracted INT/IAT RVAs.
// Older (non-x64) images had grAttrs == 0 with absolute VAs in every
// field - we reject those rather than try to guess the image base from
// addresses that may have been written under a different load address.
Result<void>
collect_delay_imports(const Binary& bin,
                      addr_t image_base,
                      std::span<const DataDirectory> dirs,
                      std::vector<Symbol>& out,
                      std::unordered_map<addr_t, std::string>* got_to_name) {
    if (dirs.size() <= kDdDelayImport) return {};
    const auto& dd = dirs[kDdDelayImport];
    if (dd.size == 0 || dd.virtual_address == 0) return {};
    if (!rva_is_mapped(bin, image_base, dd.virtual_address, kDelayImportDescSize)) return {};

    const std::size_t max_descs = dd.size / kDelayImportDescSize;
    u32 cur = dd.virtual_address;

    for (std::size_t i = 0; i < max_descs; ++i, cur += kDelayImportDescSize) {
        const auto desc = bytes_at_rva(bin, image_base, cur);
        if (desc.size() < kDelayImportDescSize) break;

        const u32 attrs    = read_le_at<u32>(desc.data() + 0x00);
        const u32 name_rva = read_le_at<u32>(desc.data() + 0x04);
        const u32 iat_rva  = read_le_at<u32>(desc.data() + 0x0C);
        const u32 int_rva  = read_le_at<u32>(desc.data() + 0x10);
        if ((attrs | name_rva | iat_rva | int_rva) == 0) break;  // terminator
        if (!rva_is_mapped(bin, image_base, name_rva)) continue;
        // Pre-x64 layout: ignore the slice rather than misread VAs as RVAs.
        if ((attrs & kDelayAttrRvaBased) == 0) continue;
        // Some linkers ship descriptors with no INT (rvaINT == 0); for the
        // statically-recorded names we *need* the INT, so skip - the IAT
        // alone is just patched function pointers at runtime.
        if (int_rva == 0 || iat_rva == 0) continue;

        for (u32 k = 0;; ++k) {
            const auto int_bytes = bytes_at_rva(bin, image_base, int_rva + k * 8);
            const auto iat_bytes = bytes_at_rva(bin, image_base, iat_rva + k * 8);
            if (int_bytes.size() < 8 || iat_bytes.size() < 8) break;
            const u64 thunk = read_le_at<u64>(int_bytes.data());
            if (thunk == 0) break;

            Symbol sym;
            sym.kind      = SymbolKind::Function;
            sym.is_import = true;
            sym.got_addr  = image_base + static_cast<addr_t>(iat_rva) + k * 8;

            if ((thunk & kOrdinalFlagBit) != 0) {
                const u16 ordinal = static_cast<u16>(thunk & 0xFFFFu);
                sym.name = std::format("Ordinal#{}", ordinal);
            } else {
                const u32 hintname_rva = static_cast<u32>(thunk & 0xFFFF'FFFFULL);
                const auto nm = cstr_at_rva(bin, image_base, hintname_rva + 2);
                if (nm.empty()) continue;
                sym.name = std::string(nm);
            }

            if (got_to_name) got_to_name->emplace(sym.got_addr, sym.name);
            out.push_back(std::move(sym));
        }
    }
    return {};
}

Result<void>
collect_exports(const Binary& bin,
                addr_t image_base,
                std::span<const DataDirectory> dirs,
                std::vector<Symbol>& out) {
    if (dirs.size() <= kDdExport) return {};
    const auto& dd = dirs[kDdExport];
    if (dd.size == 0 || dd.virtual_address == 0) return {};
    if (!rva_is_mapped(bin, image_base, dd.virtual_address, kExportDirSize)) return {};

    const auto edir = bytes_at_rva(bin, image_base, dd.virtual_address);
    if (edir.size() < kExportDirSize) return {};

    const u32 ordinal_base = read_le_at<u32>(edir.data() + 0x10);
    const u32 num_funcs    = read_le_at<u32>(edir.data() + 0x14);
    const u32 num_names    = read_le_at<u32>(edir.data() + 0x18);
    const u32 eat_rva      = read_le_at<u32>(edir.data() + 0x1C);
    const u32 ent_rva      = read_le_at<u32>(edir.data() + 0x20);
    const u32 eot_rva      = read_le_at<u32>(edir.data() + 0x24);

    constexpr u32 kMaxExportSymbols = 1u << 20;
    if (num_funcs > kMaxExportSymbols || num_names > kMaxExportSymbols) {
        return std::unexpected(Error::invalid_format(std::format(
            "pe: export table count exceeds {} entries", kMaxExportSymbols)));
    }
    const auto eat = bytes_at_rva(bin, image_base, eat_rva);
    const auto ent = bytes_at_rva(bin, image_base, ent_rva);
    const auto eot = bytes_at_rva(bin, image_base, eot_rva);
    if (num_funcs > eat.size() / 4 ||
        num_names > ent.size() / 4 || num_names > eot.size() / 2) {
        return std::unexpected(Error::truncated(
            "pe: export address/name/ordinal table overruns mapped image"));
    }

    // Forwarder exports point *into* the export data directory itself -
    // the RVA there is the "DLL.Symbol" redirect string, not a function
    // address. Skip them instead of emitting a garbage Symbol at a
    // string VA. Widen to u64 for the upper-bound check: a hostile PE
    // with `dd.virtual_address + dd.size` that overflows u32 would
    // otherwise wrap to a tiny number, causing every export to fail
    // (or pass) the forwarder test depending on which side the wrap
    // lands on.
    const u64 dd_end = static_cast<u64>(dd.virtual_address) +
                       static_cast<u64>(dd.size);
    const auto is_forwarder = [&](u32 rva) noexcept {
        return rva >= dd.virtual_address && rva < dd_end;
    };

    // Named exports: walk ENT + EOT in parallel. EOT[i] is an index
    // into EAT (0-based, not ordinal-based).
    for (u32 i = 0; i < num_names; ++i) {
        const u32 name_rva = read_le_at<u32>(ent.data() +
                                              static_cast<std::size_t>(i) * 4);
        const u16 eat_idx  = read_le_at<u16>(eot.data() +
                                              static_cast<std::size_t>(i) * 2);
        if (eat_idx >= num_funcs) continue;

        const u32 func_rva = read_le_at<u32>(eat.data() +
                                              static_cast<std::size_t>(eat_idx) * 4);
        if (func_rva == 0 || is_forwarder(func_rva)) continue;

        const auto name = cstr_at_rva(bin, image_base, name_rva);
        if (name.empty()) continue;

        Symbol sym;
        sym.name      = std::string(name);
        sym.addr      = image_base + static_cast<addr_t>(func_rva);
        sym.kind      = SymbolKind::Function;
        sym.is_export = true;
        out.push_back(std::move(sym));
    }

    // Unnamed (ordinal-only) exports: any EAT slot not reached by EOT.
    // Build a bitmap of referenced indices, then emit "Ordinal#N" entries
    // for the gaps. Keeps addresses resolvable even without a name.
    std::vector<bool> named(num_funcs, false);
    for (u32 i = 0; i < num_names; ++i) {
        const u16 eat_idx = read_le_at<u16>(eot.data() +
                                             static_cast<std::size_t>(i) * 2);
        if (eat_idx < num_funcs) named[eat_idx] = true;
    }
    for (u32 i = 0; i < num_funcs; ++i) {
        if (named[i]) continue;
        const u32 func_rva = read_le_at<u32>(eat.data() +
                                              static_cast<std::size_t>(i) * 4);
        if (func_rva == 0 || is_forwarder(func_rva)) continue;

        Symbol sym;
        sym.name      = std::format("Ordinal#{}",
                                    static_cast<u64>(ordinal_base) + i);
        sym.addr      = image_base + static_cast<addr_t>(func_rva);
        sym.kind      = SymbolKind::Function;
        sym.is_export = true;
        out.push_back(std::move(sym));
    }
    return {};
}

}  // namespace ember::pe
