#include <ember/binary/pe_view.hpp>

#include <algorithm>
#include <cstddef>
#include <expected>
#include <format>
#include <limits>
#include <optional>
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

[[nodiscard]] bool rva_range_fits(u32 start, u32 size) noexcept {
    constexpr u64 kRvaSpaceSize = u64{1} << 32;
    return static_cast<u64>(start) + size <= kRvaSpaceSize;
}

[[nodiscard]] std::optional<u32>
add_rva(u32 base, std::size_t offset) noexcept {
    if (offset > std::numeric_limits<u32>::max() - base) {
        return std::nullopt;
    }
    return base + static_cast<u32>(offset);
}

Result<void> collect_thunks(
    const Binary& bin, addr_t image_base, u32 int_rva, u32 iat_rva,
    std::vector<Symbol>& out,
    std::unordered_map<addr_t, std::string>* got_to_name,
    bool iat_is_name_fallback) {
    const auto int_bytes = bytes_at_rva(bin, image_base, int_rva);
    const auto iat_bytes = bytes_at_rva(bin, image_base, iat_rva);
    const std::size_t available =
        std::min(int_bytes.size(), iat_bytes.size()) / 8;
    constexpr std::size_t kMaxImportSymbols = 1u << 20;
    const std::size_t count = std::min(available, kMaxImportSymbols);

    for (std::size_t index = 0; index < count; ++index) {
        const std::size_t offset = index * 8;
        const u64 thunk = read_le_at<u64>(int_bytes.data() + offset);
        if (thunk == 0) return {};

        const auto slot_rva = add_rva(iat_rva, offset);
        if (!slot_rva || *slot_rva >
                std::numeric_limits<addr_t>::max() - image_base) {
            return std::unexpected(Error::invalid_format(
                "pe: import address table RVA overflows"));
        }

        Symbol symbol;
        symbol.kind = SymbolKind::Function;
        symbol.is_import = true;
        symbol.got_addr = image_base + *slot_rva;

        if ((thunk & kOrdinalFlagBit) != 0) {
            constexpr u64 kOrdinalPayloadMask = 0x7fffffffffff0000ull;
            if ((thunk & kOrdinalPayloadMask) != 0) {
                if (iat_is_name_fallback) return {};
                return std::unexpected(Error::invalid_format(
                    "pe: import ordinal thunk has reserved bits set"));
            }
            const u16 ordinal = static_cast<u16>(thunk & 0xffffu);
            symbol.name = std::format("Ordinal#{}", ordinal);
        } else {
            if (thunk > std::numeric_limits<u32>::max()) {
                // When OriginalFirstThunk is absent, a loaded-memory view
                // may expose runtime-resolved function VAs in FirstThunk.
                // Those entries carry no recoverable static name table.
                if (iat_is_name_fallback) return {};
                return std::unexpected(Error::invalid_format(
                    "pe: import name RVA exceeds 32 bits"));
            }
            const u32 hint_name_rva = static_cast<u32>(thunk);
            const auto name_rva = add_rva(hint_name_rva, 2);
            if (!name_rva) {
                return std::unexpected(Error::invalid_format(
                    "pe: import hint/name RVA overflows"));
            }
            const auto name = cstr_at_rva(bin, image_base, *name_rva);
            if (name.empty()) continue;
            symbol.name = std::string(name);
        }

        if (got_to_name) {
            got_to_name->emplace(symbol.got_addr, symbol.name);
        }
        out.push_back(std::move(symbol));
    }
    if (available > kMaxImportSymbols) {
        return std::unexpected(Error::invalid_format(std::format(
            "pe: import table exceeds {} entries", kMaxImportSymbols)));
    }
    return std::unexpected(Error::truncated(
        "pe: import table has no terminating null thunk"));
}

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
    if (!rva_range_fits(dd.virtual_address, dd.size)) {
        return std::unexpected(Error::invalid_format(
            "pe: import directory RVA range overflows"));
    }
    if (!rva_is_mapped(bin, image_base, dd.virtual_address, kImportDescSize)) return {};

    // Array of IMAGE_IMPORT_DESCRIPTOR terminated by an all-zero record.
    // Cap the loop at dd.size / kImportDescSize so a malicious missing
    // terminator can't walk forever.
    const std::size_t max_descs = dd.size / kImportDescSize;
    for (std::size_t i = 0; i < max_descs; ++i) {
        const auto current = add_rva(dd.virtual_address, i * kImportDescSize);
        if (!current) {
            return std::unexpected(Error::invalid_format(
                "pe: import descriptor RVA overflows"));
        }
        const auto desc = bytes_at_rva(bin, image_base, *current);
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
        if (auto result = collect_thunks(
                bin, image_base, int_rva, iat_rva, out, got_to_name,
                oft_rva == 0);
            !result) {
            return result;
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
    if (!rva_range_fits(dd.virtual_address, dd.size)) {
        return std::unexpected(Error::invalid_format(
            "pe: delay-import directory RVA range overflows"));
    }
    if (!rva_is_mapped(bin, image_base, dd.virtual_address, kDelayImportDescSize)) return {};

    const std::size_t max_descs = dd.size / kDelayImportDescSize;
    for (std::size_t i = 0; i < max_descs; ++i) {
        const auto current = add_rva(
            dd.virtual_address, i * kDelayImportDescSize);
        if (!current) {
            return std::unexpected(Error::invalid_format(
                "pe: delay-import descriptor RVA overflows"));
        }
        const auto desc = bytes_at_rva(bin, image_base, *current);
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

        if (auto result = collect_thunks(
                bin, image_base, int_rva, iat_rva, out, got_to_name,
                false);
            !result) {
            return result;
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
        if (func_rva > std::numeric_limits<addr_t>::max() - image_base) {
            return std::unexpected(Error::invalid_format(
                "pe: named export address overflows"));
        }
        sym.addr      = image_base + func_rva;
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
        if (func_rva > std::numeric_limits<addr_t>::max() - image_base) {
            return std::unexpected(Error::invalid_format(
                "pe: ordinal export address overflows"));
        }
        sym.addr      = image_base + func_rva;
        sym.kind      = SymbolKind::Function;
        sym.is_export = true;
        out.push_back(std::move(sym));
    }
    return {};
}

}  // namespace ember::pe
