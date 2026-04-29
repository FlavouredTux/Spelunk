#pragma once

#include <cstddef>
#include <filesystem>
#include <memory>
#include <span>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <ember/binary/arch.hpp>
#include <ember/binary/format.hpp>
#include <ember/binary/section.hpp>
#include <ember/binary/symbol.hpp>
#include <ember/common/error.hpp>
#include <ember/common/types.hpp>

namespace ember {

class Binary {
public:
    Binary() = default;
    virtual ~Binary() = default;

    Binary(const Binary&)            = delete;
    Binary& operator=(const Binary&) = delete;
    Binary(Binary&&)                 = delete;
    Binary& operator=(Binary&&)      = delete;

    [[nodiscard]] virtual Format format() const noexcept      = 0;
    [[nodiscard]] virtual Arch   arch() const noexcept        = 0;
    [[nodiscard]] virtual Endian endian() const noexcept      = 0;
    [[nodiscard]] virtual addr_t entry_point() const noexcept = 0;

    // The virtual address the binary was *linked* to load at. Subtract
    // this from a symbol address to get the file-offset / RVA, then add
    // the runtime load base to get the slid runtime address (the
    // debugger does exactly this dance for `b <symbol>` against PIE/ASLR
    // binaries). Default 0 — appropriate for raw-region inputs and any
    // format that treats addresses as already-absolute.
    [[nodiscard]] virtual addr_t preferred_load_base() const noexcept { return 0; }

    [[nodiscard]] virtual std::span<const Section> sections() const noexcept = 0;
    [[nodiscard]] virtual std::span<const Symbol>  symbols() const noexcept  = 0;

    [[nodiscard]] virtual std::span<const std::byte> image() const noexcept = 0;

    // True when `addr` lives inside a region the linker flagged as
    // non-code data embedded in __TEXT (LC_DATA_IN_CODE on Mach-O, or
    // analogous metadata on other formats). The CFG walker stops before
    // decoding such bytes as instructions. Default says "no such metadata"
    // for formats that don't carry it.
    [[nodiscard]] virtual bool
    is_data_in_code(addr_t) const noexcept { return false; }

    // Default: walk `sections()` to resolve a virtual address to file bytes.
    // Format-specific loaders (e.g. ElfBinary with PT_LOAD) should override
    // this to use their authoritative mapping table; for binaries that
    // carry only section headers (relocatable .o files) the default is
    // still correct.
    [[nodiscard]] virtual std::span<const std::byte>
    bytes_at(addr_t vaddr) const noexcept {
        for (const auto& s : sections()) {
            if (s.data.empty()) continue;
            if (vaddr < s.vaddr) continue;
            const auto offset = vaddr - s.vaddr;
            if (offset >= s.data.size()) continue;
            return s.data.subspan(static_cast<std::size_t>(offset));
        }
        return {};
    }

    // Look up the import whose PLT stub covers `plt_addr`. Accepts any
    // address within the stub's slot — typically 16 bytes on x86-64 — so
    // that callers targeting the middle of a slot (e.g. skipping a leading
    // endbr64 prefix) still resolve to the right import.
    [[nodiscard]] const Symbol*
    import_at_plt(addr_t plt_addr, unsigned slot_size = 16) const noexcept;

    // Look up the import whose GOT slot is at `got_addr` (the address the
    // dynamic linker fills with the resolved function pointer).
    [[nodiscard]] const Symbol* import_at_got(addr_t got_addr) const noexcept;

    // Find a named defined symbol (Object or Function) that contains the
    // given virtual address. Used by the emitter to render `*(u64*)(0x404020)`
    // as `g_name` where a matching global exists.
    [[nodiscard]] const Symbol* defined_object_at(addr_t vaddr) const noexcept;

    // Find a symbol by name. O(1) average (hashed); returns the first
    // matching symbol, preferring a defined one if both exist.
    [[nodiscard]] const Symbol* find_by_name(std::string_view name) const noexcept;

    // Return every non-import symbol whose name matches `name`. Linear
    // scan; fingerprint import and user renames can collide on short
    // stubs, and this is the escape hatch for "how many addresses does
    // this name cover?". Empty span when nothing matches or only
    // imports match.
    [[nodiscard]] std::vector<const Symbol*>
    find_all_by_name(std::string_view name) const;

    // Invalidate the lookup caches. Loaders call this when symbols_
    // changes after the initial parse() — e.g. when the PDB sidecar
    // ingestion pass adds names that the on-disk PE didn't carry.
    void invalidate_caches() const noexcept { caches_.reset(); }

    // Add a synthetic Function symbol at `va`. Used by the
    // `--force-fn-start <VA>` CLI override to correct mis-attributed
    // function entries in obfuscated code where ember would otherwise
    // rebind to the closest-below symbol. No-op when a Function
    // symbol already exists at exactly `va`. The added symbol uses
    // the standard `sub_<hex>` synthetic name; users can rename via
    // `--annotations` afterwards. Requires the derived class to
    // expose its mutable symbol table via `mutable_symbols()`.
    void add_synthetic_function_start(addr_t va);

protected:
    // Mutable view of the derived class's symbol storage. Used only
    // by the small number of base-class methods that need to push
    // synthetic entries — the public `symbols()` accessor stays
    // const-only.
    [[nodiscard]] virtual std::vector<Symbol>& mutable_symbols() noexcept = 0;
public:

    // ---- Indirect-edge oracle ----------------------------------------
    // User-populated map: instruction VA of an indirect call/jmp →
    // concrete target VAs observed at runtime (or otherwise known).
    // Populated by JS scripts (binary.recordIndirectEdge) or `--trace`
    // CLI input from a dynamic-instrumentation tool. The CFG builder
    // consults this when it would otherwise leave the block as
    // BlockKind::IndirectJmp; if the oracle has entries, it materializes
    // them as concrete successors so the rest of the pipeline sees a
    // resolved CFG. The store is per-`Binary` instance, in-memory only
    // — restart Ember and you start fresh.
    void record_indirect_edge(addr_t from, addr_t to) const;
    [[nodiscard]] std::span<const addr_t>
    indirect_edges_from(addr_t from) const noexcept;
    [[nodiscard]] std::size_t indirect_edge_count() const noexcept;
    void clear_indirect_edges() const noexcept;

private:
    // Lazy lookup caches. Built on first call to any of the lookup helpers
    // above; invalidated only by the loader during parse (which the base
    // class is not involved in — loaders should not call the lookup helpers
    // while they are still mutating symbols_).
    struct LookupCaches {
        std::unordered_map<std::string_view, const Symbol*> by_name;
        std::unordered_map<addr_t, const Symbol*>           import_by_got;
        // Sorted by addr; every element has is_import && addr != 0.
        std::vector<const Symbol*> imports_by_addr;
        // Sorted by addr; every element has !is_import && size != 0
        // && (kind == Function || kind == Object).
        std::vector<const Symbol*> defined_objects_by_addr;
    };
    mutable std::unique_ptr<LookupCaches> caches_;
    const LookupCaches& caches() const;

    // Side-channel populated by the trace-replay surface; deduped on
    // insertion. Never invalidated by symbol mutations (the oracle keys
    // off instruction VAs, not symbol identity).
    mutable std::unordered_map<addr_t, std::vector<addr_t>> indirect_edges_;
};

// Optional knobs for `load_binary`. Today only PE binaries care:
//
//   pdb_path : when non-empty, the loader skips its sidecar
//              auto-discovery (which scans the embedded CodeView name
//              and the conventional `<binary>.pdb` paths) and uses
//              this PDB instead. Useful for binaries built on a
//              different host where the embedded path is wrong.
//   no_pdb   : suppress PDB ingestion entirely. The binary still
//              loads with whatever names the PE / ELF carried; PDB
//              type information will not be available.
struct LoadOptions {
    std::filesystem::path pdb_path;
    bool                  no_pdb = false;
};

[[nodiscard]] Result<std::unique_ptr<Binary>>
load_binary(const std::filesystem::path& path);

[[nodiscard]] Result<std::unique_ptr<Binary>>
load_binary(const std::filesystem::path& path, const LoadOptions& opts);

}  // namespace ember
