#pragma once

#include <atomic>
#include <cstddef>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string_view>
#include <typeindex>
#include <typeinfo>
#include <unordered_map>
#include <utility>
#include <vector>

#include <spelunk/binary/arch.hpp>
#include <spelunk/binary/format.hpp>
#include <spelunk/binary/relocation.hpp>
#include <spelunk/binary/section.hpp>
#include <spelunk/binary/symbol.hpp>
#include <spelunk/common/annotations.hpp>
#include <spelunk/common/error.hpp>
#include <spelunk/common/types.hpp>

namespace spelunk {

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
    [[nodiscard]] virtual bool is_relocatable_object() const noexcept { return false; }

    // The virtual address the binary was *linked* to load at. Subtract
    // this from a symbol address to get the file-offset / RVA, then add
    // the runtime load base to get the slid runtime address. Default 0 -
    // appropriate for raw-region inputs and any
    // format that treats addresses as already-absolute.
    [[nodiscard]] virtual addr_t preferred_load_base() const noexcept { return 0; }

    // Total VA span the loader will consume when mapping the binary's
    // segments - i.e. max(seg.vaddr + seg.memsz) - preferred_load_base().
    // Used when linking loaded modules and overlays. Default 0 - formats
    // with segments override.
    [[nodiscard]] virtual addr_t mapped_size() const noexcept { return 0; }

    [[nodiscard]] virtual std::span<const Section> sections() const noexcept = 0;
    [[nodiscard]] virtual std::span<const Symbol>  symbols() const noexcept  = 0;

    // PowerPC EABI small-data anchor recovered from symbol metadata. DTK
    // names `.sdata`/`.sbss` through r13 and `.sdata2`/`.sbss2` through r2;
    // formats without that metadata leave these empty.
    [[nodiscard]] virtual std::optional<addr_t>
    ppc_small_data_base(bool read_only) const noexcept {
        (void)read_only;
        return std::nullopt;
    }

    [[nodiscard]] virtual std::span<const std::byte> image() const noexcept = 0;

    // Complete loader relocation evidence. Unlike relocated_qwords(), this
    // keeps instruction relocations, widths, symbols, and addends and is
    // therefore suitable for relocatable objects and target/candidate diffs.
    [[nodiscard]] virtual std::span<const Relocation>
    relocations() const noexcept { return {}; }

    // Loader-patched pointer slots known from format metadata, returned as
    // slot-VA -> absolute target VA. ELF models R_*_RELATIVE addends; PE
    // models DIR64 base relocations. Other formats return no evidence.
    [[nodiscard]] virtual std::map<addr_t, addr_t> relocated_qwords() const {
        return {};
    }

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
    // address within the stub's slot - typically 16 bytes on x86-64 - so
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

    // Invalidate the lookup caches and analysis memos. Loaders call this
    // when symbols_ changes after the initial parse() - e.g. when the PDB
    // sidecar ingestion pass adds names that the on-disk PE didn't carry.
    void invalidate_caches() const noexcept {
        {
            const std::lock_guard lock(caches_mutex_);
            caches_ready_.store(nullptr, std::memory_order_release);
            caches_.reset();
        }
        const std::lock_guard lock(analysis_memo_mutex_);
        analysis_memos_.clear();
    }

    // Per-image memo for analyses whose results depend only on the image
    // and its symbols, such as x86 per-function calling conventions. The
    // analysis defines the payload and guards its own contents; the binary
    // owns its lifetime and drops it with the lookup caches. Safe to call
    // from concurrent lifters, but not concurrently with a symbol change.
    struct AnalysisMemo {
        virtual ~AnalysisMemo() = default;
    };
    template <class T>
    [[nodiscard]] T& analysis_memo() const {
        const std::lock_guard lock(analysis_memo_mutex_);
        auto& slot = analysis_memos_[std::type_index(typeid(T))];
        if (!slot) slot = std::make_unique<T>();
        return static_cast<T&>(*slot);
    }

    // Add a synthetic Function symbol at `va`. Used by the
    // `--force-fn-start <VA>` CLI override to correct mis-attributed
    // function entries in obfuscated code where spelunk would otherwise
    // rebind to the closest-below symbol. No-op when a Function
    // symbol already exists at exactly `va`. The added symbol uses
    // the standard `sub_<hex>` synthetic name; users can rename via
    // `--annotations` afterwards. Requires the derived class to
    // expose its mutable symbol table via `mutable_symbols()`.
    void add_synthetic_function_start(addr_t va);

    // Add or upgrade a non-import Function symbol at `va` using a recovered
    // name. Existing real names win; synthetic `sub_<hex>` placeholders are
    // replaced. Returns true when the symbol table changed.
    bool add_inferred_function_name(addr_t va, std::string_view name);

    void add_debug_signature(addr_t va, const FunctionSig& signature) {
        debug_signatures_.try_emplace(va, signature);
    }
    [[nodiscard]] const std::map<addr_t, FunctionSig>&
    debug_signatures() const noexcept { return debug_signatures_; }
    [[nodiscard]] const Annotations& debug_types() const noexcept { return debug_types_; }
    void add_debug_types(Annotations types) { debug_types_ = std::move(types); }

    // Merge defined Function/Object symbols from a separate symbol-bearing
    // binary by linked-image offset. This covers split-debug companions such
    // as Mach-O dSYM files: a symbol at (overlay.base + X) names the primary
    // image address (primary.base + X). Existing primary names win unless the
    // current name is a synthetic `sub_<hex>` placeholder.
    std::size_t overlay_symbols_from(const Binary& overlay);

protected:
    // Mutable view of the derived class's symbol storage. Used only
    // by the small number of base-class methods that need to push
    // synthetic entries - the public `symbols()` accessor stays
    // const-only.
    [[nodiscard]] virtual std::vector<Symbol>& mutable_symbols() noexcept = 0;
    std::map<addr_t, FunctionSig> debug_signatures_;
    Annotations debug_types_;
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
    // - restart Spelunk and you start fresh.
    void record_indirect_edge(addr_t from, addr_t to) const;
    [[nodiscard]] std::span<const addr_t>
    indirect_edges_from(addr_t from) const noexcept;
    [[nodiscard]] std::size_t indirect_edge_count() const noexcept;

    // Runtime value facts from logs/traces. These overlay sparse qword values
    // not present in a static file view: singleton globals, object vptrs, or
    // relocated slots observed by instrumentation.
    void record_runtime_qword(addr_t at, u64 value) const;
    [[nodiscard]] std::optional<u64> runtime_qword_at(addr_t at) const noexcept;
    [[nodiscard]] std::size_t runtime_qword_count() const noexcept;

private:
    // Lazy lookup caches. Built on first call to any of the lookup helpers
    // above; invalidated only by the loader during parse (which the base
    // class is not involved in - loaders should not call the lookup helpers
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
    // Built on first use, possibly by concurrent emitters: `caches_ready_`
    // publishes the finished tables, `caches_mutex_` serializes building.
    mutable std::unique_ptr<LookupCaches> caches_;
    mutable std::atomic<const LookupCaches*> caches_ready_{nullptr};
    mutable std::mutex caches_mutex_;
    const LookupCaches& caches() const;

    // Side-channel populated by the trace-replay surface; deduped on
    // insertion. Never invalidated by symbol mutations (the oracle keys
    // off instruction VAs, not symbol identity).
    mutable std::unordered_map<addr_t, std::vector<addr_t>> indirect_edges_;
    mutable std::unordered_map<addr_t, u64> runtime_qwords_;

    mutable std::mutex analysis_memo_mutex_;
    mutable std::unordered_map<std::type_index, std::unique_ptr<AnalysisMemo>>
        analysis_memos_;
};

// Optional knobs for `load_binary`.
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
    // Exact decomp-toolkit symbols for a DOL or REL. DOL entries contain
    // absolute VAs; REL entries contain section-relative offsets.
    std::filesystem::path dol_symbols_path;
    // Standalone RELs default to a deterministic Wii-range address. A DTK
    // multi-module context assigns distinct bases to its peer modules.
    std::optional<addr_t>  rel_load_base;
    bool                  no_pdb = false;
};

[[nodiscard]] Result<std::unique_ptr<Binary>>
load_binary(const std::filesystem::path& path);

[[nodiscard]] Result<std::unique_ptr<Binary>>
load_binary(const std::filesystem::path& path, const LoadOptions& opts);

}  // namespace spelunk
