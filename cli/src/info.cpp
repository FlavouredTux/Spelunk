#include "info.hpp"

#include <array>
#include <cstddef>
#include <print>
#include <string_view>

#include <ember/binary/binary.hpp>

namespace ember::cli {

namespace {

[[nodiscard]] constexpr std::string_view flag_str(SectionFlags f) noexcept {
    constexpr std::array<std::string_view, 8> table = {
        "---", "r--", "-w-", "rw-",
        "--x", "r-x", "-wx", "rwx",
    };
    const unsigned idx =
        (f.readable   ? 0b0001u : 0u) |
        (f.writable   ? 0b0010u : 0u) |
        (f.executable ? 0b0100u : 0u);
    return table[idx & 0x7];
}

}  // namespace

void print_info(const Binary& b, std::string_view path) {
    std::println("file    {}", path);
    std::println("format  {}", format_name(b.format()));
    std::println("arch    {}", arch_name(b.arch()));
    std::println("endian  {}", endian_name(b.endian()));
    std::println("entry   {:#018x}", b.entry_point());

    const auto secs = b.sections();
    std::println("");
    std::println("sections ({})", secs.size());
    std::println("  {:>3}  {:<24} {:>18} {:>10}  {}", "idx", "name", "vaddr", "size", "flags");
    std::size_t i = 0;
    for (const auto& s : secs) {
        std::println("  {:>3}  {:<24} {:>#18x} {:>#10x}  {}",
                     i++, s.name, s.vaddr, s.size, flag_str(s.flags));
    }

    const auto syms = b.symbols();
    std::size_t n_defined = 0;
    std::size_t n_imports = 0;
    for (const auto& s : syms) (s.is_import ? n_imports : n_defined)++;

    std::println("");
    std::println("defined symbols ({})", n_defined);
    std::println("  {:>18} {:>8}  {:<8}  {}", "addr", "size", "kind", "name");
    for (const auto& s : syms) {
        if (s.is_import) continue;
        std::println("  {:>#18x} {:>#8x}  {:<8}  {}",
                     s.addr, s.size, symbol_kind_name(s.kind), s.name);
    }

    std::println("");
    std::println("imports ({})", n_imports);
    std::println("  {:>10}  {:>12}  {:<8}  {}", "plt", "got", "kind", "name");
    for (const auto& s : syms) {
        if (!s.is_import) continue;
        std::println("  {:>#10x}  {:>#12x}  {:<8}  {}",
                     s.addr, s.got_addr, symbol_kind_name(s.kind), s.name);
    }
}

void print_help() {
    std::println("usage: ember [-d|-c|-i|--ssa|-O|--struct|-p] [-s SYMBOL] <binary>");
    std::println("");
    std::println("  -d, --disasm         linear disassembly of a function");
    std::println("  -c, --cfg            control-flow graph of a function (asm bodies)");
    std::println("      --cfg-pseudo     control-flow graph of a function (pseudo-C bodies)");
    std::println("  -i, --ir             lifted IR of a function");
    std::println("      --ssa            IR in SSA form (implies -i)");
    std::println("  -O, --opt            run cleanup passes (implies --ssa)");
    std::println("      --struct         structured regions (implies -O)");
    std::println("  -p, --pseudo         pseudo-C output (implies --struct)");
    std::println("  -X, --xrefs          emit full call graph (all fn -> call targets)");
    std::println("      --strings        dump printable strings (addr|text|xrefs)");
    std::println("      --arities        dump inferred arity per function (addr N)");
    std::println("      --functions [P]  list every discovered function (symbols ∪ sub_*) as TSV;");
    std::println("                       optional substring P filters by name (case-insensitive).");
    std::println("                       Prefer --functions=P to avoid positional-order ambiguity");
    std::println("                       with the binary path.");
    std::println("      --fingerprints   dump address-independent content hash per function");
    std::println("      --diff OLD       diff OLD binary vs the positional binary by fingerprint");
    std::println("      --diff-format    'tsv' (default) or 'json' for --diff output");
    std::println("      --fingerprint-out P  also write --fingerprints TSV to P (portable across machines)");
    std::println("      --fingerprint-old P  skip OLD-side fingerprint compute in --diff; read TSV from P");
    std::println("      --fingerprint-new P  skip NEW-side fingerprint compute in --diff; read TSV from P");
    std::println("      --refs-to VA     list callers of VA (one-shot reverse xref)");
    std::println("      --data-xrefs     TSV: <target>\\t<site>\\t<kind> for every rip-rel/abs");
    std::println("                       data-section reference (kind=read/write/lea)");
    std::println("      --callees VA     list direct/tail/indirect_const callees of the function at VA");
    std::println("      --containing-fn VA  entry/size/name/offset of the function covering VA (TSV/JSON)");
    std::println("      --validate NAME  list every addr bound to NAME + byte-similar lookalikes (TSV/JSON)");
    std::println("      --collisions     dump every name and fingerprint bound to >1 address (TSV/JSON)");
    std::println("      --callees-class NAME  JSON: {{slot_N: [callees]}} for every vfn of an RTTI class");
    std::println("      --json           machine-readable output for --callees / --callees-class");
    std::println("      --disasm-at VA   disasm a bounded window at VA (default 32 insns; --count N to override)");
    std::println("      --ipa            run interprocedural char*-arg propagation before -p/--struct");
    std::println("      --eh             parse __eh_frame + LSDA; annotate landing-pad blocks");
    std::println("      --objc-names     dump recovered Obj-C methods as TSV (imp, ±, class, selector, sig)");
    std::println("      --objc-protocols dump Obj-C protocol method signatures");
    std::println("      --rtti           dump Itanium C++ RTTI: classes + vtables + IMPs");
    std::println("      --vm-detect      scan for interpreter-style VM dispatchers (TSV)");
    std::println("  -s, --symbol NAME    target a specific symbol (default: main)");
    std::println("      --annotations P  explicit project file with renames/signatures (overrides");
    std::println("                       the sidecar/cache auto-load)");
    std::println("      --export-annotations P  copy the currently-resolved annotations file to P");
    std::println("      --trace PATH     load indirect-edge trace (TSV: from\\tto per line)");
    std::println("      --labels         keep // bb_XXXX comments in pseudo-C output");
    std::println("      --project PATH   project file scripts may read/write via project.*");
    std::println("      --script PATH    run a JavaScript file against the loaded binary");
    std::println("      -- ARG...        pass remaining args to the script as argv");
    std::println("      --cache-dir DIR  override ~/.cache/ember for disk cache");
    std::println("      --no-cache       bypass the disk cache (--xrefs/strings/arities)");
    std::println("      --apply PATH     apply a declarative .ember script (renames, sigs, notes,");
    std::println("                       pattern-renames, log-format-driven renames, deletes) to");
    std::println("                       the resolved annotation file");
    std::println("      --dry-run        with --apply: don't write the result; dump the would-be");
    std::println("                       annotation TSV to stdout instead");
    std::println("      --apply-patches FILE  apply byte patches (vaddr_hex bytes_hex per line)");
    std::println("  -o, --output PATH    output path (required with --apply-patches)");
    std::println("  -q, --quiet          suppress stderr progress output");
    std::println("  -h, --help           show this help");
}

}  // namespace ember::cli
