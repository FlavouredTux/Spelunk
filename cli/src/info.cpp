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
    std::println("base    {:#018x}", b.preferred_load_base());

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

namespace {

// One topic = one detailed section. Splitting print_help out by topic
// keeps the default `--help` legible (the surface ember exposes is
// big enough that a single dump no longer fits a screen) and gives
// LLM agents a stable token to ask about (`--help syms`).
void help_view() {
    std::println("View pipeline (each implies the earlier stages — `-p` runs everything):");
    std::println("  -d, --disasm         linear disassembly of a function");
    std::println("  -c, --cfg            CFG with asm-body blocks");
    std::println("      --cfg-pseudo     CFG with pseudo-C body blocks");
    std::println("  -i, --ir             lifted IR (per fn)");
    std::println("      --ssa            IR in SSA form (implies -i)");
    std::println("  -O, --opt            run cleanup passes (implies --ssa)");
    std::println("      --struct         structured regions (implies -O)");
    std::println("  -p, --pseudo         pseudo-C output (implies --struct)");
    std::println("  -s, --symbol NAME    target a specific symbol (default: main)");
    std::println("      --labels         keep // bb_XXXX comments in pseudo-C output");
    std::println("      --show-provenance  emit `// confidence: ...` headers when annotation meta is set");
    std::println("      --disasm-at VA   disasm a bounded window at VA (default 32 insns)");
    std::println("      --count N        instruction count for --disasm-at / --disasm-window");
    std::println("      --disasm-window VAs  batch form: comma-separated VAs or @PATH for");
    std::println("                       one-per-line input. Each block prefixed `# <hex-va>`;");
    std::println("                       --json returns an array of [addr, disasm] objects.");
    std::println("      --arities        dump inferred arity per function (addr N)");
}

void help_syms() {
    std::println("Symbols, strings, packed string tables, callees, refs:");
    std::println("      --functions [P]  list every discovered fn (TSV); P is a substring filter.");
    std::println("                       Prefer --functions=P to avoid binary-vs-pattern ordering.");
    std::println("      --collisions     every name / fingerprint bound to >1 address (TSV/JSON)");
    std::println("      --validate NAME  every addr bound to NAME + byte-similar lookalikes");
    std::println("      --containing-fn VA  entry/size/name/offset of the function covering VA");
    std::println("      --strings        printable strings (addr | text | xrefs)");
    std::println("      --symtable VA    walk a packed NUL-terminated string table at VA. TSV");
    std::println("                       <va>\\t<offset>\\t<len>\\t<string>; stops on 4+ NUL run,");
    std::println("                       non-printable byte, segment end, or 1 MB cap. Emits a");
    std::println("                       `# categories:` keyword summary block on dlsym-shaped tables.");
    std::println("      --symuses VA     per-fn refs into the table at VA. Default TSV:");
    std::println("                       fn_va\\tn_uses\\tsymbols. Picks up direct");
    std::println("                       `lea reg, [rip+entry]`, imm64-stored slots, and");
    std::println("                       base+offset shapes (the lazy / per-fn dlsym pattern).");
    std::println("                       Loose-scope candidates run through a register-taint");
    std::println("                       walker so unrelated `add reg, IMM` operations don't");
    std::println("                       light up entries whose offsets match common constants.");
    std::println("                       --verbose for per-callsite rows. --filter cat,... /");
    std::println("                       --min-uses N / --show-empty / --no-taint (drop taint).");
    std::println("      --symresolve VA  pair the string table with its fnptr table. Iteratively");
    std::println("                       finds resolver functions (longest stride-8 write run);");
    std::println("                       merged TSV: idx, str_va, symbol, fnptr_va, n_callsites,");
    std::println("                       top_callsites. --filter cat,... / --max-callsites N (default 5).");
    std::println("      --refs-to VA     callers of VA (one-shot reverse xref)");
    std::println("      --callees VA     direct/tail/indirect_const callees of the fn at VA");
    std::println("      --callees-class NAME  JSON {{slot_N: [callees]}} for every vfn of an RTTI class");
    std::println("      --json           machine-readable output where supported");
}

void help_xrefs() {
    std::println("Cross-references and indirect-edge oracle:");
    std::println("  -X, --xrefs          full call graph (all fn -> call targets)");
    std::println("      --data-xrefs     TSV <target>\\t<site>\\t<kind> for every rip-rel / abs");
    std::println("                       data-section reference (kind = read/write/lea)");
    std::println("      --refs-to VA     callers of VA (cached)");
    std::println("      --refs-to-loose VA  superset: also scans constant-pool imm64s and");
    std::println("                       R_*_RELATIVE relocs whose addend == VA, recovering");
    std::println("                       fn-pointer-only dispatch shapes (Roblox-style)");
    std::println("      --verbose        with --refs-to/--refs-to-loose, append site disasm");
    std::println("      --trace PATH     load indirect-edge trace (TSV from\\tto per line)");
    std::println("                       — seeds the CFG builder before any analysis runs");
}

void help_ana() {
    std::println("Analysis passes / library-fn recognition / runtime call shapes:");
    std::println("      --ipa            interprocedural char*-arg propagation (run before -p/--struct)");
    std::println("      --resolve-calls  global indirect-call resolver (vtable dispatch -> named call)");
    std::println("      --eh             parse __eh_frame + LSDA; mark landing pads");
    std::println("      --rtti           dump Itanium C++ RTTI: classes + vtables + IMPs");
    std::println("      --objc-names     Obj-C runtime methods as TSV (imp ± class selector sig)");
    std::println("      --objc-protocols Obj-C protocol method signatures");
    std::println("      --int3-resolve   classify embedded int3 bytes (handler / pad / dead)");
    std::println("      --identify       YARA-like crypto/protocol identifier");
    std::println("      --identify-threshold T  confidence floor (default 0.4)");
    std::println("      --recognize      library-function recognition against --corpus");
    std::println("      --recognize-threshold T  margin floor (default 0.6)");
    std::println("      --corpus PATH    repeatable; TEEF TSV (output of `ember --teef <lib>`)");
    std::println("      --anti-corpus PATH  repeatable; queries matching any blocked hash short-");
    std::println("                       circuit. Use for UPX prologues / packer trampolines / CRT.");
    std::println("      --pat PATH       repeatable; FLIRT-style .pat sig file");
    std::println("      --list-syscalls VA  walk fn @ VA, report each `syscall` site as TSV");
    std::println("                       (file_offset, va, nr, name). Linux x86-64.");
    std::println("      --forge-spec ENTRY:VA  minimum struct/branch shape required to reach VA");
    std::println("                       from ENTRY; --json for machine form");
}

void help_teef() {
    std::println("TEEF / fingerprints / cross-binary diff:");
    std::println("      --fingerprints   address-independent content hash per fn");
    std::println("      --teef           Tree-Edit Equivalence Fingerprint per fn");
    std::println("      --teef-no-l4     skip behavioral L4 (faster/lower-RAM corpus build)");
    std::println("      --orbit-dump     side-by-side diagnostic of all per-fn signatures");
    std::println("      --diff OLD       diff OLD vs the positional binary by fingerprint");
    std::println("      --diff-format    'tsv' (default) or 'json'");
    std::println("      --fingerprint-out P  also write --fingerprints TSV to P");
    std::println("      --fingerprint-old P  read OLD-side TSV from P (skip OLD compute in --diff)");
    std::println("      --fingerprint-new P  read NEW-side TSV from P");
    std::println("      --l0-prefilter   in --recognize, skip K=64 L4 traces on fns whose L0");
    std::println("                       topology hash isn't represented in the corpus");
    std::println("      --min-fn-size N  drop fns smaller than N bytes before fingerprinting");
    std::println("      --max-fn-size N  drop fns larger than N bytes");
    std::println("      --max-cfg-blocks N / --max-cfg-edges N / --max-cfg-insts N");
    std::println("                       skip fns above the cap (0 = disabled)");
    std::println("      --max-ir-insts N  override post-lift IR inst cap");
}

void help_ann() {
    std::println("Annotations / .ember scripts:");
    std::println("      --annotate ADDR  append one annotation to the resolved file. Companion");
    std::println("                       flags: --set-name NEW / --set-note TEXT / --set-signature DECL,");
    std::println("                       optionally --confidence FLOAT / --evidence TEXT / --source TAG");
    std::println("                       (default `cli`). Pair with --dry-run to preview.");
    std::println("      --apply PATH     apply a declarative .ember script (renames, sigs, notes,");
    std::println("                       constants, pattern-renames, log-format renames, deletes)");
    std::println("      --dry-run        with --apply: dump the would-be TSV to stdout, don't write");
    std::println("      --list-annotations  dump every record in the resolved annotations file");
    std::println("                       (rename / note / signature) with its meta");
    std::println("      --annotations P  explicit project file (overrides the sidecar/cache auto-load)");
    std::println("      --export-annotations P  copy the currently-resolved annotations file to P");
    std::println("      --show-provenance  emit `// confidence: ...` headers under -p");
}

void help_dbg() {
    std::println("Interactive modes (debugger + agent daemon):");
    std::println("      --debug          launch under the built-in REPL debugger (uses ember's");
    std::println("                       pseudo-C as the source view; no DWARF). Linux ptrace");
    std::println("                       backend by default; macOS uses Mach.");
    std::println("      --attach-pid PID  attach to a running process instead of launching");
    std::println("      --debug-backend  ptrace (default), perf (HW BP/WP only, sets TracerPid=0),");
    std::println("                       or auto (try perf, fall back to ptrace)");
    std::println("      --aux-binary PATH[@HEX]  repeatable; secondary Binary as a symbol oracle");
    std::println("                       for non-ELF code regions in the tracee");
    std::println("      --ignore-fault-at HEX / --ignore-fault-file PATH  repeatable; static VAs");
    std::println("                       where SIGSEGV/SIGBUS/SIGFPE/SIGILL is recovered by the");
    std::println("                       tracee's own handler (silently forwarded back)");
    std::println("      -- ARG...        sentinel; remaining tokens are argv for the launched program");
    std::println("      --serve          long-lived daemon: read JSON-line tool requests on stdin,");
    std::println("                       reply on stdout. Binary loaded once across calls.");
}

void help_load() {
    std::println("Loading non-default inputs / non-default function-entry hints:");
    std::println("      --pdb PATH       use this PDB instead of auto-discovering one (PE only)");
    std::println("      --no-pdb         skip PDB sidecar discovery / ingestion entirely");
    std::println("      --regions PATH   load via a raw-region manifest (Scylla-style scrape)");
    std::println("                       — see docs/raw-input.md for the manifest format");
    std::println("      --raw-bytes PATH  load PATH as a single rwx region at --base-va; no PE");
    std::println("                       container, useful for runtime memory captures");
    std::println("      --base-va 0xVA   required with --raw-bytes; base virtual address");
    std::println("      --force-fn-start 0xVA  repeatable; treat VA as a function entry. Use when");
    std::println("                       obfuscator-merged / mid-body real entries cause ember to");
    std::println("                       silently rebind to a closest-below symbol.");
    std::println("      --module NAME    scope fn iteration to one loaded module (minidumps,");
    std::println("                       multi-module containers). Affects --functions, --recognize,");
    std::println("                       --serve fanout. Out-of-scope addresses skipped before lift.");
}

void help_patch() {
    std::println("Byte patching:");
    std::println("      --apply-patches FILE  apply byte patches (vaddr_hex bytes_hex per line)");
    std::println("  -o, --output PATH    output path (required with --apply-patches)");
}

void help_cache() {
    std::println("Disk cache:");
    std::println("      --cache-dir DIR  override $XDG_CACHE_HOME/ember for disk cache");
    std::println("      --no-cache       bypass disk cache (--xrefs / --strings / --arities /");
    std::println("                       --fingerprints). Cache key = abspath|size|mtime|kVersion;");
    std::println("                       --module is folded into the key so per-module runs don't");
    std::println("                       collide.");
}

}  // namespace

void print_help() {
    std::println("usage: ember [view-flag] [-s NAME] <binary>");
    std::println("       ember --help <topic>");
    std::println("");
    std::println("View pipeline:");
    std::println("  -d  -c  --cfg-pseudo  -i  --ssa  -O  --struct  -p  [-s NAME]");
    std::println("");
    std::println("Topics:");
    std::println("  view     decompile / disasm / IR / pseudo-C / disasm windows");
    std::println("  syms     functions, strings, symtable, symuses, symresolve,");
    std::println("           refs-to, callees, validate, collisions");
    std::println("  xrefs    --xrefs, --data-xrefs, --refs-to, --refs-to-loose, --trace");
    std::println("  ana      ipa, eh, rtti, objc, identify, recognize, resolve-calls,");
    std::println("           int3, syscalls, forge-spec, FLIRT");
    std::println("  teef     fingerprints, teef, recognize, diff, orbit-dump,");
    std::println("           corpus, size caps");
    std::println("  ann      annotate, apply, list-annotations, dry-run, .ember scripts");
    std::println("  dbg      --debug, attach, backends, aux-bin, --serve");
    std::println("  load     pdb, regions, raw-bytes, base-va, force-fn-start, module");
    std::println("  patch    --apply-patches");
    std::println("  cache    --cache-dir, --no-cache");
    std::println("");
    std::println("Common:  --json  -q/--quiet  -h/--help");
    std::println("");
    std::println("Get topic detail:  ember --help <topic>   (or --help=<topic>)");
}

void print_help_topic(std::string_view topic) {
    if      (topic == "view")  { help_view();  return; }
    else if (topic == "syms")  { help_syms();  return; }
    else if (topic == "xrefs") { help_xrefs(); return; }
    else if (topic == "ana")   { help_ana();   return; }
    else if (topic == "teef")  { help_teef();  return; }
    else if (topic == "ann")   { help_ann();   return; }
    else if (topic == "dbg")   { help_dbg();   return; }
    else if (topic == "load")  { help_load();  return; }
    else if (topic == "patch") { help_patch(); return; }
    else if (topic == "cache") { help_cache(); return; }
    std::println(stderr, "ember: --help: unknown topic '{}'", topic);
    print_help();
}

}  // namespace ember::cli
