#include <spelunk/common/diagnostic.hpp>
#include "info.hpp"

#include <array>
#include <cstddef>
#include <print>
#include <string_view>

#include <spelunk/binary/arch.hpp>
#include <spelunk/binary/binary.hpp>
#include <spelunk/binary/format.hpp>
#include <spelunk/binary/section.hpp>
#include <spelunk/binary/symbol.hpp>

namespace spelunk::cli {

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

void print_info(const Binary& b, std::string_view path,
                std::size_t row_limit, bool verbose) {
    std::println("file    {}", path);
    std::println("format  {}", format_name(b.format()));
    std::println("arch    {}", arch_name(b.arch()));
    std::println("endian  {}", endian_name(b.endian()));
    std::println("entry   {:#018x}", b.entry_point());
    std::println("base    {:#018x}", b.preferred_load_base());
    if (const auto relocations = b.relocations(); !relocations.empty()) {
        std::size_t applied = 0;
        for (const auto& relocation : relocations) applied += relocation.applied;
        std::println("relocations (analysis image): {} applied, {} unapplied",
                     applied, relocations.size() - applied);
        std::size_t shown = 0;
        for (const auto& relocation : relocations) {
            if (relocation.applied) continue;
            if (!verbose && row_limit != 0 && shown >= row_limit) continue;
            std::println("  unapplied {:#x}: {} ({})", relocation.site,
                         relocation.type_name, relocation.symbol_name);
            ++shown;
        }
        if (shown < relocations.size() - applied)
            std::println("  ... {} more unapplied relocation(s)", relocations.size() - applied - shown);
    }

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
    std::size_t emitted_defined = 0;
    for (const auto& s : syms) {
        if (s.is_import) continue;
        if (!verbose && row_limit != 0 && emitted_defined >= row_limit) continue;
        std::println("  {:>#18x} {:>#8x}  {:<8}  {}",
                     s.addr, s.size, symbol_kind_name(s.kind), s.name);
        ++emitted_defined;
    }
    if (!verbose && row_limit != 0 && emitted_defined < n_defined) {
        std::println("  ... {} more defined symbol(s); pass --verbose or --row-limit 0 for all",
                     n_defined - emitted_defined);
    }

    std::println("");
    std::println("imports ({})", n_imports);
    std::println("  {:>10}  {:>12}  {:<8}  {}", "plt", "got", "kind", "name");
    std::size_t emitted_imports = 0;
    for (const auto& s : syms) {
        if (!s.is_import) continue;
        if (!verbose && row_limit != 0 && emitted_imports >= row_limit) continue;
        std::println("  {:>#10x}  {:>#12x}  {:<8}  {}",
                     s.addr, s.got_addr, symbol_kind_name(s.kind), s.name);
        ++emitted_imports;
    }
    if (!verbose && row_limit != 0 && emitted_imports < n_imports) {
        std::println("  ... {} more import(s); pass --verbose or --row-limit 0 for all",
                     n_imports - emitted_imports);
    }
}

namespace {

// One topic = one detailed section. Splitting print_help out by topic
// keeps the default `--help` legible (the surface spelunk exposes is
// big enough that a single dump no longer fits a screen) and gives
// scripts a stable token to ask about (`--help syms`).
void help_view() {
    std::println("View pipeline (each implies the earlier stages - `-p` runs everything):");
    std::println("  -d, --disasm         linear disassembly of a function");
    std::println("  -c, --cfg            CFG with asm-body blocks");
    std::println("      --cfg-pseudo     CFG with pseudo-C body blocks");
    std::println("  -i, --ir             lifted IR (per fn)");
    std::println("      --ssa            IR in SSA form (implies -i)");
    std::println("  -O, --opt            run cleanup passes (implies --ssa)");
    std::println("      --struct         structured regions (implies -O)");
    std::println("  -p, --pseudo         pseudo-C output (implies --struct)");
    std::println("      --emit-c         C export with declarations and explicit memory accesses");
    std::println("  -s, --symbol NAME    target a specific symbol (default: main)");
    std::println("      --symbols FILE   batch the selected view over one "
                 "symbol per line;");
    std::println("                       loads the binary/DTK project and "
                 "headers only once");
    std::println("      --labels         keep // bb_XXXX comments in pseudo-C output");
    std::println("      --show-provenance  emit `// confidence: ...` headers when annotation meta is set");
    std::println("      --disasm-at FN|VA  disasm a bounded window at FN or VA (default 32 insns)");
    std::println("                       includes trampoline steal/relocation metadata;");
    std::println("                       --json emits bytes, operands, targets, hazards");
    std::println("      --count N        instruction count for --disasm-at / --disasm-window");
    std::println("      --disasm-window VAs  batch form: comma-separated VAs or @PATH for");
    std::println("                       one-per-line input. Each block prefixed `# <hex-va>`;");
    std::println("                       --json returns an array of [addr, disasm] objects.");
    std::println("      --arities        dump inferred arity per function (addr N)");
    std::println("      --row-limit N    cap broad list/info rows (0 = all)");
    std::println("      --ppc-coverage   rank unsupported PPC words and opaque ppc.* lift fallbacks");
    std::println("                       --coverage-limit N caps rows (default 25, 0 = all); --json supported");
}

void help_syms() {
    std::println("Symbols, strings, packed string tables, callees, refs:");
    std::println("      --functions [P]  list every discovered fn (TSV); P is a substring filter.");
    std::println("                       Prefer --functions=P to avoid binary-vs-pattern ordering.");
    std::println("                       --row-limit N caps emitted rows for scripted use.");
    std::println("      --collisions     every name / fingerprint bound to >1 address (TSV/JSON)");
    std::println("      --validate NAME  every addr bound to NAME + byte-similar lookalikes");
    std::println("      --containing-fn FN|VA  entry/size/name/offset of the function covering VA");
    std::println("      --strings        printable strings (addr | text | xrefs)");
    std::println("      --surfaces       app/subsystem inventory (ScriptVM, network, media,");
    std::println("                       web auth, storage, analytics, crash/update, etc.);");
    std::println("                       Mach-O .app inputs also classify shipped bundle files");
    std::println("                       filters: --surface NAME, --surface-kind NAME,");
    std::println("                       --surface-category NAME, --surface-owner NAME,");
    std::println("                       --surface-row-type summary/category/owner/descriptor/artifact/function/evidence/all,");
    std::println("                       --surface-function VA; reflection_descriptor rows included");
    std::println("                       for C++ reflection metadata; --json supported");
    std::println("      --graphics       graphics backend/API/proc-loader inventory with domains");
    std::println("                       (OpenGL/Vulkan/SDL/Metal/GLSL/SPIR-V); --json supported");
    std::println("                       filters: --graphics-backend NAME, --graphics-domain NAME,");
    std::println("                       --graphics-api NAME (case-insensitive substring),");
    std::println("                       --graphics-extension NAME (ARB/EXT/KHR/etc.),");
    std::println("                       --graphics-category NAME (api_proc_name/constant_name/etc.),");
    std::println("                       --graphics-role NAME, --graphics-row-type NAME");
    std::println("                       (summary/api/extension/function/symbol/string),");
    std::println("                       --graphics-function VA");
    std::println("      --log-categories cluster bracketed log categories by referencing functions");
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
    std::println("      --refs-to FN|VA  callers of FN or VA (one-shot reverse xref)");
    std::println("      --callees VA     direct/tail/indirect_const callees of the fn at VA");
    std::println("      --callees-class NAME  JSON {{slot_N: [callees]}} for every vfn of an RTTI class");
    std::println("      --json           machine-readable output where supported");
}

void help_xrefs() {
    std::println("Cross-references and indirect-edge oracle:");
    std::println("  -X, --xrefs          full call graph (all fn -> call targets)");
    std::println("      --data-xrefs     TSV <target>\\t<site>\\t<kind> for every rip-rel / abs");
    std::println("                       data-section reference (kind = read/write/lea)");
    std::println("      --refs-to FN|VA  target-only callers/code-ptr/lea for one FN or VA");
    std::println("                       --access read|write|lea|code-ptr|all filters data refs");
    std::println("      --refs-to-loose FN|VA  superset: also scans constant-pool imm64s and");
    std::println("                       R_*_RELATIVE relocs whose addend == VA, recovering");
    std::println("                       fn-pointer-only dispatch shapes");
    std::println("      --state-map VA   target-only read/write/lea map for one state/global");
    std::println("      --branch-on VA   reads of one state/global that reach conditional branches");
    std::println("      --guard-map FN   conditional branches and nearby guard conditions in one fn");
    std::println("      --state-lifetime VA  writers/readers/branch-gates story for one state/global");
    std::println("      --side-effects FN  writes, calls, and return behavior for one function");
    std::println("      --object-roles FN  infer direct this+offset field roles in one function");
    std::println("      --explain-address VA  fast orientation summary for code/data/pointer/state");
    std::println("      --patch-plan VA  hook/trampoline safety plan for a code address");
    std::println("      --explain-vcall OBJ:OFF  resolve object vptr slot to target summary");
    std::println("      --dump-object ADDR --size N  classify pointer-sized object fields");
    std::println("      --verbose        with --refs-to/--refs-to-loose, append site disasm");
    std::println("      --trace PATH     load runtime facts: `from to`, `indirect from to`,");
    std::println("                       `qword addr value`, or `object addr vtable`");
}

void help_ana() {
    std::println("Analysis passes / library-fn recognition / runtime call shapes:");
    std::println("      --ipa            interprocedural char*-arg propagation (run before -p/--struct)");
    std::println("      --resolve-calls  global indirect-call resolver (vtable dispatch -> named call)");
    std::println("      --eh             parse __eh_frame + LSDA; mark landing pads");
    std::println("      --rtti           dump C++ RTTI: Itanium/MSVC classes + vtables + IMPs");
    std::println("      --vtables        dump runtime pointer-dense vtables from data/RELRO");
    std::println("      --vtable-at VA [--limit N]  narrow runtime vtable view around VA");
    std::println("      --objc-names     Obj-C runtime methods as TSV (imp ± class selector sig)");
    std::println("      --objc-protocols Obj-C protocol method signatures");
    std::println("      --objc-surfaces  Obj-C class/category protocol implementation surface");
    std::println("      --int3-resolve   classify embedded int3 bytes (handler / pad / dead)");
    std::println("      --identify       YARA-like crypto/protocol identifier");
    std::println("      --identify-threshold T  confidence floor (default 0.4)");
    std::println("      --pat PATH       repeatable; FLIRT-style .pat sig file");
    std::println("      --list-syscalls VA  walk fn @ VA, report each `syscall` site as TSV");
    std::println("                       (file_offset, va, nr, name). Linux x86-64.");
    std::println("      --forge-spec ENTRY:VA  minimum struct/branch shape required to reach VA");
    std::println("                       from ENTRY; --json for machine form");
}

void help_fingerprints() {
    std::println("Fingerprints / cross-binary diff:");
    std::println("      --fingerprints   address-independent content hash per fn");
    std::println("      --min-fn-size N  drop fns smaller than N bytes before fingerprinting");
    std::println("      --max-fn-size N  drop fns larger than N bytes");
    std::println("      --diff OLD       diff OLD vs the positional binary by fingerprint");
    std::println("      --diff-format    'tsv' (default) or 'json'");
    std::println("      --fingerprint-out P  also write --fingerprints TSV to P");
    std::println("      --fingerprint-old P  read OLD-side TSV from P (skip OLD compute in --diff)");
    std::println("      --fingerprint-new P  read NEW-side TSV from P");
}

void help_ann() {
    std::println("Annotations:");
    std::println("      --annotate ADDR  append one annotation to the resolved file. Companion");
    std::println("                       flags: --set-name NEW / --set-note TEXT / --set-signature DECL,");
    std::println("                       optionally --confidence FLOAT / --evidence TEXT / --source TAG");
    std::println("                       (default `cli`). Pair with --dry-run to preview.");
    std::println("      --dry-run        with --annotate: dump the would-be TSV to stdout, don't write");
    std::println("      --list-annotations  dump every record in the resolved annotations file");
    std::println("                       (rename / note / signature) with its meta");
    std::println("      --annotations P  explicit project file (overrides the sidecar/cache auto-load)");
    std::println("      --export-annotations P  copy the currently-resolved annotations file to P");
    std::println("      --show-provenance  emit `// confidence: ...` headers under -p");
}

void help_load() {
    std::println("Loading non-default inputs / non-default function-entry hints:");
    std::println("      --dtk PROJECT    load the main object and exact symbols from a DTK project");
    std::println("      --dtk-version ID select config/<ID>/config.yml inside the project");
    std::println("      --dtk-module NAME load a named REL and link its configured peers");
    std::println("      --pdb PATH       use this PDB instead of auto-discovering one (PE only)");
    std::println("      --dsym PATH      overlay symbols from a Mach-O dSYM file or .dSYM bundle");
    std::println("      --infer-string-names  synthesize names from strong log/string anchors");
    std::println("      --no-pdb         skip PDB sidecar discovery / ingestion entirely");
    std::println("      --regions PATH   load via a raw-region manifest (Scylla-style scrape)");
    std::println("                       - see docs/raw-input.md for the manifest format");
    std::println("      --raw-bytes PATH  load PATH as a single rwx region at --base-va; no PE");
    std::println("                       container, useful for runtime memory captures");
    std::println("      --base-va 0xVA   required with --raw-bytes; base virtual address");
    std::println("      --recover-imports  rebuild the IAT (slot -> dll!func) for a capture with no");
    std::println("                       import directory; needs --dll-dir DIR and/or --dll PATH");
    std::println("                       reference DLLs. --json emits a slot-RVA->name manifest.");
    std::println("                       --image-base 0xVA sets the RVA key base (default: image base)");
    std::println("      --force-fn-start 0xVA  repeatable; treat VA as a function entry. Use when");
    std::println("                       obfuscator-merged / mid-body real entries cause spelunk to");
    std::println("                       silently rebind to a closest-below symbol.");
    std::println("      --module NAME    scope fn iteration to one loaded module (minidumps,");
    std::println("                       multi-module containers). Affects --functions.");
    std::println("                       Out-of-scope addresses are skipped before lifting.");
}

void help_data() {
    std::println("Typed source recovery (especially useful with DTK/Wii projects):");
    std::println("      --headers PATH   import C/C++ prototypes, records, fields, globals,");
    std::println("                       arrays, and enums through libclang; repeatable");
    std::println("      --header-arg ARG pass an extra parser option such as -I/path; repeatable");
    std::println("      --decompile-data SYMBOL --type TYPE");
    std::println("                       emit a typed C initializer. Loader relocations name");
    std::println("                       pointers, callbacks, strings, and nested records");
    std::println("      --evt-script SYMBOL");
    std::println("                       decode an SPM EvtScriptCode array into EVT macros,");
    std::println("                       structured indentation, variables, and callbacks");
    std::println("                       (plain text only; --json emits a warning)");
    std::println("      --verify-roundtrip  with typed data/event decoding, "
                 "verify that the");
    std::println("                       decoded representation reproduces "
                 "bytes/relocations");
}

void help_patch() {
    std::println("Byte patching:");
    std::println("      --apply-patches FILE  apply byte patches (vaddr_hex bytes_hex per line)");
    std::println("  -o, --output PATH    output path (required with --apply-patches)");
}

void help_cache() {
    std::println("Disk cache:");
    std::println("      --cache-dir DIR  override $XDG_CACHE_HOME/spelunk for disk cache");
    std::println("      --no-cache       bypass disk cache (--xrefs / --strings / --arities /");
    std::println("                       --fingerprints). Cache key = abspath|size|mtime|kVersion;");
    std::println("                       --module is folded into the key so per-module runs don't");
    std::println("                       collide.");
}

}  // namespace

void print_help() {
    std::println("usage: spelunk [view-flag] [-s NAME] <binary>");
    std::println("       spelunk [view-flag] --dtk <project> [--dtk-version ID] [-s NAME]");
    std::println("       spelunk --help <topic>");
    std::println("");
    std::println("View pipeline:");
    std::println("  -d  -c  --cfg-pseudo  -i  --ssa  -O  --struct  -p  [-s NAME]");
    std::println("");
    std::println("Topics:");
    std::println("  view     decompile / disasm / IR / pseudo-C / disasm windows");
    std::println("  syms     functions, strings, symtable, symuses, symresolve,");
    std::println("           refs-to, callees, validate, collisions");
    std::println("  xrefs    --xrefs, --data-xrefs, --refs-to, --refs-to-loose, --trace");
    std::println("  ana      ipa, eh, rtti, objc, identify, resolve-calls,");
    std::println("           int3, syscalls, forge-spec, FLIRT");
    std::println("  fingerprints  content hashes, diff");
    std::println("  ann      annotate, list-annotations, dry-run");
    std::println("  load     DTK projects, pdb, regions, raw-bytes, force-fn-start, module");
    std::println("  data     Clang headers, typed initializers, SPM event scripts");
    std::println("  patch    --apply-patches");
    std::println("  cache    --cache-dir, --no-cache");
    std::println("");
    std::println("Common:  --json  -q/--quiet  -h/--help  --version");
    std::println("");
    std::println("Get topic detail:  spelunk --help <topic>   (or --help=<topic>)");
}

void print_help_topic(std::string_view topic) {
    if      (topic == "view")  { help_view();  return; }
    else if (topic == "syms")  { help_syms();  return; }
    else if (topic == "xrefs") { help_xrefs(); return; }
    else if (topic == "ana")   { help_ana();   return; }
    else if (topic == "fingerprints")  { help_fingerprints();  return; }
    else if (topic == "ann")   { help_ann();   return; }
    else if (topic == "load")  { help_load();  return; }
    else if (topic == "data")  { help_data();  return; }
    else if (topic == "patch") { help_patch(); return; }
    else if (topic == "cache") { help_cache(); return; }
    // Unknown topics are an error, not a help request: report the bad
    // topic and point at the full banner instead of dumping it (the
    // topic list itself lives in `spelunk --help`).
    spelunk::diagnostic::print("spelunk: --help: unknown topic '{}'", topic);
    spelunk::diagnostic::print("run 'spelunk --help' for full usage");
}

}  // namespace spelunk::cli
