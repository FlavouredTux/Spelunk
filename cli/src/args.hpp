#pragma once

#include <string>
#include <vector>

#include <spelunk/common/error.hpp>
#include <spelunk/common/types.hpp>

namespace spelunk::cli {

struct Args {
    std::string binary;
    std::string dtk_project_path;   // --dtk PATH: project root or version config
    std::string dtk_version;        // --dtk-version ID: config/<ID>/config.yml
    std::string dtk_module;         // --dtk-module NAME: select a REL/module entry
    std::string dtk_symbols_path;   // resolved internally from the DTK config
    std::vector<std::string> header_paths; // --headers PATH (repeatable): Clang C/C++ type overlay
    std::vector<std::string> header_args;  // --header-arg ARG (repeatable): extra Clang parse option
    std::string decompile_data;     // --decompile-data SYMBOL/VA: typed C initializer
    std::string data_type;          // --type TYPE: type used by --decompile-data
    std::string evt_script;         // --evt-script SYMBOL/VA: decode an SPM EvtScriptCode array
    std::string symbol;
    std::string
        symbols_path; // --symbols FILE: batch view targets, one symbol per line
    std::string annotations_path;   // --annotations PATH: explicit project file with renames/sigs/notes
    std::string export_annotations; // --export-annotations PATH: promote resolved source to PATH and exit
    std::string trace_path;         // optional indirect-edge trace TSV (from\tto per line)
    std::string cache_dir;          // override for the disk cache location
    std::string diff_path;          // --diff OLD: compare this older binary against args.binary
    std::string diff_format;        // --diff-format: "tsv" (default) or "json"
    std::string fp_out;             // --fingerprint-out PATH: also write fingerprints TSV here
    std::string fp_old_in;          // --fingerprint-old PATH: read OLD side fingerprints from PATH
    std::string fp_new_in;          // --fingerprint-new PATH: read NEW side fingerprints from PATH
    std::string symtable;           // --symtable VA: dump packed NUL-terminated string table at VA
    std::string symresolve;         // --symresolve VA: pair string table with fnptr table + callsites
    std::string symuses;            // --symuses VA: per-function references into the string table at VA
    std::string category_filter;    // --filter cat1,cat2,...: shared by --symresolve / --symuses; limits
                                    // rows / sites to symbols falling in the named categorize_symtable buckets
    spelunk::u64  symresolve_max_callsites = 5;  // --max-callsites N: cap top_callsites column (0 = unlimited)
    spelunk::u64  symuses_min_uses    = 1;   // --min-uses N: drop --symuses rows below N uses
    spelunk::u64  vtable_limit        = 16;  // --limit N: slot cap for --vtable-at (0 = all)
    spelunk::u64  row_limit           = 0;   // --row-limit N: cap broad list/info output (0 = all)
    bool        row_limit_set       = false;
    bool        symuses_show_empty  = false;  // --show-empty: emit --symuses rows with 0 post-filter uses
    bool        symuses_no_taint    = false;  // --no-taint: drop the register-taint walker; emit every
                                              // matching IMM in candidate fns. Diagnostic only - useful
                                              // for "did the taint walker miss anything obvious?"
    bool        verbose             = false;  // --verbose: per-callsite TSV under --symuses
    std::string refs_to;            // --refs-to FN|VA: print callers of FN or VA
    std::string refs_to_loose;      // --refs-to-loose FN|VA: extend --refs-to with constant-pool /
                                    // imm64 scanning. Surfaces functions whose body holds the
                                    // target as a literal - the fn-ptr-only case where direct
                                     // E8/E9 callers are absent.
    std::string refs_access;        // --access read|write|lea|code-ptr|all: filter refs/data-xrefs
    std::string timeout;            // --timeout 10s: soft budget for quick refs probes
    std::string state_map;          // --state-map VA: mutation/read map for one state/global address
    std::string branch_on;          // --branch-on VA: reads of VA that feed nearby branches
    std::string guard_map;          // --guard-map FN/VA: conditional branches and nearby guard conditions
    std::string state_lifetime;     // --state-lifetime VA: writers/readers/branches story for one state/global
    std::string side_effects;       // --side-effects FN/VA: writes, calls, and return behavior for one function
    std::string object_roles;       // --object-roles FN/VA: infer direct this+offset field roles in one function
    std::string explain_address;    // --explain-address VA: fast address orientation summary
    std::string explain_vcall;      // --explain-vcall OBJ:OFF: resolve *( *(OBJ) + OFF )
    std::string vtable_at;          // --vtable-at VA: print the runtime vtable containing/near VA
    std::string dump_object;        // --dump-object ADDR: dump pointer-sized fields with classification
    std::string object_size;        // --size N: byte size for --dump-object
    std::string callees;            // --callees VA: print direct call targets of the function at VA
    std::string containing_fn;      // --containing-fn FN|VA: name/extent of the function covering VA
    std::string validate_name;      // --validate NAME: report all addrs bound to NAME + byte-similar lookalikes
    std::string callees_class;      // --callees-class NAME: JSON callee map for every vfn slot of a class
    std::string patch_plan;         // --patch-plan VA: hook/trampoline safety plan for a code address
    std::string disasm_at;          // --disasm-at FN|VA: disasm window at FN or VA
    std::string disasm_count;       // --count N: instructions for --disasm-at / --disasm-window
    std::string disasm_window;      // --disasm-window VA1,VA2,... - batch disassembly. Same per-VA
                                    // shape as --disasm-at, but emits one block per VA for efficient
                                    // processing of thousands of hits without per-call CLI startup.
                                    // `@PATH` reads VAs (one per line) from a file.
    std::string list_syscalls;      // --list-syscalls VA: walk fn @ VA, report each syscall site (file_offset + nr if known)
    std::string forge_spec;         // --forge-spec ENTRY:VA - minimum struct/branch
                                    // shape required for control to reach VA from
                                    // ENTRY. ENTRY is a name, hex VA, or sub_<hex>;
                                    // VA is hex / sub_<hex>. JSON form under --json.
    std::string apply_patches;      // --apply-patches FILE: vaddr_hex bytes_hex per line
    std::string output_path;        // -o / --output PATH: destination for --apply-patches
    std::string regions_manifest;   // --regions PATH: load via RawRegionsBinary instead of file magic
    std::string raw_bytes_path;     // --raw-bytes PATH: load PATH as a single rwx region (no PE container)
    std::string raw_base_va;        // --base-va 0xVA: base virtual address for --raw-bytes
    bool recover_imports = false;   // --recover-imports: rebuild the IAT (slot VA -> dll!func) for a
                                    // capture with no import directory, by base-solving harvested
                                    // module pointers against reference DLL export tables.
    std::string recover_dll_dir;    // --dll-dir DIR: folder of reference DLLs (*.dll) to name against
    std::vector<std::string> recover_dll_paths; // --dll PATH (repeatable): explicit reference DLL files
    std::string recover_image_base; // --image-base 0xVA: own-image base for slot-RVA keys in --recover-imports
                                    // output (defaults to PE image base / lowest mapped region)
    std::string module_filter;      // --module NAME: scope fn iteration to one loaded module
                                    // (minidumps, multi-module containers). Matched against
                                    // module Symbol basenames case-insensitively. Affects
                                    // --functions. Out-of-scope addresses are
                                    // skipped before fingerprinting - the actual bottleneck on
                                    // large dumps where most fns are wine-DLL noise.
    std::vector<std::string> pat_paths; // --pat PATH (repeatable): FLIRT-style .pat sig files to apply
    std::vector<std::string> force_fn_starts; // --force-fn-start VA (repeatable): synthetic Function symbols at these VAs
    std::string apply_spelunk;        // --apply PATH: declarative .spelunk script applied to annotations
    // --annotate ADDR: append a single annotation to the resolved file
    // (explicit --annotations beats sidecar beats cache, same chain
    // --apply uses). Companion flags pick what to set: --set-name,
    // --set-note, --set-signature; --confidence / --evidence / --source
    // attach provenance to whichever record was written.
    std::string annotate_addr;
    std::string annotate_name;      // --set-name NEW: store as a `rename` record
    std::string annotate_note;      // --set-note TEXT: store as a `note` record
    std::string annotate_signature; // --set-signature DECL: parsed C-style decl, stored as `sig`
    std::string annotate_conf;      // --confidence FLOAT: 0..1, applied to whichever record(s) get set
    std::string annotate_evidence;  // --evidence TEXT: short reason; survives in the meta record
    std::string annotate_source;    // --source TAG: who's claiming. Defaults to `cli`.
    std::string pdb_path;           // --pdb PATH: explicit PDB file (skips auto-discovery)
    std::string kismet_bundle;      // --kismet PATH: live UE Kismet bundle directory/manifest
    std::string kismet_event;       // --kismet-event NAME: select one Ubergraph wrapper entry
    std::string dsym_path;          // --dsym PATH: explicit Mach-O dSYM file/bundle symbol overlay
    bool no_pdb = false;            // --no-pdb: skip PDB sidecar discovery / ingestion entirely
    bool kismet_events = false;     // --kismet-events: list wrapper -> Ubergraph entry offsets
    bool infer_string_names = false; // --infer-string-names: derive names from strong log/string anchors
    bool dry_run = false;           // --dry-run: with --apply, don't write the result; print TSV to stdout
    bool no_cache = false;          // disable the disk cache entirely
    bool quick = false;             // --quick: bounded/partial refs probe; avoid full xrefs build
    bool full_analysis = false;     // force pass-2 CFG walk on packed binaries
                                    // (default: skip it - it just produces
                                    // garbage chasing indirect-jmp imm32s
                                    // through encrypted stub code)
    bool json = false;              // --json: machine-readable output where supported
    bool disasm = false;
    bool cfg    = false;
    bool ir     = false;
    bool ssa    = false;
    bool opt    = false;
    bool strct  = false;
    bool pseudo = false;
    bool emit_c = false;
    bool xrefs  = false;
    bool strings = false;
    bool surfaces = false;          // --surfaces: app/subsystem surface inventory
    std::string surface;            // --surface NAME: script_vm/network_transport/etc.
    std::string surface_kind;       // --surface-kind NAME: string/symbol/objc_method/rtti_class/log_category/reflection_descriptor
    std::string surface_category;   // --surface-category NAME: rendering/protection/artifact_shader/etc.
    std::string surface_owner;      // --surface-owner NAME: reflection descriptor owner/class filter
    std::string surface_row_type;   // --surface-row-type NAME: summary/category/owner/descriptor/artifact/function/evidence/all
    std::string surface_function;   // --surface-function VA: evidence scoped to a function
    bool graphics = false;          // --graphics: graphics backend/API/proc-loader inventory
    std::string graphics_backend;   // --graphics-backend NAME: opengl/vulkan/sdl/metal/glsl/spirv
    std::string graphics_domain;    // --graphics-domain NAME: buffer/shader/window/etc.
    std::string graphics_api;       // --graphics-api NAME: substring match for API/proc names
    std::string graphics_extension; // --graphics-extension NAME: ARB/EXT/KHR/etc.
    std::string graphics_category;  // --graphics-category NAME: api_proc_name/api_call_expr/etc.
    std::string graphics_role;      // --graphics-role NAME: proc_loader/proc_resolver/api_user/etc.
    std::string graphics_row_type;  // --graphics-row-type NAME: summary/api/extension/function/symbol/string
    std::string graphics_function;  // --graphics-function VA: evidence scoped to a function
    bool log_categories = false;
    bool arities = false;
    bool fingerprints = false;      // dump address-independent content hash per function
    bool identify = false;          // run YARA-like function identification (crypto/network profiles)
    float identify_threshold = 0.4f; // --identify-threshold T (confidence floor; default 0.4)
    spelunk::u64 min_fn_bytes = 0;             // --min-fn-size N: drop fns smaller than N bytes
                                              // before fingerprinting. Useful on obfuscator-spawned
                                              // targets (Themida / Lua VM / hellgate) whose hundreds
                                              // of thousands of trivial stubs add no signal but
                                              // dominate run time.
    spelunk::u64 max_fn_bytes = 0;             // --max-fn-size N: drop fns larger than N bytes.
                                              // VM-dispatcher functions in obfuscated targets can
                                              // span entire sections and dominate cfg.build cost.
                                              // 0 = no upper bound.
    bool labels = false;            // keep // bb_XXXX comments in pseudo-C output
    bool show_provenance = false;   // emit `// confidence: 0.9 (cli) - evidence`
                                    // header lines under -p when the resolved
                                    // annotation carries metadata. Default off
                                    // because it clutters the normal listing.
    bool list_annotations = false;  // --list-annotations: dump every record in
                                    // the resolved annotations file (rename,
                                    // note, signature) with its meta. Sibling
                                    // of --functions --json that surfaces
                                    // note-only annotations too.
    bool ipa    = false;            // run interprocedural signature inference for -p
    bool resolve_calls = false;     // global indirect-call resolver (vtable dispatch → named call)
    bool eh     = false;            // parse __eh_frame + LSDA and annotate landing pads
    bool objc_names = false;        // dump ObjC runtime -[Class sel] => IMP as TSV
    bool objc_protos = false;       // dump ObjC protocol signatures
    bool objc_surfaces = false;     // dump ObjC protocol/delegate implementation surfaces
    bool rtti   = false;            // dump Itanium RTTI classes + vtables
    bool vtables = false;           // dump runtime pointer-dense vtables from loaded data/RELRO
    bool int3_resolve = false;       // scan for embedded int3 bytes and classify them
    bool ppc_coverage = false;       // --ppc-coverage: rank decode and semantic PPC gaps
    spelunk::u64 ppc_coverage_limit = 25; // --coverage-limit N: rows for --ppc-coverage (0 = all)
    bool cfg_pseudo = false;        // CFG view with pseudo-C bodies per block
    bool functions = false;         // --functions [PATTERN]: list every discovered function (symbols ∪ sub_*)
    bool collisions = false;        // --collisions: dump every name/fingerprint group bound to >1 address
    std::string functions_pattern;  // optional substring filter for --functions (second positional)
    bool quiet  = false;            // suppress progress output regardless of TTY
    bool verify_roundtrip =
        false; // verify typed data/event decoding reproduces source bytes
    bool data_xrefs = false;        // --data-xrefs: dump every rip-rel/abs data reference
    bool dump_types = false;        // --dump-types: type-lattice self-test, no binary required
    bool debug  = false;            // --debug: launch the binary under the built-in REPL debugger
    std::string attach_pid;         // --attach-pid PID: attach to an existing process instead of launching
    std::string debug_backend;      // --debug-backend: "ptrace" (default), "perf", or "auto"
                                    //   ptrace = classic Linux ptrace backend; full features
                                    //   perf   = perf_event_open + /proc/<pid>/mem; HW BP/WP only,
                                    //            no SW BP / no step / no on-demand reg read /
                                    //            no syscall catch. Sets TracerPid=0 in the
                                    //            target's /proc/self/status - useful when an
                                    //            anti-cheat or other tracer is already attached.
                                    //   auto   = try perf first; fall back to ptrace if the
                                    //            kernel denies perf_event_open (e.g. paranoid≥2)
    std::vector<std::string> debug_args;  // tokens after `--`: argv for the launched program
    // --aux-binary PATH (repeatable): secondary Binary to load as a
    // symbol oracle for non-ELF code regions in the tracee - i.e.
    // Mach-O / PE / raw blobs that an in-process userspace loader
    // mmap'd into anon-rwx memory. Optional `@0xBASE` suffix pins the
    // runtime base when /proc/maps auto-detection isn't unique.
    std::vector<std::string> aux_binary_paths;
    // --ignore-fault-at HEX (repeatable): static address (un-slid)
    // where a fault-class signal (SIGSEGV / SIGBUS / SIGFPE / SIGILL)
    // is known to be recovered by the tracee's own handler. The
    // debugger silently forwards the signal back instead of stopping,
    // so a session through code that traps-and-recovers many times
    // doesn't drown the user in `c`s. Slide-corrected at match time.
    std::vector<std::string> ignore_fault_addrs;
    // --ignore-fault-file PATH (repeatable): file of hex addrs (one
    // per line, '#' comments OK) to seed the same set. Convention:
    // a runtime that knows its own recovery sites writes this sidecar
    // at startup, the debugger consumes it, new entries auto-pick-up.
    std::vector<std::string> ignore_fault_files;
    bool help    = false;
    bool version = false;           // --version / -V: print the version and exit
    std::string help_topic;         // --help <topic>: pick one section of the
                                    // help text; empty means "short overview"
};

// Parse argv into Args. Recognises the canonical short/long flags from
// the bool/value tables, the repeatable `--pat PATH`, the trailing
// `-- ARG…` script-args sentinel, and the `--functions=PATTERN` form
// that avoids the binary-vs-pattern positional swap. Returns an error
// on unknown flags or missing values.
[[nodiscard]] Result<Args> parse_args(int argc, char** argv);

// Stage implications: picking a later stage implies all the earlier
// ones (so `-p` runs `--struct` runs `-O` runs `--ssa` runs `-i`). Run
// once after parsing.
void apply_stage_implications(Args& a);

}  // namespace spelunk::cli
