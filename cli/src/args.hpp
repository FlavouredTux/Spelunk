#pragma once

#include <string>
#include <vector>

#include <ember/common/error.hpp>

namespace ember::cli {

struct Args {
    std::string binary;
    std::string symbol;
    std::string annotations_path;   // optional project-file for user edits (read-only load)
    std::string export_annotations; // --export-annotations PATH: promote resolved source to PATH and exit
    std::string trace_path;         // optional indirect-edge trace TSV (from\tto per line)
    std::string project_path;       // optional project-file authorising script mutations
    std::string script_path;        // optional JS script to run against the binary
    std::vector<std::string> script_argv; // args passed to the script after `--`
    std::string cache_dir;          // override for the disk cache location
    std::string diff_path;          // --diff OLD: compare this older binary against args.binary
    std::string diff_format;        // --diff-format: "tsv" (default) or "json"
    std::string fp_out;             // --fingerprint-out PATH: also write fingerprints TSV here
    std::string fp_old_in;          // --fingerprint-old PATH: read OLD side fingerprints from PATH
    std::string fp_new_in;          // --fingerprint-new PATH: read NEW side fingerprints from PATH
    std::string refs_to;            // --refs-to VA: print callers of VA
    std::string callees;            // --callees VA: print direct call targets of the function at VA
    std::string containing_fn;      // --containing-fn VA: name/extent of the function covering VA
    std::string validate_name;      // --validate NAME: report all addrs bound to NAME + byte-similar lookalikes
    std::string callees_class;      // --callees-class NAME: JSON callee map for every vfn slot of a class
    std::string disasm_at;          // --disasm-at VA: disasm window at VA
    std::string disasm_count;       // --count N: instructions for --disasm-at
    std::string apply_patches;      // --apply-patches FILE: vaddr_hex bytes_hex per line
    std::string output_path;        // -o / --output PATH: destination for --apply-patches
    std::string regions_manifest;   // --regions PATH: load via RawRegionsBinary instead of file magic
    std::vector<std::string> pat_paths; // --pat PATH (repeatable): FLIRT-style .pat sig files to apply
    std::string apply_ember;        // --apply PATH: declarative .ember script applied to annotations
    bool no_cache = false;          // disable the disk cache entirely
    bool full_analysis = false;     // force pass-2 CFG walk on packed binaries
                                    // (default: skip it — it just produces
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
    bool xrefs  = false;
    bool strings = false;
    bool arities = false;
    bool fingerprints = false;      // dump address-independent content hash per function
    bool labels = false;            // keep // bb_XXXX comments in pseudo-C output
    bool ipa    = false;            // run interprocedural signature inference for -p
    bool resolve_calls = false;     // global indirect-call resolver (vtable dispatch → named call)
    bool eh     = false;            // parse __eh_frame + LSDA and annotate landing pads
    bool objc_names = false;        // dump ObjC runtime -[Class sel] => IMP as TSV
    bool objc_protos = false;       // dump ObjC protocol signatures
    bool rtti   = false;            // dump Itanium RTTI classes + vtables
    bool vm_detect = false;         // scan for interpreter-style VM dispatchers
    bool cfg_pseudo = false;        // CFG view with pseudo-C bodies per block
    bool functions = false;         // --functions [PATTERN]: list every discovered function (symbols ∪ sub_*)
    bool collisions = false;        // --collisions: dump every name/fingerprint group bound to >1 address
    std::string functions_pattern;  // optional substring filter for --functions (second positional)
    bool quiet  = false;            // suppress progress output regardless of TTY
    bool data_xrefs = false;        // --data-xrefs: dump every rip-rel/abs data reference
    bool dump_types = false;        // --dump-types: type-lattice self-test, no binary required
    bool help   = false;
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

}  // namespace ember::cli
