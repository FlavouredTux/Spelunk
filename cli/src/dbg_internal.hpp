#pragma once

// REPL state and command handlers of the debugger front end. Private to
// the dbg*.cpp translation units.

#include <atomic>
#include <cstddef>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <ember/binary/binary.hpp>
#include <ember/common/error.hpp>
#include <ember/common/types.hpp>
#include <ember/debug/event.hpp>
#include <ember/debug/target.hpp>

#include "args.hpp"
#include "dbg.hpp"

namespace ember::cli::dbg {

// Active target for the SIGINT forwarder. The debugger blocks on
// wait_event() inside cont/step; Ctrl+C otherwise has nowhere to go
// but kill the REPL (and via PTRACE_O_EXITKILL, the tracee). With
// this hook, Ctrl+C calls interrupt() so the tracee yields control
// back to the prompt instead.
inline std::atomic<debug::Target*> g_active_target{nullptr};

std::string fmt_addr(addr_t a);

std::string sym_at_in_bin(addr_t runtime_pc, const Binary* bin, addr_t slide);

struct ReplState;

bool print_event(const debug::Event& ev, const ReplState& rs);

void print_error(const Error& e);

// Two flavours of address: a hex literal (already a runtime VA - no
// slide) versus a symbol resolved from one of the loaded Binaries
// (a static / linker VA - needs that bin's slide added). When the
// match is a symbol, `bin` and `slide` carry the source so the
// caller can apply the right slide without re-searching.
struct AddrSpec {
    addr_t        addr       = 0;
    bool          was_symbol = false;
    const Binary* bin        = nullptr;
    addr_t        slide      = 0;
};

std::optional<AddrSpec>
parse_addr_spec_in_bin(std::string_view tok, const Binary* bin);

addr_t compute_slide(debug::Target& tgt, const Binary& bin,
                     const std::string& bin_path);

std::optional<int> parse_int(std::string_view s);

// ---- command implementations --------------------------------------
// Aux symbol oracle: a Binary whose code is mapped into the tracee
// outside of any ELF segment we'd see via /proc/<pid>/maps' file
// path field (typical example: a Mach-O blob mmap'd as anon-rwx by a
// userspace loader, then mprotect'd to per-segment final prots).
// Slide is either pinned via `--aux-binary PATH@HEX` or auto-detected
// after attach by size-matching the binary's mapped extent against an
// anon region whose first 4 bytes match the binary's format magic.
struct AuxBin {
    const Binary*         bin = nullptr;
    std::string           path;
    std::string           short_name;       // basename(path) - e.g. "engine"
    addr_t                slide = 0;
    bool                  slide_resolved = false;
    std::optional<addr_t> manual_base;
};

// Whatever the user typed to `b` / `watch` - replayed through
// parse_addr_spec_multi after exec to re-arm against the new image.
struct BpSpec  { std::string spec; };

struct WpSpec  { std::string spec; u8 size; debug::WatchMode mode; };

struct ReplState {
    std::unique_ptr<debug::Target> tgt;
    debug::ThreadId                current_tid = 0;
    bool                           live        = false;
    const Binary*                  bin         = nullptr;
    std::string                    bin_path;   // for compute_slide path-matching
    std::string                    bin_short_name; // basename(bin_path) for `<bin>:<sym>` qualifier
    addr_t                         slide       = 0;  // PIE/ASLR slide; 0 for non-PIE
    std::vector<AuxBin>            aux_bins;
    std::vector<std::unique_ptr<Binary>> aux_storage;  // owns runtime-loaded `aux` binaries
    std::map<debug::BreakpointId, BpSpec> bp_specs;    // for re-arm across exec
    std::map<debug::WatchpointId, WpSpec> wp_specs;    // for re-arm across exec
    // Static-address (un-slid) PCs at which a fault-class signal
    // (SIGSEGV/SIGBUS/SIGFPE/SIGILL) is known to be recovered by the
    // tracee's own handler. wait_and_print silently forwards the
    // signal back instead of stopping. Slide-correction happens at
    // match time using whichever Binary owns the live PC.
    std::set<addr_t>               ignored_faults;

    // Backend selection lifted from --debug-backend at startup so
    // every cmd_run / cmd_attach invocation in the REPL uses the
    // same kind without re-parsing args. allow_fallback is set only
    // when the user explicitly chose "auto".
    debug::BackendKind             backend_kind           = debug::BackendKind::Default;
    bool                           backend_allow_fallback = false;
};

[[nodiscard]] std::string short_name_for(const std::string& path);

[[nodiscard]] std::optional<addr_t> parse_hex_addr(std::string_view s);

std::size_t load_ignored_faults_file(const std::string& path,
                                     std::set<addr_t>& out);

[[nodiscard]] bool is_fault_signal(int signo);

// PC → which (Binary, slide) covers it. Tries primary first, then
// aux. Coverage is "static_pc lands in [preferred_load_base,
// preferred_load_base + mapped_size)".
struct BinHit {
    const Binary* bin   = nullptr;
    addr_t        slide = 0;
};

[[nodiscard]] std::optional<BinHit>
find_bin_for_pc(const ReplState& rs, addr_t runtime_pc);

// Symbol name → first (Binary, static addr, slide) match, scanning
// primary then aux in registration order. When the same name resolves
// in more than one bin we still pick the first hit (so the call is
// O(1) at use sites) but emit a one-line warning to stderr so the
// user knows to disambiguate via `<bin>:<sym>`.
struct SymHit {
    const Binary* bin    = nullptr;
    addr_t        addr   = 0;
    addr_t        slide  = 0;
};

[[nodiscard]] std::optional<SymHit>
find_symbol(const ReplState& rs, std::string_view name);

[[nodiscard]] std::optional<SymHit>
find_symbol_qualified(const ReplState& rs,
                      std::string_view bin_tok,
                      std::string_view sym_tok);

std::optional<AddrSpec>
parse_addr_spec_multi(std::string_view tok, const ReplState& rs);

[[nodiscard]] addr_t resolve_runtime_multi(const AddrSpec& spec);

[[nodiscard]] std::string sym_at_runtime(addr_t pc, const ReplState& rs);

std::optional<addr_t>
compute_aux_slide(debug::Target& tgt, const AuxBin& aux);

void refresh_unresolved_aux_slides(ReplState& rs);

void on_target_acquired(ReplState& rs);

void on_target_released(ReplState& rs);

// Resolve --debug-backend into a (BackendKind, allow-fallback) pair.
// "auto" means try perf first, fall through to ptrace on Error::Unsupported
// or any io error from perf_event_open denial.
struct BackendChoice {
    debug::BackendKind kind = debug::BackendKind::Default;
    bool               allow_fallback = false;
};

BackendChoice parse_debug_backend(std::string_view s);

int cmd_run(ReplState& rs, const Args& args);

int cmd_attach(ReplState& rs, std::string_view pid_str);

int cmd_detach(ReplState& rs);

int cmd_kill(ReplState& rs);

bool try_break_at_pseudo_line(ReplState& rs, std::string_view tok);

int cmd_break(ReplState& rs, std::string_view tok);

int cmd_bp_list(ReplState& rs);

int cmd_delete(ReplState& rs, std::string_view tok);

int cmd_catch(ReplState& rs, std::span<const std::string> toks);

int cmd_dcatch(ReplState& rs);

int cmd_watch(ReplState& rs, std::span<const std::string> toks);

int cmd_wp_list(ReplState& rs);

int cmd_dwp(ReplState& rs, std::string_view tok);

// Re-arm bp/wp specs against the post-exec image. main() owns the
// initial Binary; after exec we own the replacement here so rs.bin
// stays valid for the rest of the session.
inline std::unique_ptr<Binary> g_post_exec_bin;

bool wait_and_print(ReplState& rs);

int cmd_cont(ReplState& rs);

int cmd_step(ReplState& rs);

int cmd_regs(ReplState& rs, bool full);

int cmd_set_reg(ReplState& rs, std::string_view reg_tok,
                std::string_view value_tok);

int cmd_poke(ReplState& rs, std::string_view addr_tok,
             std::span<const std::string> byte_toks);

int cmd_xmem(ReplState& rs, std::string_view addr_tok, std::string_view count_tok);

int cmd_bt(ReplState& rs);

int cmd_code(ReplState& rs);

int cmd_threads(ReplState& rs);

int cmd_thread_switch(ReplState& rs, std::string_view tok);

}  // namespace ember::cli::dbg
