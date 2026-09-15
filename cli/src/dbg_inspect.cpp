// Registers, memory, backtraces, code listings and threads.

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <print>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <spelunk/analysis/pipeline.hpp>
#include <spelunk/binary/binary.hpp>
#include <spelunk/common/types.hpp>
#include <spelunk/debug/regs.hpp>
#include <spelunk/debug/types.hpp>
#include <spelunk/debug/unwind.hpp>
#include <spelunk/decompile/emit_options.hpp>

#include "dbg_internal.hpp"

namespace spelunk::cli::dbg {

namespace {

void print_zmm(const debug::Registers::ZmmReg& z, int width) {
    // width = 16 (XMM), 32 (YMM), 64 (ZMM)
    for (int i = width - 1; i >= 0; --i) {
        std::print("{:02x}", z.bytes[i]);
    }
}

// Map a register name (lowercase, dollar-prefix optional) to a writable
// pointer inside Registers. Only the GPRs + RIP + RFLAGS + segment regs
// are exposed - those are the ones a debugger typically wants to nudge
// to skip past faults or redirect control flow. SIMD / x87 / DR are
// reachable via `regs all` for inspection; if someone needs to write
// them, that's a future extension.
[[nodiscard]] u64* gpr_field(debug::Registers& r, std::string_view name) {
    if (!name.empty() && name.front() == '$') name.remove_prefix(1);
    struct M { std::string_view n; u64 debug::Registers::* p; };
    static const M kMap[] = {
        {"rax", &debug::Registers::rax}, {"rbx", &debug::Registers::rbx},
        {"rcx", &debug::Registers::rcx}, {"rdx", &debug::Registers::rdx},
        {"rsi", &debug::Registers::rsi}, {"rdi", &debug::Registers::rdi},
        {"rbp", &debug::Registers::rbp}, {"rsp", &debug::Registers::rsp},
        {"r8",  &debug::Registers::r8},  {"r9",  &debug::Registers::r9},
        {"r10", &debug::Registers::r10}, {"r11", &debug::Registers::r11},
        {"r12", &debug::Registers::r12}, {"r13", &debug::Registers::r13},
        {"r14", &debug::Registers::r14}, {"r15", &debug::Registers::r15},
        {"rip", &debug::Registers::rip}, {"rflags", &debug::Registers::rflags},
        {"cs",  &debug::Registers::cs},  {"ds", &debug::Registers::ds},
        {"es",  &debug::Registers::es},  {"fs", &debug::Registers::fs},
        {"gs",  &debug::Registers::gs},  {"ss", &debug::Registers::ss},
        {"fs_base", &debug::Registers::fs_base},
        {"gs_base", &debug::Registers::gs_base},
    };
    for (const auto& m : kMap) if (m.n == name) return &(r.*m.p);
    return nullptr;
}

// Parse a sequence of hex-byte tokens (e.g. `c3`, `90`, `0xff`) into a
// flat byte buffer. Used by `poke`. Returns nullopt on the first token
// that doesn't look like a 1- or 2-digit hex byte.
[[nodiscard]] std::optional<std::vector<std::byte>>
parse_hex_bytes(std::span<const std::string> toks) {
    std::vector<std::byte> out;
    out.reserve(toks.size());
    for (const auto& sv : toks) {
        std::string_view tok = sv;
        if (tok.starts_with("0x") || tok.starts_with("0X")) tok.remove_prefix(2);
        if (tok.empty() || tok.size() > 2) return std::nullopt;
        unsigned v = 0;
        for (char c : tok) {
            const int d = (c >= '0' && c <= '9') ? c - '0'
                        : (c >= 'a' && c <= 'f') ? c - 'a' + 10
                        : (c >= 'A' && c <= 'F') ? c - 'A' + 10
                        : -1;
            if (d < 0) return std::nullopt;
            v = (v << 4) | static_cast<unsigned>(d);
        }
        out.push_back(static_cast<std::byte>(v & 0xff));
    }
    return out;
}

}  // namespace

int cmd_regs(ReplState& rs, bool full) {
    if (!rs.live) { std::println("Not attached."); return 0; }
    auto regs = rs.tgt->get_regs(rs.current_tid);
    if (!regs) { print_error(regs.error()); return 1; }
    const auto& r = *regs;

    std::println("rax={}  rbx={}  rcx={}  rdx={}",
                 fmt_addr(r.rax), fmt_addr(r.rbx), fmt_addr(r.rcx), fmt_addr(r.rdx));
    std::println("rsi={}  rdi={}  rbp={}  rsp={}",
                 fmt_addr(r.rsi), fmt_addr(r.rdi), fmt_addr(r.rbp), fmt_addr(r.rsp));
    std::println("r8 ={}  r9 ={}  r10={}  r11={}",
                 fmt_addr(r.r8), fmt_addr(r.r9), fmt_addr(r.r10), fmt_addr(r.r11));
    std::println("r12={}  r13={}  r14={}  r15={}",
                 fmt_addr(r.r12), fmt_addr(r.r13), fmt_addr(r.r14), fmt_addr(r.r15));
    std::println("rip={}  rflags={}",
                 fmt_addr(r.rip), fmt_addr(r.rflags));
    std::println("cs={:04x} ds={:04x} es={:04x} fs={:04x} gs={:04x} ss={:04x}",
                 r.cs, r.ds, r.es, r.fs, r.gs, r.ss);
    std::println("fs_base={}  gs_base={}", fmt_addr(r.fs_base), fmt_addr(r.gs_base));

    if (!full) return 0;

    if (r.present & debug::Registers::PresentX87) {
        std::println("--- x87 ---");
        std::println("fcw={:04x} fsw={:04x} ftw={:02x} fop={:04x} fip={} fdp={}",
                     r.fcw, r.fsw, r.ftw, r.fop, fmt_addr(r.fip), fmt_addr(r.fdp));
        for (int i = 0; i < 8; ++i) {
            std::print("st{}=", i);
            for (int b = 9; b >= 0; --b) std::print("{:02x}", r.st[i].bytes[b]);
            std::print("  ");
            if ((i & 1) == 1) std::print("\n");
        }
    }
    if (r.present & debug::Registers::PresentSse) {
        std::println("--- sse ---  mxcsr={:08x} mask={:08x}", r.mxcsr, r.mxcsr_mask);
        for (int i = 0; i < 16; ++i) {
            std::print("xmm{:<2}=", i);
            print_zmm(r.zmm[i], 16);
            std::print("\n");
        }
    }
    if (r.present & debug::Registers::PresentAvx) {
        std::println("--- avx (ymm high halves) ---");
        for (int i = 0; i < 16; ++i) {
            std::print("ymm{:<2}=", i);
            print_zmm(r.zmm[i], 32);
            std::print("\n");
        }
    }
    if (r.present & debug::Registers::PresentAvx512) {
        std::println("--- avx-512 ---");
        for (int i = 0; i < 8; ++i) {
            std::println("k{}={:016x}", i, r.k[i]);
        }
        for (int i = 0; i < 32; ++i) {
            std::print("zmm{:<2}=", i);
            print_zmm(r.zmm[i], 64);
            std::print("\n");
        }
    }
    if (r.present & debug::Registers::PresentDr) {
        std::println("--- debug ---");
        std::println("dr0={}  dr1={}  dr2={}  dr3={}",
                     fmt_addr(r.dr[0]), fmt_addr(r.dr[1]),
                     fmt_addr(r.dr[2]), fmt_addr(r.dr[3]));
        std::println("dr6={}  dr7={}", fmt_addr(r.dr[6]), fmt_addr(r.dr[7]));
    }
    return 0;
}

int cmd_set_reg(ReplState& rs, std::string_view reg_tok,
                std::string_view value_tok) {
    if (!rs.live) { std::println("Not attached."); return 0; }
    auto regs = rs.tgt->get_regs(rs.current_tid);
    if (!regs) { print_error(regs.error()); return 1; }
    u64* slot = gpr_field(*regs, reg_tok);
    if (!slot) {
        std::println(stderr,
            "spelunk-dbg: set: unknown register '{}' (try rax/rbx/.../rip/rflags/cs/...)",
            reg_tok);
        return 1;
    }
    // Accept hex (with or without `0x`), decimal, or address-spec
    // (sym, sym+ofs, bin:sym) - same syntax as `b` and `x` so a user
    // can `set rip <symbol>` to force a jump back into known code.
    std::optional<u64> value;
    if (auto h = parse_hex_addr(value_tok); h) {
        value = static_cast<u64>(*h);
    } else if (auto i = parse_int(value_tok); i && *i >= 0) {
        value = static_cast<u64>(*i);
    } else if (auto spec = parse_addr_spec_multi(value_tok, rs); spec) {
        value = static_cast<u64>(resolve_runtime_multi(*spec));
    }
    if (!value) {
        std::println(stderr, "spelunk-dbg: set: bad value '{}'", value_tok);
        return 1;
    }
    *slot = *value;
    auto wv = rs.tgt->set_regs(rs.current_tid, *regs);
    if (!wv) { print_error(wv.error()); return 1; }
    std::println("{} = {}", reg_tok, fmt_addr(*value));
    return 0;
}

int cmd_poke(ReplState& rs, std::string_view addr_tok,
             std::span<const std::string> byte_toks) {
    if (!rs.live) { std::println("Not attached."); return 0; }
    if (byte_toks.empty()) {
        std::println(stderr,
            "spelunk-dbg: poke: usage `poke <addr> <hex-byte> [<hex-byte>...]`");
        return 1;
    }
    auto spec = parse_addr_spec_multi(addr_tok, rs);
    if (!spec) {
        std::println(stderr, "spelunk-dbg: poke: bad address '{}'", addr_tok);
        return 1;
    }
    auto bytes = parse_hex_bytes(byte_toks);
    if (!bytes) {
        std::println(stderr,
            "spelunk-dbg: poke: bad hex byte (expected pairs like c3 90 0xff)");
        return 1;
    }
    const addr_t va_runtime = resolve_runtime_multi(*spec);
    auto rv = rs.tgt->write_mem(va_runtime, *bytes);
    if (!rv) { print_error(rv.error()); return 1; }
    const std::size_t got = *rv;
    std::println("wrote {} byte(s) at {}", got, fmt_addr(va_runtime));
    if (got < bytes->size()) {
        std::println("(write short - {} of {} requested bytes)", got, bytes->size());
    }
    return 0;
}

int cmd_xmem(ReplState& rs, std::string_view addr_tok, std::string_view count_tok) {
    if (!rs.live) { std::println("Not attached."); return 0; }
    auto spec = parse_addr_spec_multi(addr_tok, rs);
    if (!spec) {
        std::println(stderr, "spelunk-dbg: x: bad address '{}'", addr_tok);
        return 1;
    }
    const addr_t va_runtime = resolve_runtime_multi(*spec);
    int count = 16;
    if (!count_tok.empty()) {
        if (auto n = parse_int(count_tok)) count = *n;
    }
    if (count <= 0) count = 16;

    std::vector<std::byte> buf(static_cast<std::size_t>(count));
    auto rv = rs.tgt->read_mem(va_runtime, buf);
    if (!rv) { print_error(rv.error()); return 1; }

    const std::size_t got = *rv;
    for (std::size_t i = 0; i < got; i += 16) {
        std::print("{}: ", fmt_addr(va_runtime + i));
        const std::size_t row = std::min<std::size_t>(16, got - i);
        for (std::size_t j = 0; j < row; ++j) {
            std::print("{:02x} ", static_cast<unsigned>(buf[i + j]));
        }
        for (std::size_t j = row; j < 16; ++j) std::print("   ");
        std::print(" ");
        for (std::size_t j = 0; j < row; ++j) {
            const auto c = static_cast<unsigned char>(buf[i + j]);
            std::print("{}", (c >= 32 && c < 127) ? static_cast<char>(c) : '.');
        }
        std::print("\n");
    }
    if (got < buf.size()) {
        std::println("(read short - {} of {} requested bytes)", got, buf.size());
    }
    return 0;
}

int cmd_bt(ReplState& rs) {
    if (!rs.live) { std::println("Not attached."); return 0; }

    // Try .eh_frame first when we have a binary to consult. CFI
    // unwinds correctly through `-fomit-frame-pointer` code where
    // RBP-walk would fall over after the innermost frame. If CFI
    // gives nothing useful (no binary, no .eh_frame, or stalled at
    // frame 0), fall back to RBP-walk.
    std::vector<debug::Frame> frames;
    bool used_eh = false;
    if (rs.bin) {
        if (auto eh = debug::unwind_eh_frame(*rs.tgt, rs.current_tid,
                                             *rs.bin, rs.slide); eh) {
            frames  = std::move(*eh);
            used_eh = frames.size() >= 2;
        }
    }
    if (!used_eh) {
        auto rbp = debug::unwind_rbp(*rs.tgt, rs.current_tid);
        if (!rbp) { print_error(rbp.error()); return 1; }
        if (rbp->size() > frames.size()) frames = std::move(*rbp);
    }

    // Scavenged frames: when the structured unwind dies after one or
    // two frames (Rust panic chains, CFF, hand-rolled asm without
    // .eh_frame), scan the stack for qwords whose predecessor byte
    // is a `call` instruction inside a known function. Order is not
    // guaranteed; the user gets the names anyway. Skip when the
    // structured unwind already reaches deep enough that scavenged
    // hits would just be noise.
    constexpr std::size_t kScavengeThreshold = 3;
    if (frames.size() < kScavengeThreshold) {
        std::vector<debug::BinarySlide> bins;
        bins.reserve(1 + rs.aux_bins.size());
        if (rs.bin) bins.push_back({rs.bin, rs.slide});
        for (const auto& aux : rs.aux_bins) {
            if (aux.slide_resolved) bins.push_back({aux.bin, aux.slide});
        }
        if (!bins.empty()) {
            if (auto sc = debug::unwind_scavenge(*rs.tgt, rs.current_tid,
                                                 std::span<const debug::BinarySlide>(bins));
                sc && !sc->empty()) {
                std::set<addr_t> already;
                for (const auto& f : frames) already.insert(f.pc);
                for (auto& f : *sc) {
                    if (already.contains(f.pc)) continue;
                    frames.push_back(f);
                    already.insert(f.pc);
                }
            }
        }
    }

    int idx = 0;
    for (const auto& f : frames) {
        std::println("#{:<2} {}{}{}", idx++, fmt_addr(f.pc),
                     sym_at_runtime(f.pc, rs),
                     f.scavenged ? "  *scavenged*" : "");
    }
    if (used_eh) std::println("  (via .eh_frame; *scavenged* frames are best-effort)");
    return 0;
}

int cmd_code(ReplState& rs) {
    if (!rs.live) { std::println("Not attached."); return 0; }
    if (!rs.bin && rs.aux_bins.empty()) {
        std::println(stderr, "spelunk-dbg: code: no binary loaded");
        return 1;
    }
    auto regs = rs.tgt->get_regs(rs.current_tid);
    if (!regs) { print_error(regs.error()); return 1; }

    const addr_t pc_runtime = regs->rip;

    // Pick the binary whose mapped range covers this PC. Falls back
    // to the primary if none claims it (typical for ld.so / vDSO
    // frames at attach time).
    auto hit = find_bin_for_pc(rs, pc_runtime);
    const Binary* code_bin = hit ? hit->bin   : rs.bin;
    const addr_t  slide    = hit ? hit->slide : rs.slide;
    if (!code_bin) {
        std::println("No binary covers {}.", fmt_addr(pc_runtime));
        return 0;
    }
    const addr_t pc_static = pc_runtime - slide;

    auto cf = spelunk::containing_function(*code_bin, pc_static);
    if (!cf) {
        std::println("No function covers {} (static {}).",
                     fmt_addr(pc_runtime), fmt_addr(pc_static));
        return 0;
    }
    auto win = spelunk::resolve_function_at(*code_bin, cf->entry);
    if (!win) {
        std::println(stderr, "spelunk-dbg: code: failed to resolve {}", cf->name);
        return 1;
    }

    LineMap line_map;
    EmitOptions opts;
    opts.line_map = &line_map;
    auto pseudo = spelunk::format_struct(*code_bin, *win, /*pseudo*/true,
                                       /*ann*/nullptr, opts);
    if (!pseudo) { print_error(pseudo.error()); return 1; }
    const std::string& text = *pseudo;

    // Two-tier match: prefer the hit with the largest source_addr <=
    // pc_static (the IR currently in flight). If we're sitting inside
    // a region that the emitter folded away (prologue, dead code), no
    // such hit exists - fall back to the first emitted IR after pc, so
    // the user sees the next visible statement marked instead of no
    // mark at all.
    const LineMap::Hit* best = nullptr;
    const LineMap::Hit* first_after = nullptr;
    for (const auto& h : line_map.hits) {
        if (h.byte_offset >= text.size()) continue;
        if (h.source_addr <= pc_static) {
            if (!best || h.source_addr > best->source_addr) best = &h;
        } else {
            if (!first_after || h.source_addr < first_after->source_addr) {
                first_after = &h;
            }
        }
    }
    const LineMap::Hit* picked = best ? best : first_after;

    u32 marked_line = 0;
    if (picked) {
        marked_line = 1 + static_cast<u32>(std::count(
            text.begin(),
            text.begin() + static_cast<std::ptrdiff_t>(picked->byte_offset),
            '\n'));
    }

    std::println("// {}  entry={}  size={}  pc-offset=0x{:x}",
                 cf->name, fmt_addr(cf->entry), cf->size, cf->offset_within);

    // Print with arrow on the marked line.
    u32 line_no = 1;
    std::size_t i = 0;
    while (i < text.size()) {
        const auto nl = text.find('\n', i);
        const auto end = (nl == std::string::npos) ? text.size() : nl;
        std::println("{} {:>4} | {}",
                     (line_no == marked_line ? "->" : "  "),
                     line_no,
                     std::string_view(text).substr(i, end - i));
        if (nl == std::string::npos) break;
        i = nl + 1;
        ++line_no;
    }
    if (picked == first_after && first_after) {
        std::println("(pc {} is in folded-away code; arrow shows next visible IR at {})",
                     fmt_addr(pc_static), fmt_addr(first_after->source_addr));
    }
    return 0;
}

int cmd_threads(ReplState& rs) {
    if (!rs.live) { std::println("Not attached."); return 0; }
    for (auto tid : rs.tgt->threads()) {
        std::println("  {}{}", (tid == rs.current_tid ? "* " : "  "), tid);
    }
    return 0;
}

int cmd_thread_switch(ReplState& rs, std::string_view tok) {
    if (!rs.live) { std::println("Not attached."); return 0; }
    auto v = parse_int(tok);
    if (!v) {
        std::println(stderr, "spelunk-dbg: thread: bad tid '{}'", tok);
        return 1;
    }
    rs.current_tid = static_cast<debug::ThreadId>(*v);
    std::println("Switched to thread {}", rs.current_tid);
    return 0;
}

}  // namespace spelunk::cli::dbg
