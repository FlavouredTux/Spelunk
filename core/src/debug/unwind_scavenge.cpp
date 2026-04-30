// Heuristic stack-scan ("scavenged") unwinder. The use case: Rust
// abort-shim chains, control-flow-flattened code, and hand-rolled
// assembler that doesn't carry .eh_frame and doesn't preserve RBP.
// CFI gives one frame; RBP-walk gives garbage. The user just wants
// the names of the functions whose return addresses are sitting on
// the stack, even if the order is approximate.
//
// What we do: read a window starting at RSP and, for each qword,
// check two things:
//   1. A loaded Binary covers the address.
//   2. The instruction immediately before the address (i.e. the
//      candidate's predecessor) decodes as a `call`. The decoder
//      looks back up to 15 bytes (max x86 instruction length) and
//      accepts the first decode whose end-address equals the
//      candidate.
// Both filters together kill the bulk of false positives — a random
// pointer inside .text rarely lands right after a call boundary.
//
// We deliberately don't try to recover frame pointers. The user is
// here because the framing is broken; the scavenger's contract is
// "names you couldn't see otherwise", not "a complete unwind".

#include <ember/debug/unwind.hpp>

#include <cstddef>
#include <cstring>
#include <vector>

#include <ember/analysis/pipeline.hpp>
#include <ember/binary/binary.hpp>
#include <ember/disasm/decoder.hpp>
#include <ember/disasm/instruction.hpp>

namespace ember::debug {

namespace {

// True when `static_pc` is the byte immediately after a `call`
// instruction in `bin`. We read up to 15 bytes before the candidate
// (longest x86 encoding) and try decoding from each starting offset;
// the first decode whose end-address equals static_pc decides. No
// match → we conservatively reject the candidate.
[[nodiscard]] bool predecessor_is_call(
    const Binary& bin, const Decoder& dec, addr_t static_pc) {
    constexpr std::size_t kMaxInsn = 15;
    if (static_pc < kMaxInsn) return false;
    const addr_t scan_base = static_pc - kMaxInsn;
    auto window = bin.bytes_at(scan_base);
    if (window.size() < kMaxInsn) return false;
    // Try decoding from every byte offset; accept the first decode
    // that consumes exactly the right number of bytes to land at
    // static_pc and whose mnemonic is Call. If a longer decode at an
    // earlier offset would also have matched, we still accept the
    // shorter one — the byte-after-call invariant is what we care
    // about, not which exact prefix the assembler chose.
    for (std::size_t off = 1; off <= kMaxInsn; ++off) {
        const addr_t insn_addr = scan_base + (kMaxInsn - off);
        auto code = window.subspan(kMaxInsn - off, off);
        auto ins = dec.decode(code, insn_addr);
        if (!ins) continue;
        if (ins->length != off) continue;
        if (ins->mnemonic == Mnemonic::Call) return true;
    }
    return false;
}

// First (Binary*, slide) pair that covers `runtime_pc` AND can name
// the function it lands in. Returns nullopt when no bin claims it,
// or when the pc is at the very entry of a function (offset 0; that
// can't be a return address — calls never target their own first
// byte from inside the same function).
struct Hit {
    const Binary* bin       = nullptr;
    addr_t        slide     = 0;
    addr_t        static_pc = 0;
};

[[nodiscard]] std::optional<Hit>
identify(addr_t runtime_pc, std::span<const BinarySlide> bins) {
    for (const auto& bs : bins) {
        if (!bs.bin) continue;
        const addr_t static_pc = runtime_pc - bs.slide;
        auto cf = ember::containing_function(*bs.bin, static_pc);
        if (!cf) continue;
        if (cf->offset_within == 0) continue;
        return Hit{bs.bin, bs.slide, static_pc};
    }
    return std::nullopt;
}

}  // namespace

Result<std::vector<Frame>>
unwind_scavenge(Target& t, ThreadId tid,
                std::span<const BinarySlide> bins,
                std::size_t window_qwords) {
    auto regs = t.get_regs(tid);
    if (!regs) return std::unexpected(std::move(regs).error());

    const addr_t rsp = regs->rsp;
    const std::size_t bytes = window_qwords * 8;

    std::vector<std::byte> buf(bytes);
    auto rv = t.read_mem(rsp, buf);
    if (!rv) return std::unexpected(std::move(rv).error());
    const std::size_t got = *rv;
    const std::size_t qwords = got / 8;

    // One decoder per (bin, slide) — created lazily so a workload
    // with three aux bins and zero scavenge candidates pays nothing.
    std::vector<std::unique_ptr<Decoder>> decoders(bins.size());

    std::vector<Frame> out;
    out.reserve(qwords / 8);

    for (std::size_t i = 0; i < qwords; ++i) {
        addr_t cand = 0;
        std::memcpy(&cand, buf.data() + i * 8, 8);
        if (cand == 0) continue;

        auto hit = identify(cand, bins);
        if (!hit) continue;

        // Index the decoder cache by position in `bins`.
        std::size_t bin_idx = 0;
        for (; bin_idx < bins.size(); ++bin_idx) {
            if (bins[bin_idx].bin == hit->bin) break;
        }
        if (bin_idx >= bins.size()) continue;
        if (!decoders[bin_idx]) {
            auto d = make_decoder(*hit->bin);
            if (!d) continue;
            decoders[bin_idx] = std::move(*d);
        }
        if (!predecessor_is_call(*hit->bin, *decoders[bin_idx], hit->static_pc)) {
            continue;
        }

        Frame f;
        f.pc        = cand;
        f.fp        = 0;
        f.sp        = rsp + i * 8;
        f.scavenged = true;
        out.push_back(f);
    }

    return out;
}

}  // namespace ember::debug
