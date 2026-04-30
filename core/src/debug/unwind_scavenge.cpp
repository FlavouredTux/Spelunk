// Stack-scan ("scavenged") unwinder — see unwind.hpp.
// Filter pair: address falls in a known function AND the byte
// before it decodes as a `call`. Both together kill the bulk of
// false positives a naïve scan would surface.

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

// True iff `static_pc` is the byte immediately after a `call`.
// 15 = max x86 instruction length.
[[nodiscard]] bool predecessor_is_call(
    const Binary& bin, const Decoder& dec, addr_t static_pc) {
    constexpr std::size_t kMaxInsn = 15;
    if (static_pc < kMaxInsn) return false;
    const addr_t scan_base = static_pc - kMaxInsn;
    auto window = bin.bytes_at(scan_base);
    if (window.size() < kMaxInsn) return false;
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

// offset_within == 0 is rejected: calls never target an entry as a
// return address, so a hit at offset 0 is almost always coincidence.
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

    std::vector<std::unique_ptr<Decoder>> decoders(bins.size());
    std::vector<Frame> out;

    for (std::size_t i = 0; i < qwords; ++i) {
        addr_t cand = 0;
        std::memcpy(&cand, buf.data() + i * 8, 8);
        if (cand == 0) continue;

        auto hit = identify(cand, bins);
        if (!hit) continue;

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
