#include <ember/analysis/discovery.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <thread>
#include <unordered_set>
#include <vector>

#include <ember/analysis/msvc_rtti.hpp>
#include <ember/analysis/packed.hpp>
#include <ember/analysis/rtti.hpp>
#include <ember/binary/binary.hpp>
#include <ember/binary/format.hpp>
#include <ember/binary/section.hpp>
#include <ember/disasm/x64_decoder.hpp>

namespace ember {

namespace {

// "Code-shaped" = either flagged executable, or has the canonical text
// section name. Byfron / VMProtect strip the executable bit on disk
// and flip it at runtime; we still want to discover functions in
// those bytes.
[[nodiscard]] bool name_is_code_section(std::string_view n) noexcept {
    return n == ".text" || n == "__text" || n == "CODE" || n == ".byfron";
}

[[nodiscard]] bool section_is_code(const Section& s) noexcept {
    if (s.flags.executable) return true;
    return name_is_code_section(s.name);
}

[[nodiscard]] bool addr_in_code_section(const Binary& b, addr_t a) noexcept {
    for (const auto& s : b.sections()) {
        if (!section_is_code(s)) continue;
        if (a >= s.vaddr && a < s.vaddr + s.size) return true;
    }
    return false;
}

// Common MSVC / clang-on-Windows / SysV-x64 function prologues. The
// match is on the first 1–4 bytes; the decoder validates the rest.
// These hits are the tail of an enormous distribution — there are
// dozens more rare prologue shapes, but adding them costs more in
// false positives (any random byte sequence has a fixed chance of
// matching) than it gains in real coverage.
[[nodiscard]] bool looks_like_prologue(std::span<const std::byte> bytes) noexcept {
    if (bytes.size() < 3) return false;
    const auto b0 = static_cast<std::uint8_t>(bytes[0]);
    const auto b1 = static_cast<std::uint8_t>(bytes[1]);
    const auto b2 = static_cast<std::uint8_t>(bytes[2]);

    // 48 89 5C 24 ??     mov [rsp+8], rbx     (very common MSVC frame setup)
    // 48 89 6C 24 ??     mov [rsp+8], rbp
    // 48 89 74 24 ??     mov [rsp+8], rsi
    // 48 89 7C 24 ??     mov [rsp+8], rdi
    // 4C 89 6C 24 ??     mov [rsp+x], r13
    // 4C 89 74 24 ??     mov [rsp+x], r14
    // 4C 89 7C 24 ??     mov [rsp+x], r15
    if (bytes.size() >= 5
        && (b0 == 0x48 || b0 == 0x4C)
        && b1 == 0x89
        && (b2 == 0x5C || b2 == 0x6C || b2 == 0x74 || b2 == 0x7C)
        && static_cast<std::uint8_t>(bytes[3]) == 0x24) {
        return true;
    }

    // 48 83 EC ??        sub rsp, imm8
    if (b0 == 0x48 && b1 == 0x83 && b2 == 0xEC) return true;
    // 48 81 EC ?? ?? ?? ??   sub rsp, imm32
    if (bytes.size() >= 7 && b0 == 0x48 && b1 == 0x81 && b2 == 0xEC) return true;

    // 40 53 / 40 55 / 40 56 / 40 57   push rbx / rbp / rsi / rdi (REX-prefixed)
    if (b0 == 0x40 && (b1 == 0x53 || b1 == 0x55 || b1 == 0x56 || b1 == 0x57)) return true;
    // 53 / 55 / 56 / 57   push rbx / rbp / rsi / rdi (no REX)
    // — only accept these as prologue when followed by a sub rsp
    //   or another push, otherwise we false-positive on call sites.
    if ((b0 == 0x53 || b0 == 0x55 || b0 == 0x56 || b0 == 0x57)
        && (b1 == 0x48 || b1 == 0x4C || b1 == 0x53 || b1 == 0x55 || b1 == 0x56 || b1 == 0x57)) {
        return true;
    }

    // 48 8B C4           mov rax, rsp     (frame-pointer setup, common in MSVC)
    if (b0 == 0x48 && b1 == 0x8B && b2 == 0xC4) return true;

    return false;
}

// Validate a candidate by decoding two instructions. Both must
// succeed for the candidate to count. Cheap — averages ~10 bytes of
// decode work per acceptance.
[[nodiscard]] bool validates_as_function_start(const X64Decoder& dec,
                                                std::span<const std::byte> bytes,
                                                addr_t addr) noexcept {
    auto first = dec.decode(bytes, addr);
    if (!first) return false;
    const auto len1 = first->length;
    if (len1 == 0 || len1 >= bytes.size()) return false;
    auto second = dec.decode(bytes.subspan(len1),
                             addr + static_cast<addr_t>(len1));
    if (!second) return false;
    return true;
}

}  // namespace

std::vector<addr_t> discover_from_vtables(const Binary& b) {
    std::vector<addr_t> out;
    if (b.format() == Format::Pe) {
        for (const auto& cls : parse_msvc_rtti(b)) {
            for (addr_t m : cls.methods) {
                if (m == 0) continue;
                if (!addr_in_code_section(b, m)) continue;
                out.push_back(m);
            }
        }
    }
    // Itanium RTTI applies to ELF and Mach-O. Empty on plain-C
    // binaries; cheap on PE (returns empty fast).
    if (b.format() != Format::Pe) {
        for (const auto& cls : parse_itanium_rtti(b)) {
            for (addr_t m : cls.methods) {
                if (m == 0) continue;
                if (!addr_in_code_section(b, m)) continue;
                out.push_back(m);
            }
        }
    }
    return out;
}

// Sweep one section's bytes for prologue patterns. Pure function — no
// shared state — so the parallel driver can have N copies running on
// disjoint chunks of the same section without coordination.
[[nodiscard]] static std::vector<addr_t>
sweep_section_chunk(std::span<const std::byte> data, addr_t base,
                    std::size_t off_begin, std::size_t off_end,
                    const X64Decoder& dec) {
    std::vector<addr_t> hits;
    if (off_end > data.size()) off_end = data.size();
    if (off_end < 8) return hits;
    off_end -= 7;     // need 8 bytes available for a candidate
    for (std::size_t off = off_begin; off < off_end; ++off) {
        const auto cand = data.subspan(off);
        if (!looks_like_prologue(cand)) continue;
        if (!validates_as_function_start(dec, cand, base + off)) continue;
        hits.push_back(base + off);
    }
    return hits;
}

std::vector<addr_t> discover_from_prologues(const Binary& b) {
    // Sweeping one byte at a time across a multi-MB executable section
    // dominates cold-open time (~136s on a 16 MB DLL). The work is
    // perfectly parallelizable: each candidate position is independent,
    // and the X64Decoder is stateless once constructed. Split each
    // section's bytes into chunks and run them concurrently.
    //
    // Chunks DO need to overlap by the maximum prologue-match length
    // (a few bytes) so a candidate that straddles a chunk boundary
    // isn't dropped. We use a conservative 16-byte overlap.
    const unsigned hw = std::max(1u, std::thread::hardware_concurrency());
    const std::size_t target_workers = std::min<std::size_t>(hw, 8u);

    std::vector<std::vector<addr_t>> per_section_hits;

    for (const auto& s : b.sections()) {
        if (!section_is_code(s)) continue;
        if (s.size == 0) continue;
        // High-entropy code sections are encrypted/packed — a linear
        // sweep there matches noise, not real prologues.
        if (section_looks_encrypted(s)) continue;
        if (s.data.empty()) continue;

        const auto data = s.data;
        const auto base = s.vaddr;
        // Tiny sections (or low core counts) — just sweep serially.
        constexpr std::size_t kSerialThreshold = 1 << 20;     // 1 MB
        if (data.size() < kSerialThreshold || target_workers <= 1) {
            X64Decoder dec;
            per_section_hits.push_back(
                sweep_section_chunk(data, base, 0, data.size(), dec));
            continue;
        }

        // Partition into target_workers chunks. Each chunk overlaps
        // the next by `kOverlap` bytes so that a prologue split across
        // a chunk boundary still gets matched (the second-chunk worker
        // re-checks the boundary).
        constexpr std::size_t kOverlap = 16;
        const std::size_t total = data.size();
        const std::size_t chunk = (total + target_workers - 1) / target_workers;
        std::vector<std::vector<addr_t>> chunk_hits(target_workers);
        std::vector<std::thread> threads;
        threads.reserve(target_workers);
        for (std::size_t i = 0; i < target_workers; ++i) {
            const std::size_t begin = i * chunk;
            const std::size_t raw_end = std::min(total, (i + 1) * chunk);
            // Last chunk: don't extend past `total`. Earlier chunks:
            // extend by overlap so we cover candidates that begin
            // within `kOverlap` bytes of the boundary.
            const std::size_t end = (i + 1 == target_workers)
                ? raw_end
                : std::min(total, raw_end + kOverlap);
            threads.emplace_back([&, i, begin, end]() {
                X64Decoder dec;
                chunk_hits[i] = sweep_section_chunk(data, base, begin, end, dec);
            });
        }
        for (auto& t : threads) t.join();

        // Merge into one section vector — order doesn't matter,
        // dedup happens below.
        std::size_t total_hits = 0;
        for (const auto& v : chunk_hits) total_hits += v.size();
        std::vector<addr_t> merged;
        merged.reserve(total_hits);
        for (auto& v : chunk_hits) {
            merged.insert(merged.end(),
                          std::make_move_iterator(v.begin()),
                          std::make_move_iterator(v.end()));
        }
        per_section_hits.push_back(std::move(merged));
    }

    std::vector<addr_t> out;
    std::size_t total_hits = 0;
    for (const auto& v : per_section_hits) total_hits += v.size();
    out.reserve(total_hits);
    for (auto& v : per_section_hits) {
        out.insert(out.end(),
                   std::make_move_iterator(v.begin()),
                   std::make_move_iterator(v.end()));
    }

    // Dedup — overlapping prefix patterns can hit the same address,
    // and adjacent chunks may both have produced the same hit in
    // their overlap region.
    std::unordered_set<addr_t> seen;
    seen.reserve(out.size());
    auto write = out.begin();
    for (auto a : out) {
        if (seen.insert(a).second) *write++ = a;
    }
    out.erase(write, out.end());
    return out;
}

}  // namespace ember
