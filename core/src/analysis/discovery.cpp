#include <ember/analysis/discovery.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
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
    return n == ".text" || n == "__text" || n == "CODE";
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

std::vector<addr_t> discover_from_prologues(const Binary& b) {
    std::vector<addr_t> out;
    X64Decoder dec;

    for (const auto& s : b.sections()) {
        if (!section_is_code(s)) continue;
        if (s.size == 0) continue;
        // High-entropy code sections are encrypted/packed — a linear
        // sweep there matches noise, not real prologues.
        if (section_looks_encrypted(s)) continue;
        if (s.data.empty()) continue;

        const auto data = s.data;
        const auto base = s.vaddr;
        // Sweep at every byte offset. x64 instructions aren't
        // length-aligned, but function entries usually are 16-byte
        // aligned by MSVC; we still check every offset because
        // - tail-merged functions can sit at non-16-aligned offsets
        // - linkers occasionally pack with /align:1 for size
        for (std::size_t off = 0; off + 8 <= data.size(); ++off) {
            const auto cand = data.subspan(off);
            if (!looks_like_prologue(cand)) continue;
            if (!validates_as_function_start(dec, cand, base + off)) continue;
            out.push_back(base + off);
        }
    }

    // Dedup — overlapping prefix patterns can hit the same address.
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
