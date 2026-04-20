#include <ember/analysis/strings.hpp>

#include <algorithm>
#include <cstddef>
#include <map>
#include <string>

#include <ember/disasm/instruction.hpp>
#include <ember/disasm/x64_decoder.hpp>

namespace ember {

namespace {

constexpr std::size_t kMinStringLen = 4;
constexpr std::size_t kMaxStringLen = 1024;

[[nodiscard]] bool is_string_byte(unsigned char c) noexcept {
    if (c == '\t' || c == '\n' || c == '\r') return true;
    return c >= 0x20 && c <= 0x7e;
}

struct AddrRange {
    addr_t begin = 0;
    addr_t end   = 0;  // exclusive
};

// Attempts to extract printable strings from a single section. Each NUL
// terminator ends the current run; overlapping/adjacent runs are independent
// entries (one per start offset).
void scan_section(const Section& sec, std::vector<StringEntry>& out) {
    if (sec.data.empty()) return;
    if (!sec.flags.readable) return;
    // Mach-O puts `__cstring` (and `__const`, `__ustring`, etc.) inside the
    // executable `__TEXT` segment — so filtering by the segment's X bit
    // means we miss the overwhelming majority of string literals on Mach-O.
    // The printable-run + NUL-terminated checks below filter out code bytes
    // perfectly well; trust them instead of a permissions heuristic.
    // Still skip obviously-code sections (__text itself, __stubs, ...) to
    // keep the scan fast and avoid occasional ASCII-looking instruction
    // sequences. We treat any section named `__text*` / `__stubs*` /
    // `__stub_helper` / `__init` / `__unwind*` / `__eh_frame` as code.
    const std::string_view sn = sec.name;
    auto is_code_section = [&]() {
        for (const std::string_view skip : {
            std::string_view{"__text"},
            std::string_view{"__stubs"},
            std::string_view{"__stub_helper"},
            std::string_view{"__unwind_info"},
            std::string_view{"__eh_frame"},
            std::string_view{"__init"},
            std::string_view{"__mod_init_func"},
            std::string_view{"__mod_term_func"},
            std::string_view{".text"},
            std::string_view{".plt"},
            std::string_view{".init"},
            std::string_view{".fini"},
        }) {
            if (sn == skip) return true;
            if (sn.ends_with(std::string{","} + std::string{skip})) return true;
        }
        return false;
    };
    if (is_code_section()) return;

    const auto* data = reinterpret_cast<const unsigned char*>(sec.data.data());
    const std::size_t n = sec.data.size();

    std::size_t i = 0;
    while (i < n) {
        // Skip past non-string bytes until we find a printable one.
        while (i < n && !is_string_byte(data[i])) ++i;
        if (i >= n) break;

        const std::size_t start = i;
        std::string s;
        while (i < n && is_string_byte(data[i]) && s.size() < kMaxStringLen) {
            s.push_back(static_cast<char>(data[i]));
            ++i;
        }
        // A valid C string is NUL-terminated in place. Require that to avoid
        // mistaking arbitrary ASCII stretches in code/data for string pools.
        const bool terminated = (i < n && data[i] == 0);
        if (terminated && s.size() >= kMinStringLen) {
            StringEntry e;
            e.addr = sec.vaddr + static_cast<addr_t>(start);
            e.text = std::move(s);
            out.push_back(std::move(e));
        }
        if (i < n) ++i;  // skip the NUL / bad byte
    }
}

}  // namespace

std::vector<StringEntry> scan_strings(const Binary& b) {
    std::vector<StringEntry> results;
    for (const auto& sec : b.sections()) {
        scan_section(sec, results);
    }
    if (results.empty()) return results;

    // Build a lookup: address → index in results.
    std::map<addr_t, std::size_t> by_addr;
    for (std::size_t i = 0; i < results.size(); ++i) {
        by_addr.emplace(results[i].addr, i);
    }

    // For an operand-derived absolute address, find the string whose range
    // *contains* the address — since lea/mov/call immediates always target the
    // string start, we only match exact starts (simpler and avoids false hits
    // into the middle of a string).
    auto match = [&](addr_t a) -> StringEntry* {
        auto it = by_addr.find(a);
        if (it == by_addr.end()) return nullptr;
        return &results[it->second];
    };

    // Walk every defined function, decode linearly, collect xrefs.
    X64Decoder dec;
    for (const auto& sym : b.symbols()) {
        if (sym.is_import) continue;
        if (sym.kind != SymbolKind::Function) continue;
        if (sym.size == 0) continue;

        auto span = b.bytes_at(sym.addr);
        if (span.empty()) continue;
        const std::size_t limit = std::min<std::size_t>(
            span.size(), static_cast<std::size_t>(sym.size));

        addr_t ip = sym.addr;
        std::size_t off = 0;
        while (off < limit) {
            auto remaining = span.subspan(off, limit - off);
            auto decoded = dec.decode(remaining, ip);
            if (!decoded) { ip += 1; off += 1; continue; }
            const auto& insn = *decoded;

            for (u8 j = 0; j < insn.num_operands; ++j) {
                const Operand& op = insn.operands[j];
                addr_t candidate = 0;
                bool have = false;
                if (op.kind == Operand::Kind::Relative) {
                    candidate = op.rel.target;
                    have = true;
                } else if (op.kind == Operand::Kind::Memory && op.mem.has_disp) {
                    // rip-relative: disp is offset from next instruction.
                    if (op.mem.base == Reg::Rip && op.mem.index == Reg::None) {
                        candidate = ip + insn.length +
                                    static_cast<addr_t>(op.mem.disp);
                        have = true;
                    } else if (op.mem.base == Reg::None &&
                               op.mem.index == Reg::None) {
                        candidate = static_cast<addr_t>(op.mem.disp);
                        have = true;
                    }
                } else if (op.kind == Operand::Kind::Immediate &&
                           op.imm.size >= 4) {
                    candidate = static_cast<addr_t>(op.imm.value);
                    have = true;
                }
                if (!have) continue;
                if (auto* e = match(candidate)) {
                    if (e->xrefs.empty() || e->xrefs.back() != ip) {
                        e->xrefs.push_back(ip);
                    }
                }
            }

            ip  += insn.length;
            off += insn.length;
        }
    }

    // Dedupe xrefs.
    for (auto& e : results) {
        std::sort(e.xrefs.begin(), e.xrefs.end());
        e.xrefs.erase(std::unique(e.xrefs.begin(), e.xrefs.end()), e.xrefs.end());
    }

    return results;
}

}  // namespace ember
