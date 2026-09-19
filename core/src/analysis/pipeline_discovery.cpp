#include <spelunk/common/diagnostic.hpp>
// Function discovery: entries, filters, sizes, ObjC block invokes.

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <format>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <spelunk/analysis/discovery.hpp>
#include <spelunk/analysis/eh_frame.hpp>
#include <spelunk/analysis/msvc_rtti.hpp>
#include <spelunk/analysis/name_resolver.hpp>
#include <spelunk/analysis/objc.hpp>
#include <spelunk/analysis/packed.hpp>
#include <spelunk/analysis/pipeline.hpp>
#include <spelunk/analysis/rtti.hpp>
#include <spelunk/binary/arch.hpp>
#include <spelunk/binary/binary.hpp>
#include <spelunk/binary/format.hpp>
#include <spelunk/binary/section.hpp>
#include <spelunk/binary/symbol.hpp>
#include <spelunk/common/bytes.hpp>
#include <spelunk/common/timing.hpp>
#include <spelunk/common/types.hpp>
#include <spelunk/disasm/decoder.hpp>
#include <spelunk/disasm/instruction.hpp>
#include <spelunk/disasm/register.hpp>
#include <spelunk/ir/ssa.hpp>

#include "pipeline_internal.hpp"

namespace spelunk::pipeline {

namespace {

// Drop discovered `sub_*` entries that fall inside any instruction decoded
// from the preceding accepted entry. The prologue/call-target sweeps can
// nominate the displacement byte of a real two-byte jump (or a ModR/M/SIB
// byte deeper in a function) as another function start. Checking only the
// first instruction catches adjacent-prologue phantoms but misses these
// later overlaps and then truncates the containing function at the bogus
// entry.
// Real symbols are authoritative and survive unconditionally.
//
// This runs before fill_unknown_sizes so the gap-to-next-entry size
// computation isn't poisoned by the phantoms either (a real fn
// followed by a phantom 1-byte fn would otherwise be reported as
// size 1 instead of its true extent).
void filter_shadowed_entries(std::vector<DiscoveredFunction>& fns,
                             const Binary& b) {
    if (fns.size() < 2) return;
    std::sort(fns.begin(), fns.end(),
              [](const auto& x, const auto& y) { return x.addr < y.addr; });
    auto dec_r = make_decoder(b);
    if (!dec_r) return;
    const Decoder& dec = **dec_r;

    std::vector<DiscoveredFunction> out;
    out.reserve(fns.size());
    addr_t scan_pc = 0;
    for (auto& fn : fns) {
        bool inside_instruction = false;
        if (!out.empty() && fn.kind == DiscoveredFunction::Kind::Sub) {
            // Continue a conservative linear decode from the preceding
            // accepted entry until this candidate. Stop when fallthrough
            // ends: unreachable padding must not hide a later real entry.
            while (scan_pc < fn.addr) {
                auto bytes = b.bytes_at(scan_pc);
                if (bytes.empty()) break;
                auto instruction = dec.decode(bytes, scan_pc);
                if (!instruction || instruction->length == 0) break;
                const addr_t end = scan_pc + instruction->length;
                if (end > fn.addr) {
                    inside_instruction = true;
                    scan_pc = end;
                    break;
                }
                if (is_return_like(instruction->mnemonic) ||
                    is_unconditional_jmp(instruction->mnemonic)) break;
                scan_pc = end;
            }
        }
        if (inside_instruction) continue;

        // Symbols/unwind names remain authoritative even when a preceding
        // function falls through to the same address. A non-overlapping Sub
        // also starts a fresh scan range.
        out.push_back(std::move(fn));
        scan_pc = out.back().addr;
    }
    fns = std::move(out);
}

void filter_entries_inside_unwind_extents(std::vector<DiscoveredFunction>& fns,
                                          std::vector<FdeExtent> extents) {
    if (fns.empty() || extents.empty()) return;
    std::erase_if(extents, [](const FdeExtent& e) {
        return e.pc_begin == 0 || e.pc_range == 0;
    });
    if (extents.empty()) return;
    std::ranges::sort(extents, {}, &FdeExtent::pc_begin);

    std::vector<FdeExtent> merged;
    merged.reserve(extents.size());
    for (const auto& e : extents) {
        if (!merged.empty() && merged.back().pc_begin == e.pc_begin) {
            merged.back().pc_range = std::max(merged.back().pc_range, e.pc_range);
        } else {
            merged.push_back(e);
        }
    }

    auto covered_by_other_start = [&](addr_t a) {
        auto it = std::ranges::upper_bound(
            merged, a, {}, [](const FdeExtent& e) { return e.pc_begin; });
        if (it == merged.begin()) return false;
        --it;
        if (a == it->pc_begin) return false;
        const u64 off = static_cast<u64>(a - it->pc_begin);
        return off < it->pc_range;
    };

    std::erase_if(fns, [&](const DiscoveredFunction& fn) {
        return fn.kind == DiscoveredFunction::Kind::Sub &&
               covered_by_other_start(fn.addr);
    });
}

void filter_entries_inside_sized_symbols(std::vector<DiscoveredFunction>& fns) {
    if (fns.size() < 2) return;
    std::ranges::sort(fns, {}, &DiscoveredFunction::addr);
    std::vector<std::pair<addr_t, addr_t>> authoritative;
    for (const auto& function : fns) {
        if (function.kind != DiscoveredFunction::Kind::Symbol ||
            function.size == 0) continue;
        authoritative.emplace_back(function.addr, function.addr + function.size);
    }
    if (authoritative.empty()) return;
    std::erase_if(fns, [&](const DiscoveredFunction& function) {
        if (function.kind != DiscoveredFunction::Kind::Sub) return false;
        auto next = std::ranges::upper_bound(
            authoritative, function.addr, {}, &std::pair<addr_t, addr_t>::first);
        if (next == authoritative.begin()) return false;
        --next;
        return function.addr > next->first && function.addr < next->second;
    });
}

// Some defined symbols and all CFG-discovered `sub_*` entries have no reliable
// extent in the loader metadata. Downstream tools (fingerprints, xrefs, size
// filters) still need a usable estimate. Derive an upper-bound size from the
// gap to the next discovered function entry (or the end of the containing
// executable section). Over-counts when there's padding / jump tables in
// between, but that's the safe direction for filtering both ends.
void fill_unknown_sizes(std::vector<DiscoveredFunction>& fns, const Binary& b) {
    if (fns.empty()) return;

    auto is_code_section = [](const Section& s) noexcept {
        return s.flags.executable
            || s.name == ".text" || s.name == "__text" || s.name == "CODE"
            || s.name == ".byfron";
    };
    auto containing_code_section = [&](addr_t a) -> const Section* {
        for (const auto& s : b.sections()) {
            if (!is_code_section(s)) continue;
            if (a >= s.vaddr && a < s.vaddr + s.size) return &s;
        }
        return nullptr;
    };

    for (std::size_t i = 0; i < fns.size(); ++i) {
        if (fns[i].size != 0) continue;
        if (fns[i].kind == DiscoveredFunction::Kind::Sub) {
            bool inside_sized_symbol = false;
            for (std::size_t j = i; j-- > 0;) {
                if (fns[j].size == 0) continue;
                if (fns[j].addr + fns[j].size <= fns[i].addr) break;
                if (fns[j].kind == DiscoveredFunction::Kind::Symbol) {
                    inside_sized_symbol = true;
                    break;
                }
            }
            if (inside_sized_symbol) continue;
        }

        u64 upper = 0;
        const Section* sec = containing_code_section(fns[i].addr);
        if (sec != nullptr) {
            upper = sec->vaddr + sec->size;
        }
        if (i + 1 < fns.size() && fns[i + 1].addr > fns[i].addr) {
            const Section* next_sec = containing_code_section(fns[i + 1].addr);
            if (sec == nullptr || next_sec == sec) {
                upper = (upper == 0)
                    ? fns[i + 1].addr
                    : std::min<u64>(upper, fns[i + 1].addr);
            }
        }
        if (upper > fns[i].addr) {
            fns[i].size = upper - fns[i].addr;
        }
    }
}

[[nodiscard]] std::vector<addr_t> discover_code_pointers(const Binary& b) {
    const u8 width = (b.arch() == Arch::Ppc64 || b.arch() == Arch::X86_64) ? 8 : 4;
    std::vector<addr_t> out;
    auto in_code = [&](addr_t a) noexcept { return addr_in_code_section(b, a); };
    for (const auto& s : b.sections()) {
        if (!s.flags.allocated || s.flags.executable || s.data.size() < width) continue;
        for (std::size_t off = 0; off + width <= s.data.size(); off += width) {
            const std::byte* p = s.data.data() + off;
            addr_t target = 0;
            if (width == 4) {
                target = b.endian() == Endian::Big ? read_be_at<u32>(p) : read_le_at<u32>(p);
            } else {
                target = b.endian() == Endian::Big ? read_be_at<u64>(p) : read_le_at<u64>(p);
            }
            if (target == 0 || !in_code(target)) continue;
            out.push_back(target);
        }
    }
    std::ranges::sort(out);
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

[[nodiscard]] std::string objc_name_token(std::string_view s,
                                          std::string_view fallback) {
    std::string out;
    out.reserve(s.size());
    bool last_us = false;
    for (char ch : s) {
        const unsigned char c = static_cast<unsigned char>(ch);
        if (std::isalnum(c)) {
            out.push_back(ch);
            last_us = false;
        } else if (!last_us && !out.empty()) {
            out.push_back('_');
            last_us = true;
        }
    }
    while (!out.empty() && out.back() == '_') out.pop_back();
    if (out.empty()) out = std::string(fallback);
    if (!std::isalpha(static_cast<unsigned char>(out.front())) &&
        out.front() != '_') {
        out.insert(out.begin(), '_');
    }
    return out;
}

[[nodiscard]] std::string objc_method_context_name(const ObjcMethod& m) {
    std::string cls = objc_name_token(m.cls, "ObjC");
    std::string sel = objc_name_token(m.selector, "method");
    return std::format("{}_{}", cls, sel);
}

[[nodiscard]] std::string lower_first_ascii(std::string s) {
    if (!s.empty()) {
        s.front() = static_cast<char>(
            std::tolower(static_cast<unsigned char>(s.front())));
    }
    return s;
}

[[nodiscard]] std::vector<std::string>
objc_selector_arg_names_local(std::string_view selector) {
    std::vector<std::string> names;
    std::size_t start = 0;
    while (start < selector.size()) {
        const std::size_t colon = selector.find(':', start);
        if (colon == std::string_view::npos) break;
        std::string piece(selector.substr(start, colon - start));
        if (names.empty()) {
            if (piece.starts_with("set") && piece.size() > 3) {
                piece = lower_first_ascii(piece.substr(3));
            } else if (piece.starts_with("with") && piece.size() > 4) {
                piece = lower_first_ascii(piece.substr(4));
            } else if (auto with = piece.rfind("With");
                       with != std::string::npos && with + 4 < piece.size()) {
                piece = lower_first_ascii(piece.substr(with + 4));
            }
        }
        names.push_back(objc_name_token(piece, std::format("arg{}", names.size())));
        start = colon + 1;
    }
    return names;
}

[[nodiscard]] std::optional<std::string>
objc_method_capture_name_for_reg(Reg r, const ObjcMethod& m) {
    switch (canonical_reg(r)) {
        case Reg::Rdi:
            return "self";
        case Reg::Rdx: {
            const auto names = objc_selector_arg_names_local(m.selector);
            if (!names.empty()) return names[0];
            break;
        }
        case Reg::Rcx: {
            const auto names = objc_selector_arg_names_local(m.selector);
            if (names.size() > 1) return names[1];
            break;
        }
        case Reg::R8: {
            const auto names = objc_selector_arg_names_local(m.selector);
            if (names.size() > 2) return names[2];
            break;
        }
        case Reg::R9: {
            const auto names = objc_selector_arg_names_local(m.selector);
            if (names.size() > 3) return names[3];
            break;
        }
        default:
            break;
    }
    return std::nullopt;
}

[[nodiscard]] std::string objc_selector_result_name(std::string_view selector) {
    const std::size_t colon = selector.find(':');
    if (colon != std::string_view::npos) selector = selector.substr(0, colon);
    return objc_name_token(selector, "result");
}

[[nodiscard]] std::optional<std::string>
call_target_name(const Binary& b, const Instruction& insn) {
    std::optional<addr_t> target = branch_target(insn);
    if (!target) {
        if (auto slot = rip_relative_target(insn); slot) {
            auto bytes = b.bytes_at(*slot);
            if (bytes.size() >= 8) {
                u64 ptr = 0;
                std::memcpy(&ptr, bytes.data(), 8);
                if (ptr != 0) target = static_cast<addr_t>(ptr);
            }
        }
    }
    if (!target) return std::nullopt;
    auto resolved = resolve_address_name(b, *target);
    if (!resolved) return std::nullopt;
    return resolved->name;
}

[[nodiscard]] std::vector<ObjcStackBlockInvoke>
discover_objc_stack_block_invokes_impl(const Binary& b) {
    if (b.format() != Format::MachO || b.arch() != Arch::X86_64) return {};

    auto dec_r = make_decoder(b);
    if (!dec_r) return {};
    const Decoder& dec = **dec_r;

    const auto methods = parse_objc_methods(b);
    if (methods.empty()) return {};
    const auto selrefs = parse_objc_selrefs(b);

    std::vector<addr_t> method_starts;
    method_starts.reserve(methods.size());
    for (const auto& m : methods) {
        if (m.imp != 0 && addr_in_code_section(b, m.imp)) {
            method_starts.push_back(m.imp);
        }
    }
    std::ranges::sort(method_starts);
    method_starts.erase(std::unique(method_starts.begin(), method_starts.end()),
                        method_starts.end());

    struct Found {
        addr_t invoke = 0;
        std::string selector;
        std::size_t insn_index = 0;
        Reg base = Reg::None;
        Reg index = Reg::None;
        i64 block_disp = 0;
        std::map<u64, std::string> captures;
        std::string self_class;
    };

    std::vector<ObjcStackBlockInvoke> out;
    std::unordered_set<addr_t> seen;
    for (const auto& m : methods) {
        if (m.imp == 0 || !addr_in_code_section(b, m.imp)) continue;
        auto bytes = b.bytes_at(m.imp);
        if (bytes.empty()) continue;

        const std::string method_ctx = objc_method_context_name(m);
        std::map<Reg, addr_t> code_ptr_reg;
        std::map<Reg, std::string> selector_reg;
        std::map<Reg, std::string> value_reg;
        std::vector<Found> found;
        std::string last_selector;
        std::size_t last_selector_index = 0;
        std::size_t insn_index = 0;
        std::size_t off = 0;
        std::size_t method_limit = 4096;
        auto next = std::ranges::upper_bound(method_starts, m.imp);
        if (next != method_starts.end() && *next > m.imp) {
            method_limit = static_cast<std::size_t>(*next - m.imp);
        }
        const std::size_t limit = std::min<std::size_t>(bytes.size(), method_limit);

        auto set_selector = [&](std::string selector) {
            if (selector.empty()) return;
            last_selector = std::move(selector);
            last_selector_index = insn_index;
            for (auto& f : found) {
                if (insn_index > f.insn_index + 96) continue;
                f.selector = last_selector;
            }
        };

        while (off < limit) {
            auto insn_r = dec.decode(bytes.subspan(off, limit - off),
                                     m.imp + static_cast<addr_t>(off));
            if (!insn_r || insn_r->length == 0) {
                off += decode_failure_advance(b.arch(), bytes.subspan(off, limit - off));
                ++insn_index;
                continue;
            }
            const Instruction& insn = *insn_r;

            if (insn.mnemonic == Mnemonic::Mov && insn.num_operands == 2 &&
                insn.operands[0].kind == Operand::Kind::Register) {
                const Reg dst = canonical_reg(insn.operands[0].reg);
                const auto& src = insn.operands[1];
                bool selector_armed = false;
                if (src.kind == Operand::Kind::Memory &&
                    src.mem.base == Reg::Rip && src.mem.index == Reg::None &&
                    src.mem.has_disp) {
                    const addr_t slot = insn.address + insn.length +
                                        static_cast<addr_t>(src.mem.disp);
                    if (auto it = selrefs.find(slot); it != selrefs.end()) {
                        selector_reg[dst] = it->second;
                        if (dst == Reg::Rsi) set_selector(it->second);
                        selector_armed = true;
                    }
                } else if (src.kind == Operand::Kind::Register) {
                    const Reg src_r = canonical_reg(src.reg);
                    if (auto it = selector_reg.find(src_r); it != selector_reg.end()) {
                        selector_reg[dst] = it->second;
                        if (dst == Reg::Rsi) set_selector(it->second);
                        selector_armed = true;
                    }
                }
                if (!selector_armed) selector_reg.erase(dst);
            }

            if (insn.mnemonic == Mnemonic::Lea && insn.num_operands == 2 &&
                insn.operands[0].kind == Operand::Kind::Register &&
                insn.operands[1].kind == Operand::Kind::Memory) {
                const Reg dst = canonical_reg(insn.operands[0].reg);
                const Mem& mem = insn.operands[1].mem;
                if (mem.base == Reg::Rip && mem.index == Reg::None && mem.has_disp) {
                    const addr_t target = insn.address + insn.length +
                                          static_cast<addr_t>(mem.disp);
                    if (target != m.imp && addr_in_code_section(b, target)) {
                        code_ptr_reg[dst] = target;
                    } else {
                        code_ptr_reg.erase(dst);
                    }
                } else {
                    code_ptr_reg.erase(dst);
                }
            } else if (insn.mnemonic == Mnemonic::Mov && insn.num_operands == 2 &&
                       insn.operands[0].kind == Operand::Kind::Memory &&
                       insn.operands[1].kind == Operand::Kind::Register) {
                const Mem& dst = insn.operands[0].mem;
                const Reg src = canonical_reg(insn.operands[1].reg);
                if (dst.base != Reg::Rip && dst.index == Reg::None &&
                    dst.has_disp && dst.disp == 0x10) {
                    if (auto it = code_ptr_reg.find(src); it != code_ptr_reg.end()) {
                        Found f;
                        f.invoke = it->second;
                        f.selector = last_selector;
                        f.insn_index = insn_index;
                        f.base = canonical_reg(dst.base);
                        f.index = canonical_reg(dst.index);
                        f.block_disp = dst.disp - 0x10;
                        f.self_class = m.cls;
                        found.push_back(std::move(f));
                    }
                } else if (dst.base != Reg::Rip && dst.has_disp && dst.disp >= 0x20 &&
                           ((dst.disp - 0x20) % 8) == 0 &&
                           !code_ptr_reg.contains(src)) {
                    const Reg dst_base = canonical_reg(dst.base);
                    const Reg dst_index = canonical_reg(dst.index);
                    for (auto it = found.rbegin(); it != found.rend(); ++it) {
                        if (insn_index > it->insn_index + 96) continue;
                        if (it->base != dst_base || it->index != dst_index) continue;
                        const i64 field_off = dst.disp - it->block_disp;
                        if (field_off < 0x20 || (field_off % 8) != 0) continue;
                        if (auto name = objc_method_capture_name_for_reg(src, m); name) {
                            const u64 capture_idx =
                                static_cast<u64>((field_off - 0x20) / 8);
                            it->captures.emplace(capture_idx, *name);
                        } else if (auto name_it = value_reg.find(src);
                                   name_it != value_reg.end() &&
                                   !name_it->second.empty()) {
                            const u64 capture_idx =
                                static_cast<u64>((field_off - 0x20) / 8);
                            it->captures.emplace(capture_idx, name_it->second);
                        }
                        break;
                    }
                }
            } else if (insn.mnemonic == Mnemonic::Mov && insn.num_operands == 2 &&
                       insn.operands[0].kind == Operand::Kind::Register) {
                const Reg dst = canonical_reg(insn.operands[0].reg);
                const auto& src = insn.operands[1];
                if (src.kind == Operand::Kind::Register) {
                    const Reg src_r = canonical_reg(src.reg);
                    if (auto it = code_ptr_reg.find(src_r); it != code_ptr_reg.end()) {
                        code_ptr_reg[dst] = it->second;
                    } else {
                        code_ptr_reg.erase(dst);
                    }
                    if (auto it = value_reg.find(src_r); it != value_reg.end()) {
                        value_reg[dst] = it->second;
                    } else {
                        value_reg.erase(dst);
                    }
                } else {
                    code_ptr_reg.erase(dst);
                    value_reg.erase(dst);
                }
            }

            if (is_call(insn.mnemonic)) {
                const auto name = call_target_name(b, insn);
                const bool retain_autoreleased =
                    name && name->find("objc_retainAutoreleasedReturnValue") !=
                                std::string::npos;
                if (retain_autoreleased) {
                    if (auto it = value_reg.find(Reg::Rdi); it != value_reg.end()) {
                        value_reg[Reg::Rax] = it->second;
                    } else {
                        value_reg.erase(Reg::Rax);
                    }
                } else if (!last_selector.empty() &&
                           insn_index <= last_selector_index + 8) {
                    value_reg[Reg::Rax] = objc_selector_result_name(last_selector);
                } else {
                    value_reg.erase(Reg::Rax);
                }
                value_reg.erase(Reg::Rcx);
                value_reg.erase(Reg::Rdx);
                value_reg.erase(Reg::Rsi);
                value_reg.erase(Reg::R8);
                value_reg.erase(Reg::R9);
            }

            off += insn.length;
            ++insn_index;
            if (is_return_like(insn.mnemonic)) break;
        }

        for (const auto& f : found) {
            if (f.invoke == 0 || !seen.insert(f.invoke).second) continue;
            const std::string callback =
                f.selector.empty() ? std::string{} :
                    "_" + objc_name_token(f.selector, "callback");
            out.push_back({
                f.invoke,
                std::format("{}{}__block_invoke", method_ctx, callback),
                f.captures,
                f.self_class
            });
        }
    }

    std::ranges::sort(out, {}, &ObjcStackBlockInvoke::invoke);
    return out;
}

}  // namespace

}  // namespace spelunk::pipeline

namespace spelunk {

using namespace pipeline;

std::vector<ObjcStackBlockInvoke>
discover_objc_stack_block_invokes(const Binary& b) {
    return discover_objc_stack_block_invokes_impl(b);
}

std::vector<DiscoveredFunction>
enumerate_functions(const Binary& b, EnumerateMode mode, addr_t lo, addr_t hi) {
    const bool scoped = hi > lo;
    auto in_scope = [&](addr_t a) noexcept { return !scoped || (a >= lo && a < hi); };

    std::vector<DiscoveredFunction> out;

    // Pass 1: defined function symbols. These carry real sizes, so prefer
    // them when a later CFG-discovered entry lands on the same address.
    std::unordered_map<addr_t, std::size_t> index;
    std::size_t symbol_added = 0;
    for (const auto& s : b.symbols()) {
        if (s.is_import) continue;
        if (s.kind != SymbolKind::Function) continue;
        if ((s.addr == 0 && !b.is_relocatable_object()) || s.name.empty()) continue;
        if (!in_scope(s.addr)) continue;
        if (index.count(s.addr)) continue;
        index.emplace(s.addr, out.size());
        out.push_back({s.addr, s.size, s.name,
                       DiscoveredFunction::Kind::Symbol});
        ++symbol_added;
    }

    constexpr std::size_t kDenseFdeThreshold = 4096;

    // Pass 1.1: unwind metadata. On stripped ELF/Mach-O binaries this is
    // much stronger evidence than bytewise prologue sweeping: an FDE gives
    // both the exact entry and an extent, while a prologue-shaped byte
    // sequence inside a function body is only a guess. Large Android C++
    // libraries in particular can have hundreds of thousands of FDEs; once
    // that metadata is dense, the prologue sweep mostly adds false positives.
    std::size_t unwind_added = 0;
    auto unwind_extents = enumerate_fde_extents(b);
    std::vector<FdeExtent> compact_unwind_extents;
    {
        compact_unwind_extents = enumerate_compact_unwind_extents(b);
        unwind_extents.insert(unwind_extents.end(),
                              compact_unwind_extents.begin(),
                              compact_unwind_extents.end());
    }
    auto add_unwind_extent = [&](const FdeExtent& fde) {
        if ((fde.pc_begin == 0 && !b.is_relocatable_object()) || fde.pc_range == 0) return;
        if (!in_scope(fde.pc_begin)) return;
        if (b.import_at_plt(fde.pc_begin) != nullptr) return;
        if (auto existing = index.find(fde.pc_begin); existing != index.end()) {
            auto& function = out[existing->second];
            if (function.size == 0) function.size = fde.pc_range;
            return;
        }
        index.emplace(fde.pc_begin, out.size());
        out.push_back({fde.pc_begin, fde.pc_range,
                       std::format("sub_{:x}", fde.pc_begin),
                       DiscoveredFunction::Kind::Sub});
        ++unwind_added;
    };
    if (unwind_extents.size() >= kDenseFdeThreshold) {
        for (const auto& fde : unwind_extents) {
            add_unwind_extent(fde);
        }
    } else {
        // Compact-unwind entries are linker-authored function starts, not
        // byte-pattern guesses. Even small Mach-O binaries can rely on them
        // when LC_FUNCTION_STARTS is stripped or sparse.
        for (const auto& fde : compact_unwind_extents) {
            add_unwind_extent(fde);
        }
    }

    // Two address-level gates filter the noise from later passes:
    //   1. Target must land in some executable section.
    //   2. That section must not be encrypted (high entropy).
    //
    // Even on a binary that doesn't trip `binary_looks_packed`, a
    // single high-entropy executable section will usually produce
    // garbage targets. Section-level filtering catches that case
    // without needing the binary-level heuristic to fire.
    //
    // Cache the encrypted-section verdict by Section pointer - without
    // this cache, `section_looks_encrypted(*sec)` runs the O(n) entropy
    // sweep over the whole section once per discovered prologue
    // (~24 k hits on a 14 MB stripped DLL = ~336 GB of byte
    // processing). Dominates cold open by two orders of magnitude.
    const auto& sections = b.sections();
    std::unordered_map<const Section*, bool> encrypted_cache;
    auto is_encrypted_cached = [&](const Section* s) -> bool {
        if (auto it = encrypted_cache.find(s); it != encrypted_cache.end()) {
            return it->second;
        }
        const bool v = section_looks_encrypted(*s);
        encrypted_cache.emplace(s, v);
        return v;
    };
    auto section_for = [&](addr_t a) -> const Section* {
        for (const auto& s : sections) {
            // "Code-shaped" - either flagged exec or named .text /
            // __text / CODE. Byfron / VMProtect strip the exec bit
            // on disk and flip it at runtime; pretending those
            // bytes aren't code drops every discovered function on
            // the floor.
            const bool is_code = s.flags.executable
                || s.name == ".text" || s.name == "__text" || s.name == "CODE"
                || s.name == ".byfron";
            if (!is_code) continue;
            if (a >= s.vaddr && a < s.vaddr + s.size) return &s;
        }
        return nullptr;
    };
    auto ppc_candidate_decodes = [&](addr_t a) -> bool {
        if (b.arch() != Arch::Ppc32 && b.arch() != Arch::Ppc64) return true;
        if ((a & 3u) != 0) return false;
        auto bytes = b.bytes_at(a);
        if (bytes.size() < 4) return false;
        auto dec_r = make_decoder(b);
        if (!dec_r) return false;
        auto insn = (*dec_r)->decode(bytes, a);
        return insn && insn->length == 4;
    };
    auto add_candidate = [&](addr_t a, std::string_view label,
                             bool trusted = false,
                             const std::string* explicit_name = nullptr) {
        if (!in_scope(a)) return;
        if (b.import_at_plt(a) != nullptr) return;
        if (auto existing = index.find(a); existing != index.end()) {
            if (explicit_name && !explicit_name->empty()) {
                auto& fn = out[existing->second];
                if (fn.name.starts_with("sub_")) fn.name = *explicit_name;
            }
            return;
        }
        const Section* sec = section_for(a);
        if (!sec) return;
        if (!ppc_candidate_decodes(a)) return;
        // Trusted entries (vtable pointers from RTTI) bypass the
        // encrypted-section filter - they come from structural
        // metadata in .rdata, not heuristic pattern matching in
        // encrypted code. Even on a packed binary, these are real
        // class methods that will exist after unpacking.
        if (!trusted && mode == EnumerateMode::Auto && is_encrypted_cached(sec)) return;
        index.emplace(a, out.size());
        out.push_back({a, 0,
                       explicit_name ? *explicit_name
                                     : std::format("{}_{:x}", label, a),
                       DiscoveredFunction::Kind::Sub});
    };

    // Pass 1.5: cheap structural discovery. Vtables come from RTTI
    // (already parsed for naming) - every slot is a guaranteed
    // function pointer. Prologue sweep linear-scans executable
    // bytes for x64 prologue patterns and validates each candidate
    // by decoding two instructions. Both run on packed binaries
    // too - RTTI lives in unencrypted .rdata, and the prologue
    // sweep itself skips encrypted sections.
    if (b.format() == Format::Pe) {
        auto msvc_classes = parse_msvc_rtti(b);
        auto rtti_names   = rtti_method_names(msvc_classes);
        for (const auto& cls : msvc_classes) {
            for (addr_t m : cls.methods) {
                if (m == 0) continue;
                if (!in_scope(m)) continue;
                if (!addr_in_code_section(b, m)) continue;
                auto it = rtti_names.find(m);
                add_candidate(m, "sub", true,
                              it != rtti_names.end() ? &it->second : nullptr);
            }
        }
    }
    if (b.format() != Format::Pe) {
        auto itanium_classes = parse_itanium_rtti(b);
        auto rtti_names      = rtti_method_names(itanium_classes);
        for (const auto& cls : itanium_classes) {
            for (addr_t m : cls.methods) {
                if (m == 0) continue;
                if (!in_scope(m)) continue;
                if (!addr_in_code_section(b, m)) continue;
                auto it = rtti_names.find(m);
                add_candidate(m, "sub", true,
                              it != rtti_names.end() ? &it->second : nullptr);
            }
        }
    }
    if (b.format() == Format::MachO) {
        for (const auto& blk : parse_objc_blocks(b)) {
            if (blk.invoke == 0) continue;
            if (!in_scope(blk.invoke)) continue;
            if (!addr_in_code_section(b, blk.invoke)) continue;
            const std::string name = std::format("__block_invoke_{:x}",
                                                 static_cast<u64>(blk.invoke));
            add_candidate(blk.invoke, "sub", true, &name);
        }
        for (const auto& blk : discover_objc_stack_block_invokes(b)) {
            if (blk.invoke == 0) continue;
            if (!in_scope(blk.invoke)) continue;
            if (!addr_in_code_section(b, blk.invoke)) continue;
            add_candidate(blk.invoke, "sub", true, &blk.name);
        }
    }
    const std::size_t before_prologues = out.size();
    if (unwind_extents.size() < kDenseFdeThreshold) {
        for (addr_t a : discover_from_prologues(b, lo, hi)) add_candidate(a, "sub");
    }
    const std::size_t prologue_added = out.size() - before_prologues;
    if (b.format() == Format::Dol || b.arch() == Arch::Ppc32 || b.arch() == Arch::Ppc64) {
        for (addr_t a : discover_code_pointers(b)) add_candidate(a, "sub", true);
    }
    if (timing_enabled()) {
        spelunk::diagnostic::printf("[timing] enumerate_functions.seed: symbols=%zu unwind_extents=%zu unwind_added=%zu prologue=%zu total=%zu\n",
            symbol_added, unwind_extents.size(), unwind_added, prologue_added, out.size());
    }

    // Loader-only mode: on a packed binary the call-graph walker chases
    // garbage targets through encrypted stub code, blocks the UI for
    // ~30s, and pollutes the function list with `sub_…` entries that
    // never decompile. Skip pass 2 - the user can pass --full-analysis
    // if they want it anyway. Pass 1.5 above already gave us anything
    // recoverable from the unencrypted parts of the image.
    //
    // `Cheap` callers (resolve_containing_function on per-function CLI
    // invocations) bail here unconditionally - they only need a
    // best-effort "is this a function entry?" answer, and the call-
    // graph walk costs minutes on big DLLs. Auto mode also bails when
    // symbols/unwind already provide a dense authoritative function map:
    // on modern Mach-O/C++ apps this avoids decoding hundreds of
    // thousands of CFGs just to rediscover call targets for `--functions`.
    const bool dense_authoritative_starts =
        mode == EnumerateMode::Auto &&
        (symbol_added >= kDenseFdeThreshold ||
         unwind_extents.size() >= kDenseFdeThreshold);
    if (mode == EnumerateMode::Cheap ||
        dense_authoritative_starts ||
        (mode == EnumerateMode::Auto && binary_looks_packed(b))) {
        if (unwind_extents.size() >= kDenseFdeThreshold) {
            filter_entries_inside_unwind_extents(out, unwind_extents);
        }
        filter_shadowed_entries(out, b);
        filter_entries_inside_sized_symbols(out);
        fill_unknown_sizes(out, b);
        return out;
    }

    // Pass 2: CFG-walked call targets. Skip PLT stubs (import thunks).
    // Sizes for these are filled in later by fill_unknown_sizes() using the
    // gap to the next discovered function (or section boundary).
    for (const auto& e : compute_call_graph(b)) {
        add_candidate(e.callee, "sub");
    }

    if (unwind_extents.size() >= kDenseFdeThreshold) {
        filter_entries_inside_unwind_extents(out, unwind_extents);
    }
    filter_shadowed_entries(out, b);
    filter_entries_inside_sized_symbols(out);
    fill_unknown_sizes(out, b);
    return out;
}

}  // namespace spelunk
