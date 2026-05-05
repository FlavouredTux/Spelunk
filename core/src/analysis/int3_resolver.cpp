#include <ember/analysis/int3_resolver.hpp>

#include <algorithm>
#include <cstring>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include <ember/analysis/pipeline.hpp>
#include <ember/binary/binary.hpp>
#include <ember/binary/symbol.hpp>
#include <ember/disasm/instruction.hpp>
#include <ember/disasm/x64_decoder.hpp>

namespace ember {

namespace {

struct FnExtent {
    addr_t entry = 0;
    u64    size  = 0;
    std::string name;
};

[[nodiscard]] std::string cc_run_note(u64 count, std::string_view suffix = {}) {
    std::string note = "run of ";
    note += std::to_string(count);
    note += " CC bytes";
    note += suffix;
    return note;
}

// Build a sorted vector of function extents — named symbols + discovered
// sub_* both. Symbol-only would miss 95%+ of code on stripped binaries;
// enumerate_functions(Cheap) does the union.
[[nodiscard]] std::vector<FnExtent>
collect_fn_extents(const Binary& b) {
    std::vector<FnExtent> out;
    for (const auto& fn : enumerate_functions(b, EnumerateMode::Cheap)) {
        if (b.import_at_plt(fn.addr) != nullptr) continue;
        if (fn.addr == 0) continue;
        out.push_back(FnExtent{fn.addr, fn.size, fn.name});
    }
    std::sort(out.begin(), out.end(),
              [](const FnExtent& a, const FnExtent& rhs) {
                  return a.entry < rhs.entry;
              });
    return out;
}

// Binary-search the sorted function extents for the function that
// contains `va`. Returns nullptr when no function covers the address.
[[nodiscard]] const FnExtent*
find_containing_fn(const std::vector<FnExtent>& fns, addr_t va) {
    auto it = std::upper_bound(fns.begin(), fns.end(), va,
                                [](addr_t v, const FnExtent& f) {
                                    return v < f.entry;
                                });
    if (it == fns.begin()) return nullptr;
    --it;
    if (it->size > 0 && va >= it->entry + it->size) return nullptr;
    return &*it;
}

// Known Win32/NT API names used by anti-debug techniques.
constexpr std::string_view kAntiDebugImports[] = {
    "IsDebuggerPresent",
    "NtQueryInformationProcess",
    "CheckRemoteDebuggerPresent",
    "NtQuerySystemInformation",
    "RtlQueryProcessDebugInformation",
    "NtQueryObject",
};

// Known debug-break function names (MSVC intrinsics, Win32 wrappers).
constexpr std::string_view kDebugBreakNames[] = {
    "__debugbreak",
    "DebugBreak",
    "__builtin_debugtrap",
    "_debugbreak",
};

// Check whether any import in the binary matches a known anti-debug
// API name. Returns the set of matching import names.
[[nodiscard]] std::unordered_set<std::string_view>
find_anti_debug_imports(const Binary& b) {
    std::unordered_set<std::string_view> out;
    for (const auto& sym : b.symbols()) {
        if (!sym.is_import) continue;
        for (const auto& name : kAntiDebugImports) {
            if (sym.name == name) {
                out.insert(name);
                break;
            }
        }
    }
    return out;
}

// Check whether a function name matches known debug-break wrappers.
[[nodiscard]] bool is_debug_break_name(std::string_view name) {
    for (const auto& dbn : kDebugBreakNames) {
        if (name == dbn) return true;
        // Also match MSVC-decorated forms like ___debugbreak.
        if (name.find(dbn.substr(2)) != std::string_view::npos) return true;
    }
    return false;
}

// Check whether the function itself is clearly an anti-debug wrapper.
// Import presence alone is not enough evidence: large Windows programs often
// import one of these APIs for unrelated diagnostic paths, and treating every
// embedded int3 as anti-debug would hide real padding or breakpoints.
[[nodiscard]] bool
fn_uses_anti_debug(std::string_view fn_name,
                   const std::unordered_set<std::string_view>& ad_imports) {
    for (const auto& name : ad_imports) {
        if (fn_name.find(name) != std::string_view::npos) return true;
    }
    return false;
}

// Count consecutive 0xCC bytes starting at `va`. Used to detect
// padding runs between/after functions.
[[nodiscard]] u64
count_cc_run(const Binary& b, addr_t va, u64 limit = 64) {
    u64 count = 0;
    for (u64 i = 0; i < limit; ++i) {
        auto span = b.bytes_at(va + i);
        if (span.empty() || span[0] != std::byte{0xCC}) break;
        ++count;
    }
    return count;
}

// Try to recover the original Jcc mnemonic for a stubbed branch.
// Pattern: the instruction immediately before the int3 is a flag-
// setting instruction (cmp, test, add, sub, etc.) and the int3
// occupies the position where a Jcc rel8/rel32 would go. We look
// at the surrounding context:
//   - If a Jcc appears *after* the int3 (at addr+1), the int3
//     might be a dead byte. Not a stub.
//   - If the int3 is at a position where a Jcc would be the
//     natural successor of a flag-setting insn, we check whether
//     the fall-through address (addr+1) decodes as a valid
//     continuation and whether the int3 is the only terminator
//     in the block.
//
// For v1 we use a simpler structural check: look at the decoded
// instruction immediately preceding the int3. If it's a flag-
// setting instruction (Cmp, Test, Add, Sub, And, Or, Xor, Sub,
// etc.) and the int3 is the *only* terminator at the block end,
// the int3 is likely a stubbed Jcc. We can't determine *which*
// Jcc without more context, so we leave the predicate as Unknown
// unless we find a nearby branch that hints at the condition.
//
// A more precise approach: decode a window around the int3 and
// look for a pattern where a flag-setting instruction is followed
// by int3 where a Jcc would naturally appear. The int3's position
// relative to the preceding instruction reveals the branch slot.
[[nodiscard]] bool
is_flag_setting(Mnemonic mn) noexcept {
    switch (mn) {
        case Mnemonic::Cmp:
        case Mnemonic::Test:
        case Mnemonic::Add:
        case Mnemonic::Addi:
        case Mnemonic::Sub:
        case Mnemonic::And:
        case Mnemonic::Or:
        case Mnemonic::Xor:
        case Mnemonic::Shl:
        case Mnemonic::Shr:
        case Mnemonic::Sar:
        case Mnemonic::Neg:
        case Mnemonic::Inc:
        case Mnemonic::Dec:
        case Mnemonic::Imul:
        case Mnemonic::Cdq:
        case Mnemonic::Cqo:
            return true;
        default:
            return false;
    }
}

// Decode instructions starting from `va` until we've decoded `count`
// instructions or run out of bytes. Returns the decoded instructions.
[[nodiscard]] std::vector<Instruction>
decode_window(const Binary& b, addr_t va, unsigned count) {
    const X64Decoder dec;
    std::vector<Instruction> out;
    addr_t pc = va;
    for (unsigned i = 0; i < count; ++i) {
        auto bytes = b.bytes_at(pc);
        if (bytes.empty()) break;
        auto decoded = dec.decode(bytes, pc);
        if (!decoded) break;
        out.push_back(*decoded);
        pc += decoded->length;
        if (decoded->length == 0) break;  // safety
    }
    return out;
}

// Attempt to recover the Jcc predicate for a stubbed branch at
// `int3_addr` inside function `fn_entry`. Strategy:
//   1. Decode a few instructions before the int3.
//   2. If the immediately preceding instruction is a flag-setter,
//      the int3 likely stubbed a Jcc that tested those flags.
//   3. Look at the fall-through block (after int3) for a matching
//      Jcc that reveals the condition — obfuscators sometimes
//      leave the complementary branch or a duplicate.
//   4. If no Jcc is found nearby, we can't determine the specific
//      predicate — return nullopt.
[[nodiscard]] std::optional<BranchPredicate>
recover_predicate(const Binary& b, addr_t int3_addr, addr_t fn_entry) {
    // Decode 8 instructions before the int3.
    const X64Decoder dec;
    std::vector<Instruction> before;
    addr_t pc = fn_entry;
    // Walk from function entry to the int3, collecting instructions.
    while (pc < int3_addr) {
        auto bytes = b.bytes_at(pc);
        if (bytes.empty()) break;
        auto decoded = dec.decode(bytes, pc);
        if (!decoded) break;
        before.push_back(*decoded);
        pc += decoded->length;
        if (decoded->length == 0) break;
    }

    // Check the instruction immediately before the int3.
    if (!before.empty()) {
        const auto& prev = before.back();
        if (is_flag_setting(prev.mnemonic)) {
            // The int3 follows a flag-setting instruction — likely
            // a stubbed Jcc. Look at the fall-through for a hint.
            auto after = decode_window(b, int3_addr + 1, 4);
            for (const auto& insn : after) {
                if (auto pred = mnemonic_to_predicate(insn.mnemonic)) {
                    // Found a Jcc right after the int3 — this might
                    // be the complementary branch or a re-emit of the
                    // original condition. Return it as our best guess.
                    return pred;
                }
                if (insn.mnemonic == Mnemonic::Jmp ||
                    insn.mnemonic == Mnemonic::Ret) {
                    break;  // block boundary, stop looking
                }
            }
            // No Jcc found after — we know it's a stubbed branch
            // but can't determine which predicate. Return nullopt;
            // the caller will mark it as StubbedBranch without a
            // specific predicate.
        }
    }

    return std::nullopt;
}

}  // namespace

std::vector<Int3Resolution>
resolve_embedded_int3s(const Binary& b) {
    if (b.arch() != Arch::X86_64 && b.arch() != Arch::X86) {
        return {};
    }

    const auto ad_imports = find_anti_debug_imports(b);
    const X64Decoder dec;

    std::vector<Int3Resolution> out;

    // Walk each function's decoded instruction stream — named + discovered.
    // Symbol-only would silently skip the bulk of a stripped binary.
    for (const auto& fn : enumerate_functions(b, EnumerateMode::Cheap)) {
        if (b.import_at_plt(fn.addr) != nullptr) continue;
        if (fn.addr == 0) continue;

        const addr_t fn_entry = fn.addr;
        const u64 fn_size = fn.size > 0 ? fn.size : 256;  // cap for size-0 entries

        addr_t pc = fn_entry;
        const addr_t fn_end = fn_entry + fn_size;

        while (pc < fn_end) {
            auto bytes = b.bytes_at(pc);
            if (bytes.empty()) break;
            auto decoded = dec.decode(bytes, pc);
            if (!decoded) { ++pc; continue; }

            if (decoded->mnemonic == Mnemonic::Int3) {
                Int3Resolution res;
                res.addr = pc;
                res.containing_fn = fn_entry;
                res.fn_offset = pc - fn_entry;

                // Classification priority:
                // 1. DebugBreak (most specific)
                // 2. StubbedBranch (most useful)
                // 3. AntiDebug (heuristic)
                // 4. Unknown (fallback)

                if (is_debug_break_name(fn.name)) {
                    res.kind = Int3Kind::DebugBreak;
                    res.note = "inside debug-break wrapper '";
                    res.note += fn.name;
                    res.note += "'";
                } else {
                    // Try stubbed-branch detection: decode backwards
                    // from int3 to find the previous instruction boundary.
                    for (u64 back = 1; back < 16 && back <= pc - fn_entry; ++back) {
                        addr_t try_start = pc - back;
                        auto try_bytes = b.bytes_at(try_start);
                        if (try_bytes.empty()) continue;
                        auto try_dec = dec.decode(try_bytes, try_start);
                        if (!try_dec) continue;
                        if (try_start + try_dec->length == pc) {
                            // Found the instruction right before int3.
                            if (is_flag_setting(try_dec->mnemonic)) {
                                res.kind = Int3Kind::StubbedBranch;
                                // Try to recover the predicate.
                                auto recovered = recover_predicate(b, pc, fn_entry);
                                if (recovered) {
                                    res.predicate = recovered;
                                    // Map predicate back to a mnemonic
                                    // for the original_mnemonic field.
                                    for (int mi = static_cast<int>(Mnemonic::Jo);
                                         mi <= static_cast<int>(Mnemonic::Jg); ++mi) {
                                        auto m = static_cast<Mnemonic>(mi);
                                        if (mnemonic_to_predicate(m) == recovered) {
                                            res.original_mnemonic = m;
                                            break;
                                        }
                                    }
                                    res.note = "stubbed ";
                                    res.note += format_instruction(*try_dec);
                                    res.note += " (predicate: ";
                                    res.note += branch_predicate_name(*recovered);
                                    res.note += ")";
                                } else {
                                    res.note = "stubbed branch after ";
                                    res.note += format_instruction(*try_dec);
                                    res.note += " (predicate unknown)";
                                }
                                // Fall-through is the byte after int3.
                                res.branch_target = pc + 1;
                            }
                            break;
                        }
                    }

                    if (res.kind == Int3Kind::Unknown) {
                        // Not a stubbed branch. Check anti-debug.
                        if (fn_uses_anti_debug(fn.name, ad_imports)) {
                            res.kind = Int3Kind::AntiDebug;
                            std::string import_list;
                            for (const auto& name : ad_imports) {
                                if (!import_list.empty()) import_list += ", ";
                                import_list += name;
                            }
                            res.note = "binary imports anti-debug API(s): ";
                            res.note += import_list;
                        } else {
                            res.kind = Int3Kind::Unknown;
                            res.note = "int3 inside function";
                        }
                    }
                }

                out.push_back(std::move(res));
            }

            pc += decoded->length;
            if (decoded->length == 0) break;  // safety
        }
    }

    // Also scan inter-function gaps for CC padding. Union with discovered
    // entries so the gap definition is correct on stripped binaries —
    // otherwise "the gap between symbol A and symbol B" overshoots into
    // dozens of intervening discovered subs.
    std::vector<std::pair<addr_t, u64>> fn_ranges;  // (entry, size)
    for (const auto& fn : enumerate_functions(b, EnumerateMode::Cheap)) {
        if (b.import_at_plt(fn.addr) != nullptr) continue;
        if (fn.addr == 0 || fn.size == 0) continue;
        fn_ranges.emplace_back(fn.addr, fn.size);
    }
    std::sort(fn_ranges.begin(), fn_ranges.end());

    // Helper: scan a gap [gap_start, gap_end) for CC padding runs.
    auto scan_gap = [&](addr_t gap_start, addr_t gap_end) {
        if (gap_start >= gap_end) return;
        addr_t va = gap_start;
        while (va < gap_end) {
            auto span = b.bytes_at(va);
            if (span.empty() || span[0] != std::byte{0xCC}) {
                ++va;
                continue;
            }
            const u64 cc_run = count_cc_run(b, va, gap_end - va);
            if (cc_run >= 2) {
                Int3Resolution res;
                res.addr = va;
                res.kind = Int3Kind::Padding;
                res.note = cc_run_note(cc_run, " between functions");
                out.push_back(std::move(res));
                va += cc_run;
            } else {
                ++va;
            }
        }
    };

    // For each executable section, determine how much of it is covered
    // by known functions. Sections with little/no function coverage get
    // a full linear-sweep decode (stripped/packed binaries).
    for (const auto& sec : b.sections()) {
        if (!sec.flags.executable) continue;
        if (sec.size == 0 || sec.data.empty()) continue;

        // Compute total bytes covered by known functions in this section.
        u64 covered = 0;
        for (const auto& [entry, size] : fn_ranges) {
            if (entry >= sec.vaddr && entry < sec.vaddr + sec.size) {
                covered += size;
            }
        }

        // If functions cover less than 10% of the section, do a full
        // linear sweep — the binary is stripped/packed and the symbol
        // table is useless.
        const bool needs_sweep = (covered * 10 < sec.size);

        if (needs_sweep) {
            // Before doing a full linear sweep, sample the first 4KB
            // to check if the section is actually decodable. Packed
            // sections (Byfron, Themida, VMProtect) have high entropy
            // and the decoder will fail on most bytes — wasting time
            // and producing garbage. If the decode-failure rate in the
            // sample exceeds 80%, skip the section entirely.
            {
                constexpr u64 kSampleSize = 4096;
                const addr_t sample_end = std::min(sec.vaddr + kSampleSize,
                                                     sec.vaddr + sec.size);
                u64 total = 0;
                u64 failures = 0;
                addr_t sample_pc = sec.vaddr;
                while (sample_pc < sample_end) {
                    auto sample_bytes = b.bytes_at(sample_pc);
                    if (sample_bytes.empty()) break;
                    auto sample_dec = dec.decode(sample_bytes, sample_pc);
                    ++total;
                    if (!sample_dec) ++failures;
                    sample_pc += sample_dec ? sample_dec->length : addr_t{1};
                    if (total >= 200) break;  // enough samples
                }
                if (total > 50 && failures * 10 > total * 8) {
                    // >80% failure rate — section is packed. Skip.
                    continue;
                }
            }

            // Linear sweep: decode every instruction in the section.
            addr_t pc = sec.vaddr;
            const addr_t sec_end = sec.vaddr + sec.size;

            while (pc < sec_end) {
                auto bytes = b.bytes_at(pc);
                if (bytes.empty()) break;
                auto decoded = dec.decode(bytes, pc);
                if (!decoded) { ++pc; continue; }

                if (decoded->mnemonic == Mnemonic::Int3) {
                    // Don't re-emit if we already classified this one
                    // from a known function above.
                    bool already = false;
                    for (const auto& r : out) {
                        if (r.addr == pc) { already = true; break; }
                    }
                    if (already) { pc += decoded->length; continue; }

                    Int3Resolution res;
                    res.addr = pc;

                    // Try to find a containing function.
                    const FnExtent* fn = find_containing_fn(
                        collect_fn_extents(b), pc);
                    if (fn) {
                        res.containing_fn = fn->entry;
                        res.fn_offset = pc - fn->entry;
                    }

                    // Stubbed-branch detection: look at the instruction
                    // before the int3.
                    for (u64 back = 1; back < 16 && back <= pc - sec.vaddr; ++back) {
                        addr_t try_start = pc - back;
                        auto try_bytes = b.bytes_at(try_start);
                        if (try_bytes.empty()) continue;
                        auto try_dec = dec.decode(try_bytes, try_start);
                        if (!try_dec) continue;
                        if (try_start + try_dec->length == pc) {
                            if (is_flag_setting(try_dec->mnemonic)) {
                                res.kind = Int3Kind::StubbedBranch;
                                // Try to recover predicate from the
                                // fall-through block.
                                auto after = decode_window(b, pc + 1, 4);
                                for (const auto& insn : after) {
                                    if (auto pred = mnemonic_to_predicate(insn.mnemonic)) {
                                        res.predicate = pred;
                                        res.original_mnemonic = insn.mnemonic;
                                        break;
                                    }
                                    if (insn.mnemonic == Mnemonic::Jmp ||
                                        insn.mnemonic == Mnemonic::Ret) {
                                        break;
                                    }
                                }
                                if (res.predicate) {
                                    res.note = "stubbed branch (predicate: ";
                                    res.note += branch_predicate_name(*res.predicate);
                                    res.note += ")";
                                } else {
                                    res.note = "stubbed branch (predicate unknown)";
                                }
                                res.branch_target = pc + 1;
                            }
                            break;
                        }
                    }

                    if (res.kind == Int3Kind::Unknown) {
                        // Check if it's a padding run.
                        const u64 cc_run = count_cc_run(b, pc);
                        if (cc_run >= 4) {
                            res.kind = Int3Kind::Padding;
                            res.note = cc_run_note(cc_run);
                        } else {
                            res.kind = Int3Kind::Unknown;
                            res.note = "int3 in executable section";
                        }
                    }

                    out.push_back(std::move(res));
                }

                pc += decoded->length;
                if (decoded->length == 0) break;  // safety
            }
        } else {
            // Section is well-covered by known functions. Just scan
            // the gaps between functions for padding.
            if (!fn_ranges.empty()) {
                // Gap from section start to first function.
                if (fn_ranges.front().first > sec.vaddr) {
                    scan_gap(sec.vaddr, fn_ranges.front().first);
                }

                // Gaps between consecutive functions.
                for (std::size_t i = 0; i + 1 < fn_ranges.size(); ++i) {
                    const addr_t gap_start = fn_ranges[i].first + fn_ranges[i].second;
                    const addr_t gap_end = fn_ranges[i + 1].first;
                    if (gap_start >= sec.vaddr && gap_end <= sec.vaddr + sec.size) {
                        scan_gap(gap_start, gap_end);
                    }
                }

                // Gap from last function to section end.
                const addr_t last_end = fn_ranges.back().first + fn_ranges.back().second;
                if (last_end < sec.vaddr + sec.size) {
                    scan_gap(last_end, sec.vaddr + sec.size);
                }
            }
        }
    }

    std::sort(out.begin(), out.end(),
              [](const Int3Resolution& a, const Int3Resolution& rhs) {
                  return a.addr < rhs.addr;
              });

    return out;
}

Int3Resolution
resolve_int3_at(const Binary& b, addr_t va) {
    // Quick check: is there actually a 0xCC at this address?
    auto span = b.bytes_at(va);
    if (span.empty() || span[0] != std::byte{0xCC}) {
        Int3Resolution res;
        res.addr = va;
        res.kind = Int3Kind::Unknown;
        res.note = "no CC byte at address";
        return res;
    }

    // Run the full scan and find the entry for this address.
    auto all = resolve_embedded_int3s(b);
    auto it = std::lower_bound(all.begin(), all.end(), va,
                                [](const Int3Resolution& r, addr_t a) {
                                    return r.addr < a;
                                });
    if (it != all.end() && it->addr == va) {
        return *it;
    }

    Int3Resolution res;
    res.addr = va;
    res.kind = Int3Kind::Unknown;
    res.note = "not found in embedded int3 scan";
    return res;
}

}  // namespace ember
