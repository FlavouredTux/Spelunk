#include <spelunk/common/diagnostic.hpp>
// Disassembly windows, patch plans, syscalls and forge specs.

#include <charconv>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <format>
#include <fstream>
#include <iterator>
#include <limits>
#include <print>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <spelunk/analysis/forge_spec.hpp>
#include <spelunk/analysis/identify.hpp>
#include <spelunk/analysis/pipeline.hpp>
#include <spelunk/analysis/syscalls.hpp>
#include <spelunk/common/annotations.hpp>
#include <spelunk/common/types.hpp>
#include <spelunk/disasm/instruction.hpp>
#include <spelunk/disasm/decoder.hpp>

#include "../args.hpp"
#include "../cli_error.hpp"
#include "../subcommands.hpp"
#include "../util.hpp"
#include "common.hpp"

namespace spelunk::cli {

namespace {

[[nodiscard]] bool parse_disasm_count(std::string_view raw,
                                      std::size_t& out,
                                      std::string_view command) {
    if (raw.empty()) return true;
    u64 n = 0;
    const auto* first = raw.data();
    const auto* last = raw.data() + raw.size();
    const auto r = std::from_chars(first, last, n, 10);
    constexpr u64 kMaxCount =
        static_cast<u64>(std::numeric_limits<addr_t>::max() / 15);
    if (r.ec != std::errc{} || r.ptr != last || n == 0 || n > kMaxCount) {
        spelunk::diagnostic::print("spelunk: {}: bad --count '{}'", command, raw);
        return false;
    }
    out = static_cast<std::size_t>(n);
    return true;
}

[[nodiscard]] std::string patch_strategy(const DisasmProbe& p) {
    if (p.steal_len < 14) return "insufficient-bytes";
    if (p.safe_abs_trampoline) return "absolute-jump-ok";
    if (p.needs_relocation) return "copy-with-relocation";
    return "manual-review";
}

[[nodiscard]] std::optional<bool>
is_instruction_boundary(const Binary& b, addr_t address) {
    auto containing = containing_function(b, address);
    if (!containing) return std::nullopt;
    if (containing->entry == address) return true;
    if (containing->size != 0 && address >= containing->entry + containing->size)
        return std::nullopt;
    auto decoder = make_decoder(b);
    if (!decoder) return std::nullopt;
    addr_t pc = containing->entry;
    std::size_t budget = containing->size != 0
        ? static_cast<std::size_t>(containing->size)
        : 1u << 20;
    while (pc < address && budget) {
        auto decoded = (*decoder)->decode(b.bytes_at(pc), pc);
        if (!decoded || decoded->length == 0 || decoded->length > budget)
            return std::nullopt;
        pc += decoded->length;
        budget -= decoded->length;
    }
    return pc == address;
}

}  // namespace

int run_patch_plan(const Args& args, const Binary& b) {
    auto va = parse_cli_addr(args.patch_plan);
    if (!va) {
        spelunk::diagnostic::print("spelunk: --patch-plan: bad address '{}'", args.patch_plan);
        return EXIT_FAILURE;
    }
    if (!addr_in_executable_section_cli(b, *va)) {
        spelunk::diagnostic::print("spelunk: --patch-plan: {:#x} is not in executable code", *va);
        return EXIT_FAILURE;
    }
    auto probe = decode_disasm_probe(b, *va, 12);
    if (!probe) return report(probe.error());
    const auto& p = *probe;

    auto hazard_json = [&](const Instruction& insn) {
        std::string bytes;
        for (u8 j = 0; j < insn.length; ++j) {
            if (j) bytes.push_back(' ');
            std::format_to(std::back_inserter(bytes), "{:02x}",
                           std::to_integer<unsigned>(insn.raw_bytes[j]));
        }
        std::string out = std::format(
            "{{\"va\":\"{:#x}\",\"bytes\":\"{}\",\"text\":\"{}\"",
            insn.address, bytes, json_escape(format_instruction(insn)));
        if (auto bt = branch_target(insn); bt) {
            out += std::format(",\"branch_target\":\"{:#x}\"", *bt);
        }
        if (auto rt = cli_rip_relative_target(insn); rt) {
            out += std::format(",\"rip_relative_target\":\"{:#x}\"", *rt);
        }
        out += std::format(
            ",\"rip_relative\":{},\"short_branch\":{},\"rel32_branch_or_call\":{}}}",
            cli_rip_relative_target(insn) ? "true" : "false",
            is_short_relative_branch(insn) ? "true" : "false",
            is_rel32_call_or_jump(insn) ? "true" : "false");
        return out;
    };

    if (args.json) {
        std::string out = std::format(
            "{{\"va\":\"{:#x}\",\"recommended_steal_len\":{},"
            "\"needs_relocation\":{},\"first_basic_block_end\":\"{:#x}\","
            "\"safe_absolute_jump_trampoline\":{},\"strategy\":\"{}\","
            "\"instructions\":[",
            *va, p.steal_len,
            p.needs_relocation ? "true" : "false",
            p.first_bb_end,
            p.safe_abs_trampoline ? "true" : "false",
            patch_strategy(p));
        for (std::size_t i = 0; i < p.insns.size(); ++i) {
            if (i) out += ',';
            out += hazard_json(p.insns[i]);
        }
        out += "]}\n";
        std::fwrite(out.data(), 1, out.size(), stdout);
        return EXIT_SUCCESS;
    }

    std::println("patch-plan\t{:#x}", *va);
    std::println("strategy\t{}", patch_strategy(p));
    std::println("steal_len\t{}", p.steal_len);
    std::println("needs_relocation\t{}", p.needs_relocation ? "yes" : "no");
    std::println("first_basic_block_end\t{:#x}", p.first_bb_end);
    std::println("safe_absolute_jump_trampoline\t{}",
                 p.safe_abs_trampoline ? "yes" : "no");
    std::println("instructions");
    for (const auto& insn : p.insns) {
        std::vector<std::string> hazards;
        if (cli_rip_relative_target(insn)) hazards.emplace_back("rip-relative");
        if (is_short_relative_branch(insn)) hazards.emplace_back("short-branch");
        if (is_rel32_call_or_jump(insn)) hazards.emplace_back("rel32-branch-or-call");
        std::string hz = hazards.empty() ? "-" : hazards.front();
        for (std::size_t i = 1; i < hazards.size(); ++i) {
            hz += ",";
            hz += hazards[i];
        }
        std::println("{:#x}\t{}\t{}", insn.address, hz, format_instruction(insn));
    }
    return EXIT_SUCCESS;
}

int run_disasm_at(const Args& args, const Binary& b) {
    // Shared FN|VA resolver: accepts a symbol name as well as a raw
    // VA, and reports the failure reason itself (bad address vs no
    // such symbol) - so this returns silently on failure.
    auto va = resolve_flag_target(b, args, args.disasm_at);
    if (!va) return EXIT_FAILURE;
    std::size_t count = 32;
    if (!parse_disasm_count(args.disasm_count, count, "--disasm-at")) {
        return EXIT_FAILURE;
    }
    const auto boundary = is_instruction_boundary(b, *va);
    if (boundary == false) {
        spelunk::diagnostic::print(
            "spelunk: --disasm-at: warning: {:#x} is not an instruction boundary in its containing function",
            *va);
    }
    if (args.json) {
        auto out = disasm_probe_json(b, static_cast<addr_t>(*va), count);
        if (!out) {
            const std::string error = std::format(
                "{{\"error\":\"{}\"}}\n", json_escape(out.error().message));
            std::fwrite(error.data(), 1, error.size(), stdout);
            return EXIT_FAILURE;
        }
        std::fwrite(out->data(), 1, out->size(), stdout);
        return EXIT_SUCCESS;
    }
    // 8 bytes/insn is the typical x86-64 average; ~15 bytes is the max.
    const addr_t end = static_cast<addr_t>(*va) +
                       static_cast<addr_t>(count * 15);
    auto rv = format_disasm_range(b, static_cast<addr_t>(*va), end);
    if (!rv) return report(rv.error());
    // Trim to N lines of disassembly (skip the header/comments).
    std::size_t emitted = 0;
    std::string out;
    if (boundary == false) {
        out += std::format(
            "; warning: {:#x} is not an instruction boundary; decoding starts mid-instruction\n",
            *va);
    }
    if (!addr_in_executable_section_cli(b, static_cast<addr_t>(*va))) {
        const auto sec = section_name_containing(b, static_cast<addr_t>(*va));
        if (!sec.empty()) {
            out += std::format(
                "; warning: {:#x} is in non-executable section {}; bytes may be data\n",
                static_cast<addr_t>(*va), sec);
        } else {
            out += std::format(
                "; warning: {:#x} is not in an executable section; bytes may be data\n",
                static_cast<addr_t>(*va));
        }
    }
    out += disasm_probe_summary(b, static_cast<addr_t>(*va), count);
    std::size_t line_start = 0;
    for (std::size_t i = 0; i <= rv->size(); ++i) {
        if (i == rv->size() || (*rv)[i] == '\n') {
            const std::string_view line(rv->data() + line_start, i - line_start);
            out.append(line);
            out += '\n';
            // Count only disasm lines (start with address or whitespace
            // on continuation). Comments start with ';'.
            if (!line.empty() && line.front() != ';') ++emitted;
            if (emitted >= count) break;
            line_start = i + 1;
        }
    }
    std::print("{}", out);
    return EXIT_SUCCESS;
}

int run_disasm_window(const Args& args, const Binary& b) {
    // Batch sibling of --disasm-at. Accepts a comma-separated VA list
    // (`0x...,sub_...,...`) or `@PATH` to read VAs one-per-line from a
    // file, runs the same per-VA window each --disasm-at does, and
    // separates blocks with a `# <hex-va>` line so a downstream
    // splitter can pull them apart. Saves the per-invocation
    // spelunk startup cost when sweeping thousands of refs-to / scan
    // hits.
    std::vector<addr_t> vas;
    auto push_va = [&](std::string_view tok) -> bool {
        // Trim whitespace.
        while (!tok.empty() && (tok.front() == ' ' || tok.front() == '\t' ||
                                tok.front() == '\r')) tok.remove_prefix(1);
        while (!tok.empty() && (tok.back() == ' ' || tok.back() == '\t' ||
                                tok.back() == '\r')) tok.remove_suffix(1);
        if (tok.empty()) return true;
        auto a = parse_cli_addr(tok);
        if (!a) {
            spelunk::diagnostic::print("spelunk: --disasm-window: bad address '{}'", tok);
            return false;
        }
        vas.push_back(*a);
        return true;
    };

    const std::string_view raw = args.disasm_window;
    if (!raw.empty() && raw.front() == '@') {
        // File source: one VA per line, blank lines and `#`-prefixed
        // comment lines skipped.
        const std::string path{raw.substr(1)};
        std::ifstream f(path);
        if (!f) {
            spelunk::diagnostic::print("spelunk: --disasm-window: cannot open '{}'", path);
            return EXIT_FAILURE;
        }
        std::string line;
        while (std::getline(f, line)) {
            std::string_view sv = line;
            while (!sv.empty() && (sv.front() == ' ' || sv.front() == '\t')) sv.remove_prefix(1);
            if (sv.empty() || sv.front() == '#') continue;
            if (!push_va(sv)) return EXIT_FAILURE;
        }
    } else {
        std::size_t start = 0;
        for (std::size_t i = 0; i <= raw.size(); ++i) {
            if (i == raw.size() || raw[i] == ',') {
                if (!push_va(raw.substr(start, i - start))) return EXIT_FAILURE;
                start = i + 1;
            }
        }
    }

    if (vas.empty()) {
        spelunk::diagnostic::print("spelunk: --disasm-window: empty VA list");
        return EXIT_FAILURE;
    }

    std::size_t count = 32;
    if (!parse_disasm_count(args.disasm_count, count, "--disasm-window")) {
        return EXIT_FAILURE;
    }

    auto window_for_va = [&](addr_t va) -> std::string {
        // Mirror run_disasm_at: 15 bytes/insn upper bound, then trim to
        // `count` non-comment lines after the formatter returns.
        const addr_t end = va + static_cast<addr_t>(count * 15);
        auto rv = format_disasm_range(b, va, end);
        if (!rv) {
            return std::format("# error: {}\n", rv.error().message);
        }
        std::string out;
        if (!addr_in_executable_section_cli(b, va)) {
            const auto sec = section_name_containing(b, va);
            if (!sec.empty()) {
                out += std::format(
                    "; warning: {:#x} is in non-executable section {}; bytes may be data\n",
                    va, sec);
            } else {
                out += std::format(
                    "; warning: {:#x} is not in an executable section; bytes may be data\n",
                    va);
            }
        }
        std::size_t emitted = 0;
        std::size_t line_start = 0;
        for (std::size_t i = 0; i <= rv->size(); ++i) {
            if (i == rv->size() || (*rv)[i] == '\n') {
                const std::string_view line(rv->data() + line_start, i - line_start);
                out.append(line);
                out += '\n';
                if (!line.empty() && line.front() != ';') ++emitted;
                if (emitted >= count) break;
                line_start = i + 1;
            }
        }
        return out;
    };

    if (args.json) {
        std::string out = "[";
        bool first = true;
        for (addr_t va : vas) {
            if (!first) out += ',';
            first = false;
            const std::string body = window_for_va(va);
            out += std::format("{{\"addr\":\"{:#x}\",\"disasm\":\"{}\"}}",
                               va, json_escape(body));
        }
        out += "]\n";
        std::fwrite(out.data(), 1, out.size(), stdout);
    } else {
        std::string out;
        for (addr_t va : vas) {
            out += std::format("# {:#x}\n", va);
            out += window_for_va(va);
        }
        std::fwrite(out.data(), 1, out.size(), stdout);
    }
    return EXIT_SUCCESS;
}

int run_list_syscalls(const Args& args, const Binary& b) {
    // Resolve target - accept symbol-by-name (`-s NAME`-style strings),
    // hex VA, or `sub_<hex>`. The address is the function entry the
    // syscall walker starts decoding from; mid-function VAs get
    // rebound to the containing function's start, same as `-p`.
    const Annotations syscalls_ann = load_annotations_quiet(args);
    auto win = resolve_function(b, args.list_syscalls, &syscalls_ann);
    if (!win) return EXIT_FAILURE;  // resolve_function already printed

    auto sites = analyze_syscalls(b, win->start);
    // Format: TSV `<file_offset>\t<va>\t<nr>\t<name>` per site, with
    // `?` for unresolved nr / name. file_offset is what you `dd
    // skip=…` to the binary to land on the syscall byte; va is the
    // runtime address; nr is the resolved syscall number; name is
    // the Linux x86-64 syscall name when nr matched the table.
    for (const auto& s : sites) {
        std::print("{:#x}\t{:#x}\t",
                   static_cast<unsigned long long>(s.file_offset),
                   static_cast<unsigned long long>(s.va));
        if (s.syscall_nr) {
            std::print("{}\t", *s.syscall_nr);
        } else {
            std::print("?\t");
        }
        std::print("{}\n", s.name.empty() ? std::string{"?"} : s.name);
    }
    return EXIT_SUCCESS;
}

int run_forge_spec(const Args& args, const Binary& b) {
    // --forge-spec accepts ENTRY:VA. ENTRY = symbol name | hex VA | sub_<hex>;
    // VA = hex | sub_<hex>. Both halves are required; bail with a useful
    // error otherwise (mirroring how --apply-patches refuses malformed
    // input rather than silently doing nothing).
    const std::string_view raw = args.forge_spec;
    const auto colon = raw.find(':');
    if (colon == std::string_view::npos) {
        spelunk::diagnostic::print("spelunk: --forge-spec: expected ENTRY:VA, got '{}'", raw);
        return EXIT_FAILURE;
    }
    const std::string_view entry_tok = raw.substr(0, colon);
    const std::string_view target_tok = raw.substr(colon + 1);

    const Annotations forge_ann = load_annotations_quiet(args);
    auto entry_win = resolve_function(b, entry_tok, &forge_ann);
    if (!entry_win) return EXIT_FAILURE;  // resolve_function already printed

    auto target_va = parse_cli_addr(target_tok);
    if (!target_va) {
        spelunk::diagnostic::print("spelunk: --forge-spec: bad target VA '{}'", target_tok);
        return EXIT_FAILURE;
    }

    auto spec = infer_forge_spec(b, entry_win->start, *target_va);
    if (!spec) return report(spec.error());

    if (args.json) {
        std::print("{}\n", format_forge_spec_json(*spec));
    } else {
        std::print("{}", format_forge_spec(*spec));
    }
    return EXIT_SUCCESS;
}

}  // namespace spelunk::cli
