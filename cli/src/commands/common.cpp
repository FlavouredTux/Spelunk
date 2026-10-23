#include <spelunk/common/diagnostic.hpp>
// Helpers shared by more than one command group.

#include "common.hpp"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdio>
#include <expected>
#include <filesystem>
#include <format>
#include <iterator>
#include <optional>
#include <print>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_set>
#include <utility>
#include <vector>

#include <spelunk/analysis/identify.hpp>
#include <spelunk/analysis/pipeline.hpp>
#include <spelunk/analysis/sigs.hpp>
#include <spelunk/analysis/vtables.hpp>
#include <spelunk/binary/arch.hpp>
#include <spelunk/binary/binary.hpp>
#include <spelunk/binary/symbol.hpp>
#include <spelunk/common/annotations.hpp>
#include <spelunk/common/bytes.hpp>
#include <spelunk/common/cache.hpp>
#include <spelunk/common/error.hpp>
#include <spelunk/common/timing.hpp>
#include <spelunk/common/types.hpp>
#include <spelunk/decompile/emit_options.hpp>
#include <spelunk/disasm/decoder.hpp>
#include <spelunk/disasm/instruction.hpp>
#include <spelunk/disasm/register.hpp>

#include "../args.hpp"
#include "../subcommands.hpp"
#include "../util.hpp"

namespace spelunk::cli {

Annotations load_annotations_quiet(const Args& args) {
    Annotations ann;
    const std::filesystem::path cache_dir =
        !args.cache_dir.empty() ? std::filesystem::path{args.cache_dir}
                                : cache::default_dir();
    auto loc = resolve_annotation_location(args.binary, args.annotations_path, cache_dir);
    if (args.no_cache && loc.source == AnnotationSource::Cache) return ann;
    if (loc.source == AnnotationSource::None || loc.path.empty()) return ann;
    std::error_code ec;
    if (!std::filesystem::exists(loc.path, ec) || ec) return ann;
    if (auto rv = Annotations::load(loc.path); rv) ann = std::move(*rv);
    return ann;
}

bool looks_like_address(std::string_view spec) noexcept {
    // Judge shape with surrounding whitespace trimmed.
    while (!spec.empty() &&
           (spec.front() == ' ' || spec.front() == '\t')) {
        spec.remove_prefix(1);
    }
    while (!spec.empty() && (spec.back() == ' ' || spec.back() == '\t')) {
        spec.remove_suffix(1);
    }
    if (spec.empty()) return false;
    if (spec.starts_with("0x") || spec.starts_with("0X") ||
        spec.starts_with("sub_")) {
        return true;
    }
    if (spec.size() > 64) return false;
    for (const char c : spec) {
        const bool hex = (c >= '0' && c <= '9') ||
                         (c >= 'a' && c <= 'f') ||
                         (c >= 'A' && c <= 'F');
        if (!hex) return false;
    }
    return true;
}

std::optional<addr_t> resolve_flag_target(const Binary& b,
                                                        const Args& args,
                                                        std::string_view spec) {
    if (auto va = parse_cli_addr(spec)) return *va;
    if (looks_like_address(spec)) {
        spelunk::diagnostic::print("spelunk: invalid address '{}'", spec);
        return std::nullopt;
    }
    const Annotations ann = load_annotations_quiet(args);
    if (auto win = resolve_function(b, spec, &ann)) return win->start;
    return std::nullopt;
}

ModuleScope resolve_module_scope(const Binary& b,
                                               std::string_view name) {
    ModuleScope ms;
    if (name.empty()) return ms;

    auto lc = [](std::string_view s) {
        std::string out(s);
        for (auto& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return out;
    };
    const std::string needle = lc(name);

    std::vector<const Symbol*> candidates;
    for (const auto& s : b.symbols()) {
        if (s.kind != SymbolKind::Section) continue;   // module spans only
        if (s.size == 0) continue;
        if (lc(s.name).find(needle) != std::string::npos) {
            candidates.push_back(&s);
        }
    }

    if (candidates.empty()) {
        spelunk::diagnostic::print("spelunk: --module '{}' matched no loaded module", name);
        spelunk::diagnostic::print("spelunk: available modules:");
        for (const auto& s : b.symbols()) {
            if (s.kind != SymbolKind::Section) continue;
            if (s.size == 0) continue;
            spelunk::diagnostic::print("  {}\t{:#x}\t{:#x}", s.name, s.addr, s.size);
        }
        return ms;   // inactive - caller should bail
    }
    if (candidates.size() > 1) {
        spelunk::diagnostic::print("spelunk: --module '{}' is ambiguous ({} matches); using first ({})",
            name, candidates.size(), candidates.front()->name);
        for (const auto* c : candidates) {
            spelunk::diagnostic::print("  {}\t{:#x}\t{:#x}", c->name, c->addr, c->size);
        }
    }
    ms.lo = candidates.front()->addr;
    ms.hi = candidates.front()->addr + candidates.front()->size;
    ms.matched_name = candidates.front()->name;
    ms.active = true;
    spelunk::diagnostic::print("spelunk: --module '{}' resolved to {} [{:#x}, {:#x})",
        name, ms.matched_name, ms.lo, ms.hi);
    return ms;
}

std::vector<addr_t>
compute_callers_to_fast(const Binary& b, addr_t want) {
    std::vector<addr_t> out;
    for (const CallSite& s : compute_call_sites_to_fast(b, want)) out.push_back(s.function);
    std::ranges::sort(out);
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

std::vector<CallSite>
compute_call_sites_to_fast(const Binary& b, addr_t want) {
    ScopedTimer total_timer("callers_to_fast.total");
    auto dec_r = make_decoder(b);
    if (!dec_r) return {};
    const Decoder& dec = **dec_r;

    struct WorkItem {
        addr_t addr;
        u64 size;
    };
    std::vector<WorkItem> work;
    std::unordered_set<addr_t> seen;
    for (const auto& s : b.symbols()) {
        if (s.is_import) continue;
        if (s.kind != SymbolKind::Function) continue;
        if (s.size == 0) continue;
        if (!seen.insert(s.addr).second) continue;
        work.push_back({s.addr, s.size});
    }
    for (const auto& fn : enumerate_functions(b, EnumerateMode::Cheap)) {
        if (b.import_at_plt(fn.addr)) continue;
        if (fn.size == 0) continue;
        if (!seen.insert(fn.addr).second) continue;
        work.push_back({fn.addr, fn.size});
    }

    std::unordered_set<addr_t> known_entries;
    known_entries.reserve(work.size());
    for (const auto& w : work) known_entries.insert(w.addr);

    std::vector<CallSite> out;
    for (const auto& w : work) {
        auto span = b.bytes_at(w.addr);
        if (span.empty()) continue;
        const std::size_t limit = std::min<std::size_t>(
            span.size(), static_cast<std::size_t>(w.size));
        addr_t ip = w.addr;
        std::size_t off = 0;
        while (off < limit) {
            if (b.is_data_in_code(ip)) {
                ++ip;
                ++off;
                continue;
            }
            auto remaining = span.subspan(off, limit - off);
            auto decoded = dec.decode(remaining, ip);
            if (!decoded) {
                ++ip;
                ++off;
                continue;
            }
            const Instruction& insn = *decoded;
            if (is_call(insn.mnemonic)) {
                if (auto target = branch_target(insn); target && *target == want)
                    out.push_back({w.addr, ip});
            } else if (is_unconditional_jmp(insn.mnemonic)) {
                if (auto target = branch_target(insn); target && *target == want &&
                    (known_entries.contains(*target) || b.import_at_plt(*target) != nullptr))
                    out.push_back({w.addr, ip});
            }
            ip  += insn.length;
            off += insn.length;
        }
    }
    // Overlapping symbol and discovered extents can scan one site twice.
    std::ranges::sort(out, {}, [](const CallSite& s) { return std::pair{s.site, s.function}; });
    out.erase(std::unique(out.begin(), out.end(), [](const CallSite& a, const CallSite& b2) {
                  return a.site == b2.site;
              }), out.end());
    return out;
}

std::string_view section_name_containing(const Binary& b,
                                                       addr_t va) noexcept {
    for (const auto& s : b.sections()) {
        if (va < s.vaddr) continue;
        const auto off = va - s.vaddr;
        if (off < s.size) return s.name;
    }
    return {};
}

bool addr_in_executable_section_cli(const Binary& b,
                                                  addr_t va) noexcept {
    for (const auto& s : b.sections()) {
        if (!s.flags.executable) continue;
        if (va < s.vaddr) continue;
        if (va - s.vaddr < s.size) return true;
    }
    return false;
}

std::string first_disasm_line_at(const Binary& b, addr_t va) {
    auto r = format_disasm_range(b, va, va + 16);
    if (!r) return {};
    std::string_view s(*r);
    if (const auto nl = s.find('\n'); nl != std::string_view::npos) {
        s = s.substr(0, nl);
    }
    return std::string(s);
}

std::optional<addr_t>
cli_rip_relative_target(const Instruction& insn) noexcept {
    const addr_t end = insn.address + insn.length;
    for (std::size_t i = 0; i < insn.num_operands; ++i) {
        const Operand& op = insn.operands[i];
        if (op.kind != Operand::Kind::Memory) continue;
        const Mem& m = op.mem;
        if (m.base == Reg::Rip && m.index == Reg::None) {
            return end + static_cast<u64>(m.disp);
        }
    }
    return std::nullopt;
}

bool is_short_relative_branch(const Instruction& insn) noexcept {
    if (!branch_target(insn)) return false;
    return insn.num_operands > 0 && insn.operands[0].rel.size == 1;
}

bool is_rel32_call_or_jump(const Instruction& insn) noexcept {
    if (!branch_target(insn)) return false;
    if (!is_call(insn.mnemonic) && !is_unconditional_jmp(insn.mnemonic) &&
        !is_conditional_branch(insn.mnemonic)) return false;
    return insn.num_operands > 0 && insn.operands[0].rel.size == 4;
}

Result<DisasmProbe>
decode_disasm_probe(const Binary& b, addr_t start, std::size_t count) {
    auto dec_r = make_decoder(b);
    if (!dec_r) return std::unexpected(dec_r.error());
    const Decoder& dec = **dec_r;
    auto bytes = b.bytes_at(start);
    if (bytes.empty()) {
        return std::unexpected(Error::invalid_format(
            std::format("no bytes mapped at {:#x}", start)));
    }
    DisasmProbe p;
    addr_t ip = start;
    std::size_t off = 0;
    bool steal_complete = false;
    std::size_t scanned = 0;
    constexpr std::size_t kMaxBasicBlockBytes = 1u << 20;
    while (off < bytes.size() && off < kMaxBasicBlockBytes) {
        auto decoded = dec.decode(bytes.subspan(off), ip);
        if (!decoded) break;
        const Instruction insn = *decoded;
        if (p.insns.size() < count) p.insns.push_back(insn);
        if (!steal_complete) {
            p.needs_relocation = p.needs_relocation ||
                cli_rip_relative_target(insn).has_value() ||
                branch_target(insn).has_value();
            p.steal_len += insn.length;
            steal_complete = p.steal_len >= 14;
        }
        ip += insn.length;
        off += insn.length;
        ++scanned;
        if (p.first_bb_end == 0 && ends_basic_block(insn.mnemonic)) {
            p.first_bb_end = ip;
            break;
        }
        if (scanned >= 65536) break;
    }
    if (p.first_bb_end == 0) p.first_bb_end = ip;
    p.safe_abs_trampoline = p.steal_len >= 14 && !p.needs_relocation;
    return p;
}

Result<std::string> disasm_probe_json(const Binary& b, addr_t start,
                                                    std::size_t count) {
    auto rv = decode_disasm_probe(b, start, count);
    if (!rv) return std::unexpected(std::move(rv).error());
    const auto& p = *rv;
    std::string out = std::format(
        "{{\"va\":\"{:#x}\",\"recommended_steal_len\":{},"
        "\"needs_relocation\":{},\"first_basic_block_end\":\"{:#x}\","
        "\"safe_absolute_jump_trampoline\":{},\"instructions\":[",
        start, p.steal_len, p.needs_relocation ? "true" : "false",
        p.first_bb_end, p.safe_abs_trampoline ? "true" : "false");
    for (std::size_t i = 0; i < p.insns.size(); ++i) {
        if (i) out += ',';
        const auto& insn = p.insns[i];
        std::string bytes;
        for (u8 j = 0; j < insn.length; ++j) {
            if (j) bytes.push_back(' ');
            std::format_to(std::back_inserter(bytes), "{:02x}",
                           std::to_integer<unsigned>(insn.raw_bytes[j]));
        }
        out += std::format(
            "{{\"va\":\"{:#x}\",\"bytes\":\"{}\",\"mnemonic\":\"{}\","
            "\"operands\":[",
            insn.address, bytes, mnemonic_name(insn.mnemonic));
        for (std::size_t oi = 0; oi < insn.num_operands; ++oi) {
            if (oi) out += ',';
            out += std::format("\"{}\"",
                               json_escape(format_operand(insn, insn.operands[oi])));
        }
        out += std::format(
            "],\"text\":\"{}\"",
            json_escape(format_instruction(insn)));
        if (auto target = branch_target(insn); target) {
            out += std::format(",\"branch_target\":\"{:#x}\"", *target);
        }
        if (auto rip = cli_rip_relative_target(insn); rip) {
            out += std::format(",\"rip_relative_target\":\"{:#x}\"", *rip);
        }
        out += ",\"hazards\":{\"rip_relative\":";
        out += cli_rip_relative_target(insn) ? "true" : "false";
        out += ",\"short_branch\":";
        out += is_short_relative_branch(insn) ? "true" : "false";
        out += ",\"rel32_branch_or_call\":";
        out += is_rel32_call_or_jump(insn) ? "true" : "false";
        out += "}}";
    }
    out += "]}\n";
    return out;
}

std::string disasm_probe_summary(const Binary& b, addr_t start,
                                               std::size_t count) {
    (void)count;
    auto rv = decode_disasm_probe(b, start, 0);
    if (!rv) return {};
    const auto& p = *rv;
    return std::format(
        "; trampoline: steal_len={} needs_relocation={} first_bb_end={:#x} "
        "safe_absolute_jump={}\n",
        p.steal_len,
        p.needs_relocation ? "yes" : "no",
        p.first_bb_end,
        p.safe_abs_trampoline ? "yes" : "no");
}

bool address_is_mapped(const Binary& b, addr_t va) noexcept {
    for (const auto& s : b.sections()) {
        if (!s.flags.allocated || s.size == 0) continue;
        if (va >= s.vaddr && va - s.vaddr < s.size) return true;
    }
    return false;
}

std::optional<addr_t>
read_pointer_value(const Binary& b, addr_t va) noexcept {
    if (auto fact = b.runtime_qword_at(va); fact) return static_cast<addr_t>(*fact);
    const auto width = arch_pointer_bits(b.arch()) == 32 ? 4u : 8u;
    auto bytes = b.bytes_at(va);
    if (bytes.size() < width) return std::nullopt;
    if (width == 4) {
        return b.endian() == Endian::Big
            ? static_cast<addr_t>(read_be_at<u32>(bytes.data()))
            : static_cast<addr_t>(read_le_at<u32>(bytes.data()));
    }
    return b.endian() == Endian::Big
        ? static_cast<addr_t>(read_be_at<u64>(bytes.data()))
        : static_cast<addr_t>(read_le_at<u64>(bytes.data()));
}

std::optional<std::pair<addr_t, addr_t>>
parse_obj_off_spec(std::string_view spec) {
    std::size_t sep = spec.find(':');
    if (sep == std::string_view::npos) sep = spec.find('+');
    if (sep == std::string_view::npos) return std::nullopt;
    auto obj = parse_cli_addr(spec.substr(0, sep));
    auto off = parse_cli_addr(spec.substr(sep + 1));
    if (!obj || !off) return std::nullopt;
    return std::pair<addr_t, addr_t>{static_cast<addr_t>(*obj), static_cast<addr_t>(*off)};
}

std::string compact_pseudo_summary(const Binary& b, addr_t target,
                                                  const Annotations* ann) {
    auto win = resolve_function_at(b, target);
    if (!win) return {};
    EmitOptions opts;
    auto pseudo = format_struct(b, *win, true, ann, opts);
    if (!pseudo) return {};

    std::string out;
    std::string_view text(*pseudo);
    std::size_t pos = 0;
    std::size_t emitted = 0;
    constexpr std::size_t kMaxLines = 12;
    while (pos <= text.size() && emitted < kMaxLines) {
        std::size_t end = text.find('\n', pos);
        if (end == std::string_view::npos) end = text.size();
        std::string_view line = text.substr(pos, end - pos);
        while (!line.empty() && std::isspace(static_cast<unsigned char>(line.front()))) {
            line.remove_prefix(1);
        }
        if (!line.empty()) {
            out += "  ";
            out += line;
            out += '\n';
            ++emitted;
        }
        if (end == text.size()) break;
        pos = end + 1;
    }
    return out;
}

std::optional<std::string> read_c_string(const Binary& b, addr_t va) {
    auto bytes = b.bytes_at(va);
    if (bytes.empty()) return std::nullopt;
    std::string out;
    std::size_t printable = 0;
    constexpr std::size_t kMax = 160;
    for (std::size_t i = 0; i < bytes.size() && i < kMax; ++i) {
        const auto c = static_cast<unsigned char>(bytes[i]);
        if (c == 0) break;
        if (c == '\n') { out += "\\n"; ++printable; continue; }
        if (c == '\r') { out += "\\r"; ++printable; continue; }
        if (c == '\t') { out += "\\t"; ++printable; continue; }
        if (c == '\\') { out += "\\\\"; ++printable; continue; }
        if (c == '"') { out += "\\\""; ++printable; continue; }
        if (c >= 0x20 && c < 0x7f) {
            out.push_back(static_cast<char>(c));
            ++printable;
            continue;
        }
        return std::nullopt;
    }
    if (printable < 3) return std::nullopt;
    return out;
}

std::vector<ObjectFieldRow>
classify_object_fields(const Binary& b, addr_t obj, addr_t size) {
    const unsigned bits = arch_pointer_bits(b.arch());
    const addr_t width = bits == 32 ? 4 : 8;
    std::vector<ObjectFieldRow> rows;
    if (width == 0) return rows;

    std::set<addr_t> vtable_addrs;
    for (const auto& vt : discover_runtime_vtables(b)) vtable_addrs.insert(vt.vaddr);

    for (addr_t off = 0; off + width <= size; off += width) {
        const addr_t field_addr = obj + off;
        auto val = read_pointer_value(b, field_addr);
        if (!val) break;
        ObjectFieldRow row;
        row.offset = off;
        row.addr = field_addr;
        row.value = *val;
        if (row.value == 0) {
            row.kind = "null";
        } else if (vtable_addrs.contains(static_cast<addr_t>(row.value))) {
            row.kind = "vtable";
            row.detail = std::format("{}", section_name_containing(b, static_cast<addr_t>(row.value)));
        } else if (addr_in_executable_section_cli(b, static_cast<addr_t>(row.value))) {
            row.kind = "code";
            if (auto cf = containing_function(b, static_cast<addr_t>(row.value)); cf) {
                row.detail = std::format("{}+{:#x}", cf->name, cf->offset_within);
            }
        } else if (auto s = read_c_string(b, static_cast<addr_t>(row.value)); s) {
            row.kind = "string";
            row.detail = *s;
        } else if (address_is_mapped(b, static_cast<addr_t>(row.value))) {
            row.kind = "ptr";
            row.detail = std::format("{}", section_name_containing(b, static_cast<addr_t>(row.value)));
        } else {
            row.kind = "raw";
        }
        rows.push_back(std::move(row));
    }
    return rows;
}

Annotations load_annotations_for(const Args& args, bool& loaded) {
    const std::filesystem::path cache_dir =
        !args.cache_dir.empty() ? std::filesystem::path{args.cache_dir}
                                : cache::default_dir();
    auto loc = resolve_annotation_location(args.binary, args.annotations_path, cache_dir);
    // --no-cache bypasses the annotation *cache* path but still honors
    // sidecar / explicit --annotations.
    if (args.no_cache && loc.source == AnnotationSource::Cache) loc = {};

    Annotations annotations;
    loaded = false;
    if (loc.source == AnnotationSource::None) return annotations;
    std::error_code ec;
    if (!std::filesystem::exists(loc.path, ec) || ec) return annotations;
    auto rv = Annotations::load(loc.path);
    if (!rv) {
        spelunk::diagnostic::print("spelunk: warning: {}: {}; continuing without user annotations",
            rv.error().kind_name(), rv.error().message);
        return annotations;
    }
    annotations = std::move(*rv);
    loaded = true;
    if (!args.quiet) {
        const std::size_t n = annotations.renames.size()
                            + annotations.signatures.size()
                            + annotations.notes.size()
                            + annotations.named_constants.size();
        spelunk::diagnostic::print("spelunk: annotations: {} ({}, {} entries)",
                     loc.path.string(), annotation_source_name(loc.source), n);
    }
    return annotations;
}

}  // namespace spelunk::cli
