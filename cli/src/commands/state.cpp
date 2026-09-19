#include <spelunk/common/diagnostic.hpp>
// State-machine queries: state map, guards, lifetimes, side effects.

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <format>
#include <map>
#include <optional>
#include <print>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <spelunk/analysis/data_xrefs.hpp>
#include <spelunk/analysis/identify.hpp>
#include <spelunk/analysis/pipeline.hpp>
#include <spelunk/analysis/sigs.hpp>
#include <spelunk/binary/arch.hpp>
#include <spelunk/binary/binary.hpp>
#include <spelunk/binary/format.hpp>
#include <spelunk/common/annotations.hpp>
#include <spelunk/common/timing.hpp>
#include <spelunk/common/types.hpp>
#include <spelunk/disasm/decoder.hpp>
#include <spelunk/disasm/instruction.hpp>
#include <spelunk/disasm/register.hpp>
#include <spelunk/ir/abi.hpp>

#include "../args.hpp"
#include "../cli_error.hpp"
#include "../subcommands.hpp"
#include "../util.hpp"
#include "common.hpp"

namespace spelunk::cli {

namespace {

[[nodiscard]] std::string state_site_disasm(const Binary& b, addr_t site) {
    auto r = format_disasm_range(b, site, site + 15);
    if (!r) return {};
    std::string_view s(*r);
    if (const auto nl = s.find('\n'); nl != std::string_view::npos) {
        s = s.substr(0, nl);
    }
    return std::string(s);
}

[[nodiscard]] std::string state_site_shape(DataXrefKind kind,
                                           std::string_view disasm) {
    if (kind == DataXrefKind::Write) {
        if (disasm.find(", 0x1") != std::string_view::npos ||
            disasm.find(", 1") != std::string_view::npos) return "set";
        if (disasm.find(", 0x0") != std::string_view::npos) return "clear";
        if (disasm.find("lock ") != std::string_view::npos) return "atomic-write";
        if (disasm.find(" inc ") != std::string_view::npos ||
            disasm.find(" dec ") != std::string_view::npos ||
            disasm.find(" add ") != std::string_view::npos ||
            disasm.find(" sub ") != std::string_view::npos ||
            disasm.find(" xor ") != std::string_view::npos ||
            disasm.find(" or ") != std::string_view::npos ||
            disasm.find(" and ") != std::string_view::npos) return "read-modify-write";
        return "store";
    }
    if (kind == DataXrefKind::Read) {
        if (disasm.find(" cmp ") != std::string_view::npos ||
            disasm.find(" test ") != std::string_view::npos) return "branch-input";
        return "load";
    }
    if (kind == DataXrefKind::Lea) return "address-taken";
    if (kind == DataXrefKind::CodePtr) return "code-pointer";
    return "unknown";
}

struct StateFnIndex {
    std::vector<DiscoveredFunction> fns;

    explicit StateFnIndex(const Binary& b)
        : fns(enumerate_functions(b, EnumerateMode::Cheap)) {}

    [[nodiscard]] std::optional<ContainingFn>
    find(const Binary& b, addr_t addr) const {
        if (fns.empty()) return std::nullopt;
        auto it = std::upper_bound(fns.begin(), fns.end(), addr,
            [](addr_t a, const DiscoveredFunction& d) { return a < d.addr; });
        if (it == fns.begin()) return std::nullopt;
        --it;
        if (it->size != 0 && addr >= it->addr + it->size) return std::nullopt;
        if (it->size == 0) {
            addr_t implied_end = 0;
            auto nxt = it; ++nxt;
            if (nxt != fns.end()) implied_end = nxt->addr;
            if (implied_end != 0 && addr >= implied_end) return std::nullopt;
            if (implied_end == 0) {
                for (const auto& s : b.sections()) {
                    if (it->addr >= s.vaddr && it->addr < s.vaddr + s.size) {
                        if (addr >= s.vaddr + s.size) return std::nullopt;
                        break;
                    }
                }
            }
        }
        if (b.bytes_at(it->addr).empty()) return std::nullopt;
        return ContainingFn{it->addr, it->size, it->name, addr - it->addr};
    }
};

struct BranchOnSite {
    DataXref xref;
    std::string fn;
    u64 fn_off = 0;
    std::string read_text;
    addr_t branch_site = 0;
    std::string branch_text;
    std::optional<addr_t> taken;
    addr_t fallthrough = 0;
    std::size_t distance = 0;
};

[[nodiscard]] std::optional<addr_t>
cli_memory_operand_target(const Instruction& insn, const Operand& op) noexcept {
    if (op.kind != Operand::Kind::Memory) return std::nullopt;
    const Mem& m = op.mem;
    if (m.base == Reg::Rip && m.index == Reg::None) {
        return insn.address + insn.length + static_cast<u64>(m.disp);
    }
    if (m.base == Reg::None && m.index == Reg::None && m.has_disp) {
        return static_cast<addr_t>(m.disp);
    }
    return std::nullopt;
}

[[nodiscard]] bool instruction_directly_tests_target(const Instruction& insn,
                                                     addr_t target) noexcept {
    if (insn.mnemonic != Mnemonic::Cmp && insn.mnemonic != Mnemonic::Test) {
        return false;
    }
    for (std::size_t i = 0; i < insn.num_operands; ++i) {
        if (auto mt = cli_memory_operand_target(insn, insn.operands[i]);
            mt && *mt == target) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] std::optional<BranchOnSite>
analyze_branch_on_site(const Binary& b, const Decoder& dec,
                       const StateFnIndex& fn_index, const DataXref& xr) {
    if (xr.kind != DataXrefKind::Read) return std::nullopt;
    auto bytes = b.bytes_at(xr.from_pc);
    if (bytes.empty()) return std::nullopt;

    BranchOnSite row;
    row.xref = xr;
    if (auto cf = fn_index.find(b, xr.from_pc); cf) {
        row.fn = cf->name;
        row.fn_off = cf->offset_within;
    }

    addr_t ip = xr.from_pc;
    std::size_t off = 0;
    constexpr std::size_t kMaxBranchWindow = 8;
    for (std::size_t i = 0; i < kMaxBranchWindow && off < bytes.size(); ++i) {
        auto decoded = dec.decode(bytes.subspan(off), ip);
        if (!decoded) break;
        const Instruction insn = *decoded;
        if (i == 0) {
            if (!instruction_directly_tests_target(insn, xr.to_addr)) {
                return std::nullopt;
            }
            row.read_text = format_instruction(insn);
        }
        if (is_conditional_branch(insn.mnemonic)) {
            row.branch_site = insn.address;
            row.branch_text = format_instruction(insn);
            row.taken = branch_target(insn);
            row.fallthrough = insn.address + insn.length;
            row.distance = i;
            return row;
        }
        if (i > 0 && ends_basic_block(insn.mnemonic)) break;
        ip += insn.length;
        off += insn.length;
    }
    return std::nullopt;
}

struct GuardMapRow {
    addr_t condition_site = 0;
    std::string condition_text;
    std::optional<addr_t> memory_target;
    std::string memory_section;
    addr_t branch_site = 0;
    std::string branch_text;
    std::optional<addr_t> taken;
    addr_t fallthrough = 0;
    std::size_t distance = 0;
};

[[nodiscard]] std::optional<addr_t>
first_memory_target(const Binary& b, const Instruction& insn) noexcept {
    for (std::size_t i = 0; i < insn.num_operands; ++i) {
        auto target = cli_memory_operand_target(insn, insn.operands[i]);
        if (!target) continue;
        if (address_is_mapped(b, *target)) return target;
    }
    return std::nullopt;
}

[[nodiscard]] std::vector<GuardMapRow>
compute_guard_map(const Binary& b, addr_t start, u64 size) {
    std::vector<GuardMapRow> rows;
    auto dec_r = make_decoder(b);
    if (!dec_r) return rows;
    const Decoder& dec = **dec_r;

    auto bytes = b.bytes_at(start);
    if (bytes.empty()) return rows;
    if (size != 0) {
        bytes = bytes.first(std::min<std::size_t>(bytes.size(), static_cast<std::size_t>(size)));
    } else {
        bytes = bytes.first(std::min<std::size_t>(bytes.size(), 4096));
    }

    std::vector<Instruction> recent_conditions;
    recent_conditions.reserve(6);
    addr_t ip = start;
    std::size_t off = 0;
    while (off < bytes.size()) {
        auto decoded = dec.decode(bytes.subspan(off), ip);
        if (!decoded) {
            ++off;
            ++ip;
            recent_conditions.clear();
            continue;
        }
        const Instruction insn = *decoded;
        if (insn.mnemonic == Mnemonic::Cmp || insn.mnemonic == Mnemonic::Test) {
            recent_conditions.push_back(insn);
            if (recent_conditions.size() > 6) {
                recent_conditions.erase(recent_conditions.begin());
            }
        }
        if (is_conditional_branch(insn.mnemonic)) {
            GuardMapRow row;
            row.branch_site = insn.address;
            row.branch_text = format_instruction(insn);
            row.taken = branch_target(insn);
            row.fallthrough = insn.address + insn.length;
            if (!recent_conditions.empty()) {
                const auto& cond = recent_conditions.back();
                row.condition_site = cond.address;
                row.condition_text = format_instruction(cond);
                row.distance = insn.address >= cond.address
                    ? static_cast<std::size_t>(insn.address - cond.address)
                    : 0;
                row.memory_target = first_memory_target(b, cond);
                if (row.memory_target) {
                    row.memory_section = std::string(section_name_containing(b, *row.memory_target));
                }
            }
            rows.push_back(std::move(row));
            recent_conditions.clear();
        }
        if (ends_basic_block(insn.mnemonic) && !is_conditional_branch(insn.mnemonic)) {
            recent_conditions.clear();
        }
        off += insn.length;
        ip += insn.length;
    }
    return rows;
}

struct StateLifetimeSite {
    DataXref xref;
    std::string fn;
    u64 fn_off = 0;
    std::string disasm;
    std::string shape;
};

struct SideEffectWrite {
    addr_t site = 0;
    addr_t target = 0;
    std::string section;
    std::string shape;
    std::string text;
};

struct SideEffectScan {
    std::vector<SideEffectWrite> writes;
    bool returns = false;
};

[[nodiscard]] bool instruction_writes_memory(const Instruction& insn,
                                             std::size_t op_idx) noexcept {
    if (op_idx != 0) return false;
    if (insn.mnemonic == Mnemonic::Cmp || insn.mnemonic == Mnemonic::Test ||
        insn.mnemonic == Mnemonic::Lea || insn.mnemonic == Mnemonic::Call ||
        insn.mnemonic == Mnemonic::Jmp) {
        return false;
    }
    return insn.operands[op_idx].kind == Operand::Kind::Memory;
}

[[nodiscard]] SideEffectScan
scan_side_effects(const Binary& b, addr_t start, u64 size) {
    SideEffectScan scan;
    auto dec_r = make_decoder(b);
    if (!dec_r) return scan;
    const Decoder& dec = **dec_r;

    auto bytes = b.bytes_at(start);
    if (bytes.empty()) return scan;
    if (size != 0) {
        bytes = bytes.first(std::min<std::size_t>(bytes.size(), static_cast<std::size_t>(size)));
    } else {
        bytes = bytes.first(std::min<std::size_t>(bytes.size(), 4096));
    }

    addr_t ip = start;
    std::size_t off = 0;
    while (off < bytes.size()) {
        auto decoded = dec.decode(bytes.subspan(off), ip);
        if (!decoded) {
            ++off;
            ++ip;
            continue;
        }
        const Instruction insn = *decoded;
        if (insn.mnemonic == Mnemonic::Ret || insn.mnemonic == Mnemonic::A64Ret) {
            scan.returns = true;
        }
        for (std::size_t i = 0; i < insn.num_operands; ++i) {
            if (!instruction_writes_memory(insn, i)) continue;
            auto target = cli_memory_operand_target(insn, insn.operands[i]);
            if (!target || !address_is_mapped(b, *target)) continue;
            SideEffectWrite w;
            w.site = insn.address;
            w.target = *target;
            w.section = std::string(section_name_containing(b, *target));
            w.text = format_instruction(insn);
            w.shape = state_site_shape(DataXrefKind::Write, w.text);
            scan.writes.push_back(std::move(w));
        }
        off += insn.length;
        ip += insn.length;
    }
    std::ranges::sort(scan.writes, {}, [](const SideEffectWrite& w) {
        return std::pair{w.site, w.target};
    });
    scan.writes.erase(std::unique(scan.writes.begin(), scan.writes.end(),
        [](const SideEffectWrite& lhs, const SideEffectWrite& rhs) {
            return lhs.site == rhs.site && lhs.target == rhs.target;
        }), scan.writes.end());
    return scan;
}

struct ObjectFieldUse {
    i64 offset = 0;
    addr_t site = 0;
    std::string role;
    std::string text;
};

struct ObjectFieldSummary {
    i64 offset = 0;
    bool read = false;
    bool write = false;
    bool branch_gate = false;
    bool call_target = false;
    bool address_taken = false;
    std::vector<ObjectFieldUse> uses;
};

[[nodiscard]] std::string signed_hex(i64 v) {
    if (v < 0) return std::format("-{:#x}", static_cast<u64>(-v));
    return std::format("+{:#x}", static_cast<u64>(v));
}

[[nodiscard]] Reg inferred_this_reg(const Binary& b) noexcept {
    const Abi abi = abi_for(b.format(), b.arch(), b.endian());
    auto regs = int_arg_regs(abi);
    if (!regs.empty()) return regs.front();
    if (b.arch() == Arch::X86_64) return b.format() == Format::Pe ? Reg::Rcx : Reg::Rdi;
    if (b.arch() == Arch::Arm64) return Reg::X0;
    return Reg::None;
}

[[nodiscard]] bool mem_uses_base(const Operand& op, Reg base) noexcept {
    return op.kind == Operand::Kind::Memory &&
           op.mem.base == base &&
           op.mem.index == Reg::None;
}

[[nodiscard]] std::string object_role_for_operand(const Instruction& insn,
                                                  std::size_t op_idx) {
    if (insn.mnemonic == Mnemonic::Call || insn.mnemonic == Mnemonic::Jmp) {
        return "call-target";
    }
    if (insn.mnemonic == Mnemonic::Cmp || insn.mnemonic == Mnemonic::Test) {
        return "branch-gate";
    }
    if (insn.mnemonic == Mnemonic::Lea) return "address-taken";
    if (instruction_writes_memory(insn, op_idx)) return "write";
    return "read";
}

[[nodiscard]] std::map<i64, ObjectFieldSummary>
scan_object_roles(const Binary& b, addr_t start, u64 size, Reg this_reg) {
    std::map<i64, ObjectFieldSummary> fields;
    if (this_reg == Reg::None) return fields;
    auto dec_r = make_decoder(b);
    if (!dec_r) return fields;
    const Decoder& dec = **dec_r;

    auto bytes = b.bytes_at(start);
    if (bytes.empty()) return fields;
    if (size != 0) {
        bytes = bytes.first(std::min<std::size_t>(bytes.size(), static_cast<std::size_t>(size)));
    } else {
        bytes = bytes.first(std::min<std::size_t>(bytes.size(), 4096));
    }

    addr_t ip = start;
    std::size_t off = 0;
    while (off < bytes.size()) {
        auto decoded = dec.decode(bytes.subspan(off), ip);
        if (!decoded) {
            ++off;
            ++ip;
            continue;
        }
        const Instruction insn = *decoded;
        for (std::size_t i = 0; i < insn.num_operands; ++i) {
            const Operand& op = insn.operands[i];
            if (!mem_uses_base(op, this_reg)) continue;
            const i64 field_off = op.mem.disp;
            std::string role = object_role_for_operand(insn, i);
            auto& f = fields[field_off];
            f.offset = field_off;
            if (role == "read") f.read = true;
            else if (role == "write") f.write = true;
            else if (role == "branch-gate") f.branch_gate = true;
            else if (role == "call-target") f.call_target = true;
            else if (role == "address-taken") f.address_taken = true;
            f.uses.push_back(ObjectFieldUse{
                .offset = field_off,
                .site = insn.address,
                .role = std::move(role),
                .text = format_instruction(insn),
            });
        }
        off += insn.length;
        ip += insn.length;
    }
    return fields;
}

[[nodiscard]] std::string object_roles_csv(const ObjectFieldSummary& f) {
    std::string out;
    auto add = [&](std::string_view s) {
        if (!out.empty()) out.push_back(',');
        out += s;
    };
    if (f.read) add("read");
    if (f.write) add("write");
    if (f.branch_gate) add("branch-gate");
    if (f.call_target) add("call-target");
    if (f.address_taken) add("address-taken");
    if (out.empty()) out = "unknown";
    return out;
}

}  // namespace

int run_state_map(const Args& args, const Binary& b) {
    ScopedTimer total_timer("state_map.total");
    auto va = parse_cli_addr(args.state_map);
    if (!va) {
        spelunk::diagnostic::print("spelunk: --state-map: bad address '{}'", args.state_map);
        return EXIT_FAILURE;
    }

    struct Site {
        DataXref xref;
        std::string fn;
        u64 fn_off = 0;
        std::string disasm;
        std::string shape;
    };

    std::vector<Site> sites;
    const auto xrefs = compute_data_xrefs_to(b, *va);
    {
        ScopedTimer t("state_map.decorate_sites");
        StateFnIndex fn_index(b);
        for (const auto& xr : xrefs) {
            Site s;
            s.xref = xr;
            if (auto cf = fn_index.find(b, xr.from_pc); cf) {
                s.fn = cf->name;
                s.fn_off = cf->offset_within;
            }
            s.disasm = state_site_disasm(b, xr.from_pc);
            s.shape = state_site_shape(xr.kind, s.disasm);
            sites.push_back(std::move(s));
        }
    }

    auto count_kind = [&](DataXrefKind k) {
        return std::ranges::count_if(sites, [&](const Site& s) {
            return s.xref.kind == k;
        });
    };
    const auto reads = count_kind(DataXrefKind::Read);
    const auto writes = count_kind(DataXrefKind::Write);
    const auto leas = count_kind(DataXrefKind::Lea);
    const auto codeptrs = count_kind(DataXrefKind::CodePtr);

    if (args.json) {
        std::string out = std::format(
            "{{\"state\":\"{:#x}\",\"summary\":{{\"reads\":{},\"writes\":{},"
            "\"lea\":{},\"code_ptr\":{}}},\"sites\":[",
            *va, reads, writes, leas, codeptrs);
        for (std::size_t i = 0; i < sites.size(); ++i) {
            if (i) out += ',';
            const auto& s = sites[i];
            out += std::format(
                "{{\"site\":\"{:#x}\",\"target\":\"{:#x}\",\"kind\":\"{}\","
                "\"shape\":\"{}\"",
                s.xref.from_pc, s.xref.to_addr, data_xref_kind_name(s.xref.kind),
                json_escape(s.shape));
            if (!s.fn.empty()) {
                out += std::format(",\"fn\":\"{}\",\"fn_offset\":\"{:#x}\"",
                                   json_escape(s.fn), s.fn_off);
            }
            if (!s.disasm.empty()) {
                out += std::format(",\"disasm\":\"{}\"", json_escape(s.disasm));
            }
            out += "}";
        }
        out += "]}\n";
        std::fwrite(out.data(), 1, out.size(), stdout);
        return EXIT_SUCCESS;
    }

    std::println("state\t{:#x}\treads={}\twrites={}\tlea={}\tcode-ptr={}",
                 *va, reads, writes, leas, codeptrs);
    for (const auto& s : sites) {
        std::string fn = s.fn.empty() ? "-" : std::format("{}+{:#x}", s.fn, s.fn_off);
        std::println("{}\t{:#x}\t{}\t{}\t{}",
                     data_xref_kind_name(s.xref.kind), s.xref.from_pc,
                     s.shape, fn, s.disasm);
    }
    return EXIT_SUCCESS;
}

int run_branch_on(const Args& args, const Binary& b) {
    ScopedTimer total_timer("branch_on.total");
    auto va = parse_cli_addr(args.branch_on);
    if (!va) {
        spelunk::diagnostic::print("spelunk: --branch-on: bad address '{}'", args.branch_on);
        return EXIT_FAILURE;
    }

    auto dec_r = make_decoder(b);
    if (!dec_r) return report(dec_r.error());
    const Decoder& dec = **dec_r;

    std::vector<BranchOnSite> rows;
    const auto xrefs = compute_data_xrefs_to(b, *va);
    StateFnIndex fn_index(b);
    for (const auto& xr : xrefs) {
        if (auto row = analyze_branch_on_site(b, dec, fn_index, xr); row) {
            rows.push_back(std::move(*row));
        }
    }

    if (args.json) {
        std::string out = std::format("{{\"state\":\"{:#x}\",\"branches\":[", *va);
        for (std::size_t i = 0; i < rows.size(); ++i) {
            if (i) out += ',';
            const auto& r = rows[i];
            out += std::format(
                "{{\"site\":\"{:#x}\",\"target\":\"{:#x}\",\"read\":\"{}\","
                "\"branch_site\":\"{:#x}\",\"branch\":\"{}\","
                "\"fallthrough\":\"{:#x}\",\"distance\":{}",
                r.xref.from_pc, r.xref.to_addr, json_escape(r.read_text),
                r.branch_site, json_escape(r.branch_text), r.fallthrough,
                r.distance);
            if (r.taken) out += std::format(",\"taken\":\"{:#x}\"", *r.taken);
            else         out += ",\"taken\":null";
            if (!r.fn.empty()) {
                out += std::format(",\"fn\":\"{}\",\"fn_offset\":\"{:#x}\"",
                                   json_escape(r.fn), r.fn_off);
            }
            out += "}";
        }
        out += "]}\n";
        std::fwrite(out.data(), 1, out.size(), stdout);
        return EXIT_SUCCESS;
    }

    std::println("branch-on\t{:#x}\tbranches={}", *va, rows.size());
    for (const auto& r : rows) {
        const std::string fn = r.fn.empty()
            ? "-"
            : std::format("{}+{:#x}", r.fn, r.fn_off);
        const std::string taken = r.taken ? std::format("{:#x}", *r.taken) : "-";
        std::println("{:#x}\t{}\t{}\t{:#x}\t{}\t{}\t{:#x}",
                     r.xref.from_pc, fn, r.read_text, r.branch_site,
                     r.branch_text, taken, r.fallthrough);
    }
    return EXIT_SUCCESS;
}

int run_guard_map(const Args& args, const Binary& b) {
    ScopedTimer total_timer("guard_map.total");
    const Annotations ann = load_annotations_quiet(args);
    auto win = resolve_function(b, args.guard_map, &ann);
    if (!win) {
        spelunk::diagnostic::print("spelunk: --guard-map: could not resolve '{}'", args.guard_map);
        return EXIT_FAILURE;
    }
    const auto rows = compute_guard_map(b, win->start, win->size);

    if (args.json) {
        std::string out = std::format(
            "{{\"function\":{{\"entry\":\"{:#x}\",\"size\":\"{:#x}\","
            "\"name\":\"{}\"}},\"guards\":[",
            win->start, win->size, json_escape(win->label));
        for (std::size_t i = 0; i < rows.size(); ++i) {
            if (i) out += ',';
            const auto& r = rows[i];
            out += std::format(
                "{{\"branch_site\":\"{:#x}\",\"branch\":\"{}\","
                "\"fallthrough\":\"{:#x}\",\"distance\":{}",
                r.branch_site, json_escape(r.branch_text), r.fallthrough,
                r.distance);
            if (r.taken) out += std::format(",\"taken\":\"{:#x}\"", *r.taken);
            else         out += ",\"taken\":null";
            if (r.condition_site != 0) {
                out += std::format(",\"condition_site\":\"{:#x}\",\"condition\":\"{}\"",
                                   r.condition_site, json_escape(r.condition_text));
            } else {
                out += ",\"condition_site\":null,\"condition\":null";
            }
            if (r.memory_target) {
                out += std::format(",\"memory_target\":\"{:#x}\"", *r.memory_target);
                if (!r.memory_section.empty()) {
                    out += std::format(",\"memory_section\":\"{}\"",
                                       json_escape(r.memory_section));
                }
            } else {
                out += ",\"memory_target\":null";
            }
            out += "}";
        }
        out += "]}\n";
        std::fwrite(out.data(), 1, out.size(), stdout);
        return EXIT_SUCCESS;
    }

    std::println("guard-map\t{:#x}\t{}\tguards={}", win->start, win->label, rows.size());
    for (const auto& r : rows) {
        const std::string taken = r.taken ? std::format("{:#x}", *r.taken) : "-";
        const std::string cond = r.condition_text.empty() ? "-" : r.condition_text;
        const std::string target = r.memory_target ? std::format("{:#x}", *r.memory_target) : "-";
        const std::string section = r.memory_section.empty() ? "-" : r.memory_section;
        std::println("{:#x}\t{}\t{:#x}\t{}\t{}\t{:#x}\t{}\t{}",
                     r.condition_site, cond, r.branch_site, r.branch_text,
                     taken, r.fallthrough, target, section);
    }
    return EXIT_SUCCESS;
}

int run_state_lifetime(const Args& args, const Binary& b) {
    ScopedTimer total_timer("state_lifetime.total");
    auto va = parse_cli_addr(args.state_lifetime);
    if (!va) {
        spelunk::diagnostic::print("spelunk: --state-lifetime: bad address '{}'",
                     args.state_lifetime);
        return EXIT_FAILURE;
    }

    auto dec_r = make_decoder(b);
    if (!dec_r) return report(dec_r.error());
    const Decoder& dec = **dec_r;

    std::vector<StateLifetimeSite> sites;
    std::vector<BranchOnSite> branches;
    const auto xrefs = compute_data_xrefs_to(b, *va);
    StateFnIndex fn_index(b);
    for (const auto& xr : xrefs) {
        StateLifetimeSite s;
        s.xref = xr;
        if (auto cf = fn_index.find(b, xr.from_pc); cf) {
            s.fn = cf->name;
            s.fn_off = cf->offset_within;
        }
        s.disasm = state_site_disasm(b, xr.from_pc);
        s.shape = state_site_shape(xr.kind, s.disasm);
        sites.push_back(std::move(s));
        if (auto br = analyze_branch_on_site(b, dec, fn_index, xr); br) {
            branches.push_back(std::move(*br));
        }
    }

    auto count_kind = [&](DataXrefKind k) {
        return std::ranges::count_if(sites, [&](const StateLifetimeSite& s) {
            return s.xref.kind == k;
        });
    };
    const auto reads = count_kind(DataXrefKind::Read);
    const auto writes = count_kind(DataXrefKind::Write);
    const auto leas = count_kind(DataXrefKind::Lea);
    const auto codeptrs = count_kind(DataXrefKind::CodePtr);

    if (args.json) {
        std::string out = std::format(
            "{{\"state\":\"{:#x}\",\"summary\":{{\"reads\":{},\"writes\":{},"
            "\"lea\":{},\"code_ptr\":{},\"branches\":{}}},\"sites\":[",
            *va, reads, writes, leas, codeptrs, branches.size());
        for (std::size_t i = 0; i < sites.size(); ++i) {
            if (i) out += ',';
            const auto& s = sites[i];
            out += std::format(
                "{{\"site\":\"{:#x}\",\"kind\":\"{}\",\"shape\":\"{}\"",
                s.xref.from_pc, data_xref_kind_name(s.xref.kind),
                json_escape(s.shape));
            if (!s.fn.empty()) {
                out += std::format(",\"fn\":\"{}\",\"fn_offset\":\"{:#x}\"",
                                   json_escape(s.fn), s.fn_off);
            }
            if (!s.disasm.empty()) {
                out += std::format(",\"disasm\":\"{}\"", json_escape(s.disasm));
            }
            out += "}";
        }
        out += "],\"branches\":[";
        for (std::size_t i = 0; i < branches.size(); ++i) {
            if (i) out += ',';
            const auto& r = branches[i];
            out += std::format(
                "{{\"site\":\"{:#x}\",\"read\":\"{}\",\"branch_site\":\"{:#x}\","
                "\"branch\":\"{}\",\"fallthrough\":\"{:#x}\"",
                r.xref.from_pc, json_escape(r.read_text), r.branch_site,
                json_escape(r.branch_text), r.fallthrough);
            if (r.taken) out += std::format(",\"taken\":\"{:#x}\"", *r.taken);
            else         out += ",\"taken\":null";
            if (!r.fn.empty()) {
                out += std::format(",\"fn\":\"{}\",\"fn_offset\":\"{:#x}\"",
                                   json_escape(r.fn), r.fn_off);
            }
            out += "}";
        }
        out += "]}\n";
        std::fwrite(out.data(), 1, out.size(), stdout);
        return EXIT_SUCCESS;
    }

    std::println("state-lifetime\t{:#x}\treads={}\twrites={}\tbranches={}\tlea={}\tcode-ptr={}",
                 *va, reads, writes, branches.size(), leas, codeptrs);
    std::println("writers");
    for (const auto& s : sites) {
        if (s.xref.kind != DataXrefKind::Write) continue;
        const std::string fn = s.fn.empty() ? "-" : std::format("{}+{:#x}", s.fn, s.fn_off);
        std::println("{:#x}\t{}\t{}\t{}", s.xref.from_pc, s.shape, fn, s.disasm);
    }
    std::println("branch-gates");
    for (const auto& r : branches) {
        const std::string fn = r.fn.empty() ? "-" : std::format("{}+{:#x}", r.fn, r.fn_off);
        const std::string taken = r.taken ? std::format("{:#x}", *r.taken) : "-";
        std::println("{:#x}\t{}\t{}\t{:#x}\t{}\t{}\t{:#x}",
                     r.xref.from_pc, fn, r.read_text, r.branch_site,
                     r.branch_text, taken, r.fallthrough);
    }
    std::println("readers");
    for (const auto& s : sites) {
        if (s.xref.kind != DataXrefKind::Read) continue;
        const std::string fn = s.fn.empty() ? "-" : std::format("{}+{:#x}", s.fn, s.fn_off);
        std::println("{:#x}\t{}\t{}\t{}", s.xref.from_pc, s.shape, fn, s.disasm);
    }
    if (leas || codeptrs) {
        std::println("address-taken");
        for (const auto& s : sites) {
            if (s.xref.kind != DataXrefKind::Lea && s.xref.kind != DataXrefKind::CodePtr) continue;
            const std::string fn = s.fn.empty() ? "-" : std::format("{}+{:#x}", s.fn, s.fn_off);
            std::println("{:#x}\t{}\t{}\t{}", s.xref.from_pc,
                         data_xref_kind_name(s.xref.kind), fn, s.disasm);
        }
    }
    return EXIT_SUCCESS;
}

int run_side_effects(const Args& args, const Binary& b) {
    ScopedTimer total_timer("side_effects.total");
    const Annotations ann = load_annotations_quiet(args);
    auto win = resolve_function(b, args.side_effects, &ann);
    if (!win) {
        spelunk::diagnostic::print("spelunk: --side-effects: could not resolve '{}'",
                     args.side_effects);
        return EXIT_FAILURE;
    }
    const auto scan = scan_side_effects(b, win->start, win->size);
    const auto calls = compute_classified_callees(b, win->start);

    if (args.json) {
        std::string out = std::format(
            "{{\"function\":{{\"entry\":\"{:#x}\",\"size\":\"{:#x}\","
            "\"name\":\"{}\"}},\"summary\":{{\"writes\":{},\"calls\":{},"
            "\"returns\":{}}},\"writes\":[",
            win->start, win->size, json_escape(win->label),
            scan.writes.size(), calls.size(), scan.returns ? "true" : "false");
        for (std::size_t i = 0; i < scan.writes.size(); ++i) {
            if (i) out += ',';
            const auto& w = scan.writes[i];
            out += std::format(
                "{{\"site\":\"{:#x}\",\"target\":\"{:#x}\",\"section\":\"{}\","
                "\"shape\":\"{}\",\"instruction\":\"{}\"}}",
                w.site, w.target, json_escape(w.section), json_escape(w.shape),
                json_escape(w.text));
        }
        out += "],\"calls\":[";
        for (std::size_t i = 0; i < calls.size(); ++i) {
            if (i) out += ',';
            out += std::format("{{\"target\":\"{:#x}\",\"kind\":\"{}\"}}",
                               calls[i].target, callee_kind_name(calls[i].kind));
        }
        out += "]}\n";
        std::fwrite(out.data(), 1, out.size(), stdout);
        return EXIT_SUCCESS;
    }

    std::println("side-effects\t{:#x}\t{}\twrites={}\tcalls={}\treturns={}",
                 win->start, win->label, scan.writes.size(), calls.size(),
                 scan.returns ? "yes" : "no");
    std::println("writes");
    for (const auto& w : scan.writes) {
        const std::string section = w.section.empty() ? "-" : w.section;
        std::println("{:#x}\t{:#x}\t{}\t{}\t{}",
                     w.site, w.target, section, w.shape, w.text);
    }
    std::println("calls");
    for (const auto& c : calls) {
        std::println("{:#x}\t{}", c.target, callee_kind_name(c.kind));
    }
    return EXIT_SUCCESS;
}

int run_object_roles(const Args& args, const Binary& b) {
    ScopedTimer total_timer("object_roles.total");
    const Annotations ann = load_annotations_quiet(args);
    auto win = resolve_function(b, args.object_roles, &ann);
    if (!win) {
        spelunk::diagnostic::print("spelunk: --object-roles: could not resolve '{}'",
                     args.object_roles);
        return EXIT_FAILURE;
    }
    const Reg this_reg = inferred_this_reg(b);
    const auto fields = scan_object_roles(b, win->start, win->size, this_reg);

    if (args.json) {
        std::string out = std::format(
            "{{\"function\":{{\"entry\":\"{:#x}\",\"size\":\"{:#x}\","
            "\"name\":\"{}\"}},\"this_reg\":\"{}\",\"fields\":[",
            win->start, win->size, json_escape(win->label),
            json_escape(std::string(reg_name(this_reg))));
        bool first_field = true;
        for (const auto& [_, f] : fields) {
            if (!first_field) out += ',';
            first_field = false;
            out += std::format("{{\"offset\":\"{}\",\"roles\":\"{}\",\"uses\":[",
                               signed_hex(f.offset), object_roles_csv(f));
            for (std::size_t i = 0; i < f.uses.size(); ++i) {
                if (i) out += ',';
                const auto& u = f.uses[i];
                out += std::format(
                    "{{\"site\":\"{:#x}\",\"role\":\"{}\",\"instruction\":\"{}\"}}",
                    u.site, json_escape(u.role), json_escape(u.text));
            }
            out += "]}";
        }
        out += "]}\n";
        std::fwrite(out.data(), 1, out.size(), stdout);
        return EXIT_SUCCESS;
    }

    std::println("object-roles\t{:#x}\t{}\tthis-reg={}\tfields={}",
                 win->start, win->label, reg_name(this_reg), fields.size());
    std::println("fields");
    for (const auto& [_, f] : fields) {
        std::println("{}\t{}\tuses={}", signed_hex(f.offset),
                     object_roles_csv(f), f.uses.size());
        for (const auto& u : f.uses) {
            std::println("{:#x}\t{}\t{}", u.site, u.role, u.text);
        }
    }
    return EXIT_SUCCESS;
}

}  // namespace spelunk::cli
