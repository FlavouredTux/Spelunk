#include <spelunk/analysis/x86.hpp>

#include <algorithm>
#include <charconv>
#include <cctype>
#include <map>
#include <optional>
#include <string_view>
#include <unordered_set>

#include <spelunk/analysis/cfg_builder.hpp>
#include <spelunk/analysis/import_sigs.hpp>
#include <spelunk/disasm/x64_decoder.hpp>
#include <spelunk/ir/ssa.hpp>
#include <spelunk/ir/x64_lifter.hpp>

namespace spelunk {
namespace {
using Definitions = std::map<SsaKey, const IrInst*>;

std::optional<i64> stack_offset(const IrValue& value, const Definitions& defs,
                               unsigned depth = 0) {
    if (depth > 40) return std::nullopt;
    if (value.kind == IrValueKind::Reg && value.version == 0 &&
        canonical_reg(value.reg) == Reg::Rsp) return 0;
    const auto key = ssa_key(value);
    if (!key) return std::nullopt;
    const auto found = defs.find(*key);
    if (found == defs.end()) return std::nullopt;
    const auto& inst = *found->second;
    if (inst.src_count && (inst.op == IrOp::Assign || inst.op == IrOp::ZExt ||
                           inst.op == IrOp::Trunc)) {
        return stack_offset(inst.srcs[0], defs, depth + 1);
    }
    if (inst.src_count == 2 && (inst.op == IrOp::Add || inst.op == IrOp::Sub)) {
        if (inst.srcs[1].kind == IrValueKind::Imm) {
            if (auto base = stack_offset(inst.srcs[0], defs, depth + 1)) {
                return *base + (inst.op == IrOp::Add ? inst.srcs[1].imm : -inst.srcs[1].imm);
            }
        }
        if (inst.op == IrOp::Add && inst.srcs[0].kind == IrValueKind::Imm) {
            if (auto base = stack_offset(inst.srcs[1], defs, depth + 1))
                return *base + inst.srcs[0].imm;
        }
    }
    return std::nullopt;
}
} // namespace

X86FunctionInfo analyze_x86_function(const Binary& binary, addr_t entry) {
    X86FunctionInfo info;
    bool decorated = false;
    unsigned decorated_bytes = 0;
    for (const auto& symbol : binary.symbols()) {
        if ((symbol.addr != entry && symbol.got_addr != entry) || entry == 0) continue;
        const std::string_view name = symbol.name;
        const auto at = name.rfind('@');
        if (!name.empty() && (name.front() == '_' || name.front() == '@') &&
            at != std::string_view::npos && at > 1) {
            const auto suffix = name.substr(at + 1);
            const auto parsed = std::from_chars(suffix.data(), suffix.data() + suffix.size(), decorated_bytes);
            if (parsed.ec == std::errc{} && parsed.ptr == suffix.data() + suffix.size() &&
                decorated_bytes <= 0xffffu) {
                info.abi = name.front() == '@' ? Abi::Win32Fastcall : Abi::Win32Stdcall;
                decorated = true;
            }
        }
        if (symbol.is_import) {
            std::string library = symbol.import_library;
            for (char& c : library) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            const bool crt = library.find("msvcr") != std::string::npos ||
                library.find("ucrt") != std::string::npos ||
                library.find("vcruntime") != std::string::npos ||
                library.find("msvcp") != std::string::npos;
            TypeArena arena;
            const auto prototype = lookup_import_sig(strip_import_name_decorations(name), arena);
            if (!decorated && !library.empty() && !crt && prototype && !prototype->variadic)
                info.abi = Abi::Win32Stdcall;
            if (prototype) {
                i64 offset = 4;
                for (TypeRef type : prototype->params) {
                    const auto& node = arena.node(type);
                    const IrType ir_type = arena.kind(type) == TypeKind::Float
                        ? (node.f.bits <= 32 ? IrType::F32 : IrType::F64) : IrType::I32;
                    info.arguments.push_back({Reg::None, ir_type, false, offset});
                    const unsigned bytes = arena.kind(type) == TypeKind::Float ? node.f.bits / 8u
                        : arena.kind(type) == TypeKind::Int ? node.i.bits / 8u : 4u;
                    offset += (std::max<unsigned>(4, bytes) + 3u) / 4u * 4u;
                }
                if (info.abi == Abi::Win32Stdcall) info.callee_pop = static_cast<u16>(offset - 4);
            }
            if (decorated && !info.callee_pop) info.callee_pop = static_cast<u16>(decorated_bytes);
            return info;
        }
    }

    const X64Decoder decoder(false);
    CfgBuilder builder(binary, decoder, false);
    std::unordered_set<addr_t> entries;
    for (const auto& symbol : binary.symbols()) {
        if (symbol.kind == SymbolKind::Function && symbol.addr) entries.insert(symbol.addr);
    }
    builder.seed_known_entries(std::move(entries));
    const auto function = builder.build(entry);
    std::map<i64, IrType> stack;
    bool ecx = false;
    bool edx = false;
    if (function) {
        for (const auto& block : function->blocks) for (const auto& insn : block.instructions) {
            if (insn.mnemonic == Mnemonic::Ret && insn.num_operands == 1 &&
                insn.operands[0].kind == Operand::Kind::Immediate)
                info.callee_pop = static_cast<u16>(insn.operands[0].imm.value);
        }
        // This lifter intentionally has no Binary: querying a callee must not
        // recursively analyze the call graph merely to identify its ABI.
        auto ir = X64Lifter(Abi::Win32Cdecl).lift(*function);
        if (ir && SsaBuilder{}.convert(*ir)) {
            Definitions defs;
            for (const auto& block : ir->blocks) for (const auto& inst : block.insts)
                if (auto key = ssa_key(inst.dst)) defs[*key] = &inst;
            for (const auto& block : ir->blocks) for (const auto& inst : block.insts) {
                if (inst.op == IrOp::Return || inst.op == IrOp::Phi ||
                    (inst.op == IrOp::Intrinsic && inst.name.starts_with("call."))) continue;
                for (u8 i = 0; i < inst.src_count; ++i) {
                    const auto& value = inst.srcs[i];
                    if (value.kind == IrValueKind::Reg && value.version == 0) {
                        ecx |= canonical_reg(value.reg) == Reg::Rcx;
                        edx |= canonical_reg(value.reg) == Reg::Rdx;
                    }
                }
                if (inst.op == IrOp::Load && inst.src_count) {
                    const auto offset = stack_offset(inst.srcs[0], defs);
                    if (offset && *offset >= 4 && *offset <= 4 * static_cast<i64>(kMaxAbiArgs) &&
                        *offset % 4 == 0) stack[*offset] = inst.dst.type;
                }
            }
        }
    }
    if (!decorated) info.abi = edx ? Abi::Win32Fastcall
        : ecx ? Abi::Win32Thiscall
        : info.callee_pop ? Abi::Win32Stdcall : Abi::Win32Cdecl;
    const auto regs = int_arg_regs(info.abi);
    if (decorated && !info.callee_pop) {
        const auto reg_bytes = static_cast<unsigned>(regs.size()) * 4u;
        info.callee_pop = static_cast<u16>(decorated_bytes > reg_bytes ? decorated_bytes - reg_bytes : 0);
    }
    for (Reg reg : regs) info.arguments.push_back({reg, IrType::I32});
    i64 last = stack.empty() ? 0 : stack.rbegin()->first;
    last = std::max(last, static_cast<i64>(info.callee_pop));
    for (i64 offset = 4; offset <= last && info.arguments.size() < kMaxAbiArgs;) {
        const auto found = stack.find(offset);
        const IrType type = found == stack.end() ? IrType::I32 : found->second;
        info.arguments.push_back({Reg::None, type, false, offset});
        offset += std::max<i64>(4, static_cast<i64>(type_bits(type) / 8));
    }
    return info;
}
} // namespace spelunk
