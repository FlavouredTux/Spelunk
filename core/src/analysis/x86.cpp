#include <spelunk/analysis/x86.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <spelunk/analysis/cfg_builder.hpp>
#include <spelunk/analysis/function.hpp>
#include <spelunk/analysis/import_sigs.hpp>
#include <spelunk/binary/binary.hpp>
#include <spelunk/disasm/instruction.hpp>
#include <spelunk/disasm/x64_decoder.hpp>
#include <spelunk/ir/ssa.hpp>
#include <spelunk/ir/x64_lifter.hpp>

namespace spelunk {
namespace {

// What the convention rules read from one symbol. Copied rather than
// pointed to: the symbol table grows while functions are discovered.
struct SymbolFacts {
    std::string name;
    std::string library;  // lower-cased import DLL name
    bool        is_import = false;
};

struct Convention {
    Abi abi = Abi::Win32Cdecl;
    // Nullopt when the image does not say; see x86_callee_pop.
    std::optional<u16> pop;
};

struct X86Memo final : Binary::AnalysisMemo {
    std::once_flag indexed;
    std::unordered_map<addr_t, std::vector<SymbolFacts>> symbols_at;
    std::unordered_set<addr_t> entries;

    std::mutex mutex;
    std::unordered_map<addr_t, Convention> conventions;
    std::unordered_map<addr_t, X86FunctionInfo> functions;
};

std::string lowercase(std::string_view text) {
    std::string out(text);
    for (char& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return out;
}

X86Memo& memo_for(const Binary& binary) {
    auto& memo = binary.analysis_memo<X86Memo>();
    std::call_once(memo.indexed, [&] {
        for (const auto& symbol : binary.symbols()) {
            const SymbolFacts facts{symbol.name, lowercase(symbol.import_library),
                                    symbol.is_import};
            if (symbol.addr) memo.symbols_at[symbol.addr].push_back(facts);
            if (symbol.got_addr && symbol.got_addr != symbol.addr)
                memo.symbols_at[symbol.got_addr].push_back(facts);
            if (symbol.kind == SymbolKind::Function && symbol.addr)
                memo.entries.insert(symbol.addr);
        }
    });
    return memo;
}

// `_name@N` is stdcall and `@name@N` fastcall; N counts every argument
// byte, including the ones fastcall passes in ecx and edx.
struct Decoration {
    Abi      abi;
    unsigned bytes;
};

std::optional<Decoration> decoration(std::string_view name) {
    if (name.starts_with("__imp_")) name.remove_prefix(6);
    const auto at = name.rfind('@');
    if (name.empty() || (name.front() != '_' && name.front() != '@') ||
        at == std::string_view::npos || at <= 1) {
        return std::nullopt;
    }
    const auto suffix = name.substr(at + 1);
    unsigned bytes = 0;
    const auto parsed = std::from_chars(suffix.data(), suffix.data() + suffix.size(), bytes);
    if (parsed.ec != std::errc{} || parsed.ptr != suffix.data() + suffix.size() ||
        bytes > 0xffffu) {
        return std::nullopt;
    }
    return Decoration{name.front() == '@' ? Abi::Win32Fastcall : Abi::Win32Stdcall, bytes};
}

u16 decorated_pop(const Decoration& decorated) {
    const unsigned register_bytes = decorated.abi == Abi::Win32Fastcall
        ? 4u * static_cast<unsigned>(int_arg_regs(decorated.abi).size()) : 0u;
    return static_cast<u16>(decorated.bytes > register_bytes ? decorated.bytes - register_bytes : 0);
}

bool is_crt_library(std::string_view library) {
    return library.starts_with("api-ms-win-crt-") || library.starts_with("msvcr") ||
        library.starts_with("msvcp") || library.starts_with("ucrt") ||
        library.starts_with("vcruntime");
}

// DLLs whose exports are WINAPI unless shown otherwise.
bool is_system_library(std::string_view library) {
    if (library.starts_with("api-ms-win-") || library.starts_with("ext-ms-")) {
        return !library.starts_with("api-ms-win-crt-");
    }
    static constexpr std::array<std::string_view, 32> kSystem = {
        "kernel32.dll", "kernelbase.dll", "ntdll.dll",    "user32.dll",
        "gdi32.dll",    "advapi32.dll",   "shell32.dll",  "shlwapi.dll",
        "ole32.dll",    "oleaut32.dll",   "comctl32.dll", "comdlg32.dll",
        "ws2_32.dll",   "wsock32.dll",    "winmm.dll",    "version.dll",
        "crypt32.dll",  "wininet.dll",    "winhttp.dll",  "psapi.dll",
        "dbghelp.dll",  "imm32.dll",      "secur32.dll",  "setupapi.dll",
        "rpcrt4.dll",   "iphlpapi.dll",   "netapi32.dll", "userenv.dll",
        "bcrypt.dll",   "opengl32.dll",   "d3d9.dll",     "dsound.dll",
    };
    return std::ranges::find(kSystem, library) != kSystem.end();
}

unsigned slot_bytes(const TypeArena& arena, TypeRef type) {
    const auto& node = arena.node(type);
    const unsigned bytes = arena.kind(type) == TypeKind::Float ? node.f.bits / 8u
        : arena.kind(type) == TypeKind::Int ? node.i.bits / 8u : 4u;
    return (std::max(4u, bytes) + 3u) / 4u * 4u;
}

IrType slot_type(const TypeArena& arena, TypeRef type) {
    const auto& node = arena.node(type);
    if (arena.kind(type) == TypeKind::Float) return node.f.bits <= 32 ? IrType::F32 : IrType::F64;
    if (arena.kind(type) == TypeKind::Int && node.i.bits > 32) return IrType::I64;
    return IrType::I32;
}

X86FunctionInfo import_info(const SymbolFacts& import, std::optional<Decoration> decorated,
                            std::optional<u16>* pop) {
    X86FunctionInfo info;
    const auto name = strip_import_name_decorations(import.name);
    TypeArena arena;
    const auto prototype = lookup_import_sig(name, arena, 32);
    if (decorated) {
        info.abi = decorated->abi;
    } else if (!is_system_library(import.library) ||
               (prototype && prototype->variadic) || name.starts_with('_') ||
               (import.library == "ntdll.dll" && !name.empty() &&
                std::islower(static_cast<unsigned char>(name.front()))) ||
               name.starts_with("wsprintf") || name.starts_with("wnsprintf")) {
        // CRT exports, and ntdll's copies of them, are cdecl; so is anything
        // variadic. Third-party DLLs are assumed cdecl until a call site
        // shows otherwise.
        info.abi = Abi::Win32Cdecl;
    } else {
        info.abi = Abi::Win32Stdcall;
    }

    std::optional<u16> bytes;
    if (decorated) bytes = decorated_pop(*decorated);
    if (prototype) {
        const auto regs = int_arg_regs(info.abi);
        std::size_t next_reg = 0;
        i64 offset = 4;
        for (TypeRef type : prototype->params) {
            const IrType ir_type = slot_type(arena, type);
            if (next_reg < regs.size() && ir_type == IrType::I32) {
                info.arguments.push_back({regs[next_reg++], ir_type});
                continue;
            }
            info.arguments.push_back({Reg::None, ir_type, false, offset});
            offset += slot_bytes(arena, type);
        }
        if (!bytes) {
            bytes = info.abi == Abi::Win32Cdecl ? 0 : static_cast<u16>(offset - 4);
        }
    } else if (!bytes && (is_crt_library(import.library) ||
                          (info.abi == Abi::Win32Cdecl &&
                           is_system_library(import.library)))) {
        bytes = 0;
    }
    info.callee_pop = bytes.value_or(0);
    if (pop) *pop = bytes;
    return info;
}

std::optional<Decoration> decoration_at(const std::vector<SymbolFacts>* facts) {
    if (!facts) return std::nullopt;
    for (const auto& symbol : *facts) {
        if (auto decorated = decoration(symbol.name)) return decorated;
    }
    return std::nullopt;
}

const SymbolFacts* import_at(const std::vector<SymbolFacts>* facts) {
    if (!facts) return nullptr;
    for (const auto& symbol : *facts) {
        if (symbol.is_import) return &symbol;
    }
    return nullptr;
}

Result<Function> build_cfg(const Binary& binary, const X86Memo& memo, addr_t entry) {
    const X64Decoder decoder(false);
    CfgBuilder builder(binary, decoder, false);
    builder.seed_known_entries(memo.entries);
    return builder.build(entry);
}

Convention convention_of(const Binary& binary, X86Memo& memo, addr_t target, unsigned depth);

// RET n is authoritative for code in the image. A function with no return
// of its own pops whatever the function it tail-jumps to pops.
Convention convention_from_cfg(const Binary& binary, X86Memo& memo, const Function& function,
                               std::optional<Decoration> decorated, unsigned depth) {
    std::optional<u16> pop;
    std::optional<addr_t> tail;
    for (const auto& block : function.blocks) {
        for (const auto& insn : block.instructions) {
            if (insn.mnemonic == Mnemonic::Ret) {
                const bool has_imm = insn.num_operands == 1 &&
                    insn.operands[0].kind == Operand::Kind::Immediate;
                pop = std::max<u16>(pop.value_or(0), has_imm
                    ? static_cast<u16>(insn.operands[0].imm.value) : u16{0});
            } else if (insn.mnemonic == Mnemonic::Jmp && block.successors.empty()) {
                if (auto jump = branch_target(insn)) tail = *jump;
            }
        }
    }
    if (!pop && tail && depth < 4) pop = convention_of(binary, memo, *tail, depth + 1).pop;
    Convention convention;
    convention.pop = pop;
    if (decorated && !convention.pop) convention.pop = decorated_pop(*decorated);
    convention.abi = decorated ? decorated->abi
        : convention.pop.value_or(0) ? Abi::Win32Stdcall : Abi::Win32Cdecl;
    return convention;
}

Convention remember(X86Memo& memo, addr_t target, const Convention& convention) {
    const std::lock_guard lock(memo.mutex);
    return memo.conventions.emplace(target, convention).first->second;
}

Convention convention_of(const Binary& binary, X86Memo& memo, addr_t target, unsigned depth) {
    if (target == 0) return {};
    {
        const std::lock_guard lock(memo.mutex);
        if (auto found = memo.conventions.find(target); found != memo.conventions.end())
            return found->second;
    }
    const auto symbols = memo.symbols_at.find(target);
    const auto* facts = symbols == memo.symbols_at.end() ? nullptr : &symbols->second;
    const auto decorated = decoration_at(facts);
    Convention convention;
    if (const auto* import = import_at(facts)) {
        convention.abi = import_info(*import, decorated, &convention.pop).abi;
    } else if (const auto function = build_cfg(binary, memo, target)) {
        convention = convention_from_cfg(binary, memo, *function, decorated, depth);
    } else if (decorated) {
        convention = {decorated->abi, decorated_pop(*decorated)};
    }
    return remember(memo, target, convention);
}

std::optional<addr_t> call_target(const Instruction& insn) {
    if (auto target = branch_target(insn)) return target;
    if (insn.num_operands != 1) return std::nullopt;
    const auto& op = insn.operands[0];
    if (op.kind == Operand::Kind::Memory && op.mem.base == Reg::None &&
        op.mem.index == Reg::None && op.mem.has_disp) {
        return static_cast<addr_t>(static_cast<u32>(op.mem.disp));
    }
    return std::nullopt;
}

bool is_esp(const Operand& op) {
    return op.kind == Operand::Kind::Register && canonical_reg(op.reg) == Reg::Rsp;
}

// `push ebx/esi/edi/ebp`: how a prologue saves the registers it will use.
bool is_callee_saved_push(const Instruction& insn) {
    if (insn.mnemonic != Mnemonic::Push || insn.num_operands != 1 ||
        insn.operands[0].kind != Operand::Kind::Register) return false;
    const Reg reg = canonical_reg(insn.operands[0].reg);
    return reg == Reg::Rbx || reg == Reg::Rsi || reg == Reg::Rdi || reg == Reg::Rbp;
}

// `mov ebp, esp`.
bool is_frame_setup(const Instruction& insn) {
    return insn.mnemonic == Mnemonic::Mov && insn.num_operands == 2 &&
           insn.operands[0].kind == Operand::Kind::Register &&
           canonical_reg(insn.operands[0].reg) == Reg::Rbp && is_esp(insn.operands[1]);
}

// Stack-pointer offset from entry for every SSA value derived from it, by
// constant propagation over the SSA graph. Phis whose paths disagree, and
// values not derived from the entry stack pointer, have no offset.
class StackOffsets {
public:
    explicit StackOffsets(const IrFunction& fn) {
        std::vector<const IrInst*> insts;
        for (const auto& block : fn.blocks) {
            for (const auto& inst : block.insts) {
                if (ssa_key(inst.dst)) insts.push_back(&inst);
            }
        }
        for (std::size_t round = 0; round < 64; ++round) {
            bool changed = false;
            for (const IrInst* inst : insts) {
                const Fact fact = evaluate(*inst);
                if (fact.kind == Fact::Unknown) continue;
                auto [it, inserted] = facts_.try_emplace(*ssa_key(inst->dst), fact);
                if (inserted) {
                    changed = true;
                } else if (it->second.kind == Fact::Known &&
                           (fact.kind == Fact::Conflict || fact.offset != it->second.offset)) {
                    // Facts only ever move from known to conflicting.
                    it->second.kind = Fact::Conflict;
                    changed = true;
                }
            }
            if (!changed) break;
        }
    }

    [[nodiscard]] std::optional<i64> of(const IrValue& value) const {
        const Fact fact = lookup(value);
        if (fact.kind != Fact::Known) return std::nullopt;
        return fact.offset;
    }

private:
    struct Fact {
        enum Kind : u8 { Unknown, Known, Conflict } kind = Unknown;
        i64 offset = 0;
    };

    [[nodiscard]] Fact lookup(const IrValue& value) const {
        if (value.kind == IrValueKind::Reg && value.version == 0) {
            return canonical_reg(value.reg) == Reg::Rsp
                ? Fact{Fact::Known, 0} : Fact{Fact::Conflict, 0};
        }
        const auto key = ssa_key(value);
        if (!key) return {Fact::Conflict, 0};
        const auto found = facts_.find(*key);
        return found == facts_.end() ? Fact{} : found->second;
    }

    [[nodiscard]] Fact evaluate(const IrInst& inst) const {
        switch (inst.op) {
            case IrOp::Assign:
            case IrOp::ZExt:
            case IrOp::Trunc:
                return inst.src_count ? lookup(inst.srcs[0]) : Fact{};
            case IrOp::Add:
            case IrOp::Sub: {
                if (inst.src_count != 2) return {};
                const IrValue* base = &inst.srcs[0];
                i64 delta = 0;
                if (inst.srcs[1].kind == IrValueKind::Imm) {
                    delta = inst.op == IrOp::Add ? inst.srcs[1].imm : -inst.srcs[1].imm;
                } else if (inst.op == IrOp::Add && inst.srcs[0].kind == IrValueKind::Imm) {
                    base = &inst.srcs[1];
                    delta = inst.srcs[0].imm;
                } else {
                    return {Fact::Conflict, 0};
                }
                Fact fact = lookup(*base);
                fact.offset += delta;
                return fact;
            }
            case IrOp::Phi: {
                const auto self = ssa_key(inst.dst);
                Fact merged;
                for (const auto& operand : inst.phi_operands) {
                    if (ssa_key(operand) == self) continue;
                    const Fact fact = lookup(operand);
                    if (fact.kind == Fact::Unknown) continue;
                    if (fact.kind == Fact::Conflict ||
                        (merged.kind == Fact::Known && merged.offset != fact.offset)) {
                        return {Fact::Conflict, 0};
                    }
                    merged = fact;
                }
                return merged;
            }
            default:
                return {Fact::Conflict, 0};
        }
    }

    std::map<SsaKey, Fact> facts_;
};

bool is_entry_value(const IrValue& value, Reg reg) {
    return value.kind == IrValueKind::Reg && value.version == 0 &&
        canonical_reg(value.reg) == reg;
}

bool same_value(const IrValue& a, const IrValue& b) {
    return a.kind == b.kind && ssa_key(a) && ssa_key(a) == ssa_key(b);
}

// x ^ x and x - x, with the borrow and overflow of the latter, are
// constants: the zero idioms `xor r, r` and `sub r, r`.
bool is_self_cancelling(const IrInst& inst) {
    const bool cancels = inst.op == IrOp::Xor || inst.op == IrOp::Sub ||
        inst.op == IrOp::SubBorrow || inst.op == IrOp::SubOverflow;
    return cancels && inst.src_count == 2 && same_value(inst.srcs[0], inst.srcs[1]);
}

// The merge half of a partial register write keeps the caller's upper bits
// but never decides anything with them.
bool is_partial_write_merge(const IrInst& inst) {
    if (inst.op != IrOp::And || inst.src_count != 2 ||
        inst.srcs[1].kind != IrValueKind::Imm) {
        return false;
    }
    const auto mask = static_cast<u32>(inst.srcs[1].imm);
    return mask == 0xffffff00u || mask == 0xffff0000u || mask == 0xffff00ffu;
}

// Whether `reg` carries an argument in: read before written, ignoring
// reads that cannot observe the caller's value. Zero idioms and partial
// writes don't; a spill does only if the slot is reloaded for use rather
// than to restore the register, or is handed to a call as its first stack
// argument (`push ecx; call f` forwarding `this`).
bool reads_entry_register(const IrFunction& fn, const StackOffsets& stack, Reg reg) {
    std::set<i64> spills;
    std::set<i64> other_stores;
    std::set<i64> call_stacks;
    for (const auto& block : fn.blocks) {
        for (const auto& inst : block.insts) {
            if (inst.op == IrOp::Store && inst.src_count >= 2) {
                if (auto offset = stack.of(inst.srcs[0])) {
                    if (is_entry_value(inst.srcs[1], reg)) spills.insert(*offset);
                    else other_stores.insert(*offset);
                }
            }
            if (inst.op == IrOp::Intrinsic && inst.name == "call.stack_pointer" &&
                inst.src_count) {
                if (auto offset = stack.of(inst.srcs[0])) call_stacks.insert(*offset);
            }
            if (inst.op == IrOp::Return || inst.op == IrOp::Phi ||
                (inst.op == IrOp::Intrinsic && inst.name.starts_with("call."))) {
                continue;
            }
            for (u8 i = 0; i < inst.src_count; ++i) {
                if (!is_entry_value(inst.srcs[i], reg)) continue;
                if (is_self_cancelling(inst)) continue;
                if (is_partial_write_merge(inst)) continue;
                if (inst.op == IrOp::Store && i == 1 && stack.of(inst.srcs[0])) continue;
                return true;
            }
        }
    }
    std::erase_if(spills, [&](i64 offset) { return other_stores.contains(offset); });
    if (spills.empty()) return false;
    for (i64 offset : spills) {
        if (call_stacks.contains(offset)) return true;
    }

    std::map<SsaKey, std::vector<const IrInst*>> uses;
    for (const auto& block : fn.blocks) {
        for (const auto& inst : block.insts) {
            for (u8 i = 0; i < inst.src_count; ++i) {
                if (auto key = ssa_key(inst.srcs[i])) uses[*key].push_back(&inst);
            }
            for (const auto& operand : inst.phi_operands) {
                if (auto key = ssa_key(operand)) uses[*key].push_back(&inst);
            }
        }
    }
    for (const auto& block : fn.blocks) {
        for (const auto& inst : block.insts) {
            if (inst.op != IrOp::Load || !inst.src_count) continue;
            const auto offset = stack.of(inst.srcs[0]);
            if (!offset || !spills.contains(*offset)) continue;
            const auto key = ssa_key(inst.dst);
            if (!key) continue;
            for (const IrInst* use : uses[*key]) {
                const bool restore = use->op == IrOp::Assign &&
                    use->dst.kind == IrValueKind::Reg && canonical_reg(use->dst.reg) == reg;
                if (!restore) return true;
            }
        }
    }
    return false;
}

// ecx and edx when nothing in the function writes them. Its own calls
// clobber them in the analysis lift, so this is transitive; a tail jump or
// an unresolved indirect jump leaves the question to code not seen here.
std::vector<Reg> preserved_registers(const Function& function, const IrFunction& ir) {
    for (const auto& block : function.blocks) {
        if (!block.successors.empty() || block.instructions.empty()) continue;
        if (block.instructions.back().mnemonic == Mnemonic::Jmp) return {};
    }
    bool ecx = true;
    bool edx = true;
    for (const auto& block : ir.blocks) {
        for (const auto& inst : block.insts) {
            if (inst.dst.kind != IrValueKind::Reg) continue;
            ecx &= canonical_reg(inst.dst.reg) != Reg::Rcx;
            edx &= canonical_reg(inst.dst.reg) != Reg::Rdx;
        }
    }
    std::vector<Reg> preserved;
    if (ecx) preserved.push_back(Reg::Rcx);
    if (edx) preserved.push_back(Reg::Rdx);
    return preserved;
}

X86FunctionInfo analyze_uncached(const Binary& binary, X86Memo& memo, addr_t entry) {
    if (entry == 0) return {};
    const auto symbols = memo.symbols_at.find(entry);
    const auto* facts = symbols == memo.symbols_at.end() ? nullptr : &symbols->second;
    const auto decorated = decoration_at(facts);
    if (const auto* import = import_at(facts)) return import_info(*import, decorated, nullptr);

    X86FunctionInfo info;
    std::map<i64, IrType> stack;
    bool ecx = false;
    bool edx = false;
    if (const auto function = build_cfg(binary, memo, entry)) {
        info.callee_pop = remember(memo, entry, convention_from_cfg(
            binary, memo, *function, decorated, 0)).pop.value_or(0);
        // The analysis lift applies callee pops but does not resolve this
        // function's own convention, which is what is being computed here.
        auto ir = X64Lifter(Abi::Win32Cdecl, &binary, false).lift(*function);
        if (ir && SsaBuilder{}.convert(*ir)) {
            const StackOffsets offsets(*ir);
            ecx = reads_entry_register(*ir, offsets, Reg::Rcx);
            edx = reads_entry_register(*ir, offsets, Reg::Rdx);
            info.preserved = preserved_registers(*function, *ir);
            for (const auto& block : ir->blocks) {
                for (const auto& inst : block.insts) {
                    if (inst.op != IrOp::Load || !inst.src_count) continue;
                    const auto offset = offsets.of(inst.srcs[0]);
                    if (offset && *offset >= 4 &&
                        *offset <= 4 * static_cast<i64>(kMaxAbiArgs) && *offset % 4 == 0) {
                        stack[*offset] = inst.dst.type;
                    }
                }
            }
        }
    }
    info.abi = decorated ? decorated->abi
        : edx ? Abi::Win32Fastcall
        : ecx ? Abi::Win32Thiscall
        : info.callee_pop ? Abi::Win32Stdcall : Abi::Win32Cdecl;
    const auto regs = int_arg_regs(info.abi);
    if (decorated && !info.callee_pop) info.callee_pop = decorated_pop(*decorated);
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


// Symbolic execution of a straight-line frame helper. Values are constants,
// addresses relative to the caller's esp before the call or its ebp, the
// word stored at such an address, or unknown.
struct FrameSym {
    enum class Kind : u8 { Unknown, Imm, Ptr, Load, ReturnAddress };
    Kind kind = Kind::Unknown;
    X86FrameValue::Base base = X86FrameValue::Base::CallSp;
    i64 value = 0;

    static FrameSym imm(i64 v) { return {Kind::Imm, {}, v}; }
    static FrameSym ptr(X86FrameValue::Base b, i64 off) { return {Kind::Ptr, b, off}; }
    [[nodiscard]] bool is_ptr() const { return kind == Kind::Ptr; }
};

std::optional<X86FrameHelper>
simulate_frame_helper(const Binary& binary, addr_t entry,
                      const std::vector<FrameSym>& pushed, FrameSym eax) {
    using Base = X86FrameValue::Base;
    using Kind = FrameSym::Kind;
    const X64Decoder decoder(false);
    std::array<FrameSym, 8> regs{};   // eax..edi
    std::map<std::pair<Base, i64>, FrameSym> stack;
    const auto index = [](Reg r) -> std::optional<std::size_t> {
        const Reg canon = canonical_reg(r);
        if (canon < Reg::Rax || canon > Reg::Rdi) return std::nullopt;
        return static_cast<std::size_t>(canon) - static_cast<std::size_t>(Reg::Rax);
    };
    constexpr std::size_t kEsp = 4, kEbp = 5;
    regs[0] = eax;
    regs[kEsp] = FrameSym::ptr(Base::CallSp, -4);
    regs[kEbp] = FrameSym::ptr(Base::CallerFp, 0);
    stack[{Base::CallSp, -4}] = {Kind::ReturnAddress, {}, 0};
    for (std::size_t i = 0; i < pushed.size(); ++i)
        stack[{Base::CallSp, static_cast<i64>(4 * i)}] = pushed[i];

    X86FrameHelper result;
    std::optional<FrameSym> record;
    std::array<bool, 3> written{};   // eax, ecx, edx
    const auto address = [&](const Mem& m) -> std::optional<std::pair<Base, i64>> {
        if (m.segment != Reg::None || m.index != Reg::None) return std::nullopt;
        const auto base = index(m.base);
        if (!base || !regs[*base].is_ptr()) return std::nullopt;
        return std::pair{regs[*base].base, regs[*base].value + m.disp};
    };
    const auto read = [&](const Operand& op) -> FrameSym {
        if (op.kind == Operand::Kind::Immediate) return FrameSym::imm(op.imm.value);
        if (op.kind == Operand::Kind::Register) {
            const auto r = index(op.reg);
            return r && reg_size(op.reg) == 4 ? regs[*r] : FrameSym{};
        }
        if (op.kind != Operand::Kind::Memory) return {};
        const auto at = address(op.mem);
        if (!at) return {};
        const auto found = stack.find(*at);
        return found != stack.end() ? found->second : FrameSym{Kind::Load, at->first, at->second};
    };
    // False when the write leaves esp or ebp unknowable.
    const auto write = [&](const Operand& op, FrameSym value) -> bool {
        if (op.kind == Operand::Kind::Register) {
            const auto r = index(op.reg);
            if (!r) return true;
            if (reg_size(op.reg) != 4) value = {};
            if ((*r == kEsp || *r == kEbp) && value.kind != Kind::Ptr && value.kind != Kind::Load)
                return false;
            if (*r < written.size()) written[*r] = true;
            regs[*r] = value;
            return true;
        }
        if (op.kind != Operand::Kind::Memory) return true;
        if (op.mem.segment == Reg::Fs && op.mem.base == Reg::None && op.mem.disp == 0) {
            if (value.is_ptr()) {
                result.links_seh = true;
                record = value;
            }
            return true;
        }
        if (const auto at = address(op.mem)) stack[*at] = value;
        return true;
    };
    const auto push = [&](FrameSym value) -> bool {
        if (!regs[kEsp].is_ptr()) return false;
        regs[kEsp].value -= 4;
        stack[{regs[kEsp].base, regs[kEsp].value}] = value;
        return true;
    };
    const auto pop = [&]() -> std::optional<FrameSym> {
        if (!regs[kEsp].is_ptr()) return std::nullopt;
        const auto found = stack.find({regs[kEsp].base, regs[kEsp].value});
        FrameSym value = found != stack.end() ? found->second
            : FrameSym{Kind::Load, regs[kEsp].base, regs[kEsp].value};
        regs[kEsp].value += 4;
        return value;
    };

    addr_t pc = entry;
    for (int step = 0; step < 64; ++step) {
        const auto bytes = binary.bytes_at(pc);
        if (bytes.empty()) return std::nullopt;
        const auto decoded = decoder.decode(bytes, pc);
        if (!decoded) return std::nullopt;
        const Instruction& insn = *decoded;
        pc += insn.length;
        const auto& dst = insn.operands[0];
        switch (insn.mnemonic) {
            case Mnemonic::Push:
                if (!push(read(dst))) return std::nullopt;
                continue;
            case Mnemonic::Pop: {
                const auto value = pop();
                if (!value || !write(dst, *value)) return std::nullopt;
                continue;
            }
            case Mnemonic::Mov:
                if (!write(dst, read(insn.operands[1]))) return std::nullopt;
                continue;
            case Mnemonic::Lea: {
                const auto at = address(insn.operands[1].mem);
                if (!write(dst, at ? FrameSym::ptr(at->first, at->second) : FrameSym{}))
                    return std::nullopt;
                continue;
            }
            case Mnemonic::Add:
            case Mnemonic::Sub: {
                FrameSym value = read(dst);
                const FrameSym amount = read(insn.operands[1]);
                const i64 sign = insn.mnemonic == Mnemonic::Add ? 1 : -1;
                if ((value.is_ptr() || value.kind == Kind::Imm) && amount.kind == Kind::Imm)
                    value.value += sign * amount.value;
                else
                    value = {};
                if (!write(dst, value)) return std::nullopt;
                continue;
            }
            case Mnemonic::Leave: {
                regs[kEsp] = regs[kEbp];
                const auto value = pop();
                if (!value || !write(Operand::make_reg(Reg::Ebp), *value)) return std::nullopt;
                continue;
            }
            case Mnemonic::Call:
                // __security_check_cookie in an epilogue: balanced, and it
                // keeps eax - the value the function is returning.
                if (!branch_target(insn)) return std::nullopt;
                regs[1] = regs[2] = {};
                written[1] = written[2] = true;
                continue;
            case Mnemonic::Jmp:
                if (const auto target = branch_target(insn)) {
                    pc = *target;
                    continue;
                }
                return std::nullopt;
            case Mnemonic::Ret: {
                const auto returned = pop();
                if (!returned || returned->kind != Kind::ReturnAddress) return std::nullopt;
                if (insn.num_operands && insn.operands[0].kind == Operand::Kind::Immediate)
                    regs[kEsp].value += insn.operands[0].imm.value;
                break;
            }
            default:
                if (ends_basic_block(insn.mnemonic)) return std::nullopt;
                if (insn.num_operands && !write(dst, {})) return std::nullopt;
                continue;
        }
        break;
    }
    const FrameSym sp = regs[kEsp];
    const FrameSym fp = regs[kEbp];
    if (!sp.is_ptr() || (fp.kind != Kind::Ptr && fp.kind != Kind::Load)) return std::nullopt;
    const bool fp_changed = !(fp.is_ptr() && fp.base == Base::CallerFp && fp.value == 0);
    if (!fp_changed && !result.links_seh) return std::nullopt;
    for (std::size_t r = 0; r < written.size(); ++r) {
        if (written[r]) result.clobbers.push_back(static_cast<Reg>(static_cast<unsigned>(Reg::Rax) + r));
    }
    result.sp = {sp.base, static_cast<i32>(sp.value), false};
    result.fp = {fp.base, static_cast<i32>(fp.value), fp.kind == Kind::Load};
    if (record) {
        const auto handler = stack.find({record->base, record->value + 4});
        if (handler != stack.end() && handler->second.kind == Kind::Imm)
            result.handler = static_cast<u32>(handler->second.value);
    }
    return result;
}

}  // namespace

X86FunctionInfo analyze_x86_function(const Binary& binary, addr_t entry) {
    auto& memo = memo_for(binary);
    {
        const std::lock_guard lock(memo.mutex);
        if (auto found = memo.functions.find(entry); found != memo.functions.end())
            return found->second;
    }
    X86FunctionInfo info = analyze_uncached(binary, memo, entry);
    const std::lock_guard lock(memo.mutex);
    return memo.functions.emplace(entry, std::move(info)).first->second;
}

std::optional<u16> x86_callee_pop(const Binary& binary, addr_t target) {
    return convention_of(binary, memo_for(binary), target, 0).pop;
}

bool mentions_esp(const Instruction& insn) {
    for (std::size_t i = 0; i < insn.num_operands; ++i) {
        const auto& op = insn.operands[i];
        if (is_esp(op)) return true;
        if (op.kind == Operand::Kind::Memory &&
            (canonical_reg(op.mem.base) == Reg::Rsp || canonical_reg(op.mem.index) == Reg::Rsp))
            return true;
    }
    return insn.mnemonic == Mnemonic::Push || insn.mnemonic == Mnemonic::Pop;
}

// Writes registers it does not name: a register it holds cannot be traced
// through these.
bool has_implicit_register_writes(Mnemonic mnemonic) {
    switch (mnemonic) {
        case Mnemonic::Movsb: case Mnemonic::Movsd: case Mnemonic::Movsq:
        case Mnemonic::Stosb: case Mnemonic::Stosd: case Mnemonic::Stosq:
        case Mnemonic::Lodsb: case Mnemonic::Lodsd: case Mnemonic::Lodsq:
        case Mnemonic::Scasb: case Mnemonic::Scasd: case Mnemonic::Scasq:
        case Mnemonic::Cmpsb: case Mnemonic::Cmpsd: case Mnemonic::Cmpsq:
        case Mnemonic::Mul: case Mnemonic::Div: case Mnemonic::Idiv:
        case Mnemonic::Cdq: case Mnemonic::Cpuid: case Mnemonic::Rdtsc:
        case Mnemonic::Xchg:
            return true;
        default:
            return false;
    }
}

// The memory slot `call reg` reaches: `mov esi, [__imp__X]` once, then
// `call esi` - MSVC's habit for an import called repeatedly - or gcc's
// `mov ebp, [__imp__X]` hoisted above a loop. Every path into the call
// must load the register from the same absolute slot.
std::optional<addr_t> register_call_slot(const Function& fn, std::size_t block_index,
                                         std::size_t end, Reg reg) {
    enum class Answer { Unknown, Slot, Conflict };
    std::optional<addr_t> slot;
    std::set<std::size_t> visited;
    const bool caller_saved = reg == Reg::Rax || reg == Reg::Rcx || reg == Reg::Rdx;
    const auto walk = [&](this const auto& self, std::size_t index, std::size_t limit) -> Answer {
        const auto& insns = fn.blocks[index].instructions;
        for (std::size_t j = limit; j-- > 0;) {
            const auto& prior = insns[j];
            if (has_implicit_register_writes(prior.mnemonic)) return Answer::Conflict;
            if (prior.mnemonic == Mnemonic::Call) {
                if (caller_saved) return Answer::Conflict;
                continue;
            }
            if (prior.num_operands == 0 || prior.operands[0].kind != Operand::Kind::Register ||
                canonical_reg(prior.operands[0].reg) != reg) continue;
            if (prior.mnemonic == Mnemonic::Cmp || prior.mnemonic == Mnemonic::Test ||
                prior.mnemonic == Mnemonic::Push) continue;
            const auto& source = prior.num_operands == 2 ? prior.operands[1] : prior.operands[0];
            if (prior.mnemonic != Mnemonic::Mov || source.kind != Operand::Kind::Memory ||
                source.mem.base != Reg::None || source.mem.index != Reg::None ||
                !source.mem.has_disp) return Answer::Conflict;
            const auto found = static_cast<addr_t>(static_cast<u32>(source.mem.disp));
            if (slot && *slot != found) return Answer::Conflict;
            slot = found;
            return Answer::Slot;
        }
        if (fn.blocks[index].start == fn.start || fn.blocks[index].predecessors.empty())
            return Answer::Conflict;
        bool any = false;
        for (addr_t predecessor : fn.blocks[index].predecessors) {
            const auto at = fn.block_at.find(predecessor);
            if (at == fn.block_at.end()) return Answer::Conflict;
            if (!visited.insert(at->second).second) continue;
            const Answer answer = self(at->second, fn.blocks[at->second].instructions.size());
            if (answer == Answer::Conflict) return Answer::Conflict;
            any = any || answer == Answer::Slot;
        }
        return any ? Answer::Slot : Answer::Unknown;
    };
    visited.insert(block_index);
    return walk(block_index, end) == Answer::Slot ? slot : std::nullopt;
}

std::unordered_map<addr_t, u16> x86_call_pops(const Binary& binary, const Function& fn) {
    auto& memo = memo_for(binary);
    std::unordered_map<addr_t, u16> pops;
    for (std::size_t block_index = 0; block_index < fn.blocks.size(); ++block_index) {
        const auto& block = fn.blocks[block_index];
        const auto& insns = block.instructions;
        for (std::size_t i = 0; i < insns.size(); ++i) {
            const auto& insn = insns[i];
            if (insn.mnemonic != Mnemonic::Call) continue;
            auto target = call_target(insn);
            if (!target && insn.num_operands == 1 &&
                insn.operands[0].kind == Operand::Kind::Register) {
                target = register_call_slot(fn, block_index, i,
                                            canonical_reg(insn.operands[0].reg));
            }
            const Convention convention = target
                ? convention_of(binary, memo, *target, 0) : Convention{};
            std::optional<u16> pop = convention.pop;
            if (!pop) {
                // gcc re-reserves the outgoing area a callee popped, perhaps
                // after moving the result somewhere (`mov esi, eax`).
                const std::vector<Instruction>* run = &insns;
                std::size_t next = i + 1;
                for (unsigned seen = 0; seen < 4; ++seen, ++next) {
                    if (next == run->size()) {
                        const auto after = fn.block_at.find(insn.address + insn.length);
                        if (run != &insns || after == fn.block_at.end()) break;
                        run = &fn.blocks[after->second].instructions;
                        next = 0;
                        if (run->empty()) break;
                    }
                    const auto& following = (*run)[next];
                    if (following.mnemonic == Mnemonic::Sub && following.num_operands == 2 &&
                        is_esp(following.operands[0]) &&
                        following.operands[1].kind == Operand::Kind::Immediate) {
                        pop = static_cast<u16>(following.operands[1].imm.value);
                        break;
                    }
                    if (mentions_esp(following) || ends_basic_block(following.mnemonic) ||
                        following.mnemonic == Mnemonic::Call) break;
                }
            }
            if (!pop && convention.abi == Abi::Win32Stdcall) {
                // A stdcall callee pops what was pushed for it - but not the
                // callee-saved registers the prologue pushed just before it
                // (`sub esp, 0x58; push ebx; push esi; push edi; call
                // [GetVersion]`).
                unsigned pushed = 0;
                unsigned saves = 0;  // saves adjacent to where the walk stops
                bool prologue = block.start == fn.start;
                for (std::size_t j = i; j-- > 0;) {
                    const auto& prior = insns[j];
                    if (prior.mnemonic == Mnemonic::Push) {
                        const unsigned bytes = prior.prefixes.opsize ? 2u : 4u;
                        pushed += bytes;
                        saves = is_callee_saved_push(prior) ? saves + bytes : 0;
                        continue;
                    }
                    if (prior.mnemonic == Mnemonic::Call) {
                        prologue = false;
                        break;
                    }
                    if (prior.num_operands && is_esp(prior.operands[0])) break;
                    if (is_frame_setup(prior)) break;
                    saves = 0;
                }
                pop = static_cast<u16>(pushed - (prologue ? saves : 0));
            }
            if (pop.value_or(0)) pops[insn.address] = *pop;
        }
    }
    return pops;
}

std::unordered_map<addr_t, std::vector<Reg>>
x86_call_preserved(const Binary& binary, const Function& fn) {
    auto& memo = memo_for(binary);
    std::unordered_map<addr_t, std::vector<Reg>> preserved;
    for (const auto& block : fn.blocks) {
        for (const auto& insn : block.instructions) {
            if (insn.mnemonic != Mnemonic::Call) continue;
            const auto target = branch_target(insn);
            if (!target) continue;
            const auto symbols = memo.symbols_at.find(*target);
            if (symbols != memo.symbols_at.end() && import_at(&symbols->second)) continue;
            auto info = analyze_x86_function(binary, *target);
            if (!info.preserved.empty()) preserved.emplace(insn.address, std::move(info.preserved));
        }
    }
    return preserved;
}

std::unordered_map<addr_t, X86FrameHelper>
x86_frame_helpers(const Binary& binary, const Function& fn) {
    std::unordered_map<addr_t, X86FrameHelper> helpers;
    for (const auto& block : fn.blocks) {
        const auto& insns = block.instructions;
        for (std::size_t i = 0; i < insns.size(); ++i) {
            if (insns[i].mnemonic != Mnemonic::Call) continue;
            const auto target = branch_target(insns[i]);
            if (!target) continue;
            // What the call site hands over: its pushes, nearest first, and
            // a constant in eax (`mov eax, handler; call __EH_prolog3`).
            std::vector<FrameSym> pushed;
            std::optional<FrameSym> eax;
            for (std::size_t j = i; j-- > 0 && pushed.size() < 8;) {
                const auto& prior = insns[j];
                if (prior.mnemonic == Mnemonic::Push) {
                    pushed.push_back(prior.operands[0].kind == Operand::Kind::Immediate
                        ? FrameSym::imm(prior.operands[0].imm.value) : FrameSym{});
                    continue;
                }
                if (prior.mnemonic == Mnemonic::Call || mentions_esp(prior)) break;
                if (!eax && prior.mnemonic == Mnemonic::Mov && prior.num_operands == 2 &&
                    prior.operands[0].kind == Operand::Kind::Register &&
                    prior.operands[0].reg == Reg::Eax &&
                    prior.operands[1].kind == Operand::Kind::Immediate) {
                    eax = FrameSym::imm(prior.operands[1].imm.value);
                }
            }
            if (auto helper = simulate_frame_helper(binary, *target, pushed, eax.value_or(FrameSym{})))
                helpers.emplace(insns[i].address, *helper);
        }
    }
    return helpers;
}

}  // namespace spelunk
