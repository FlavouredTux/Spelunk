#include <ember/analysis/arity.hpp>

#include <array>
#include <cstddef>
#include <span>

#include <ember/disasm/instruction.hpp>
#include <ember/disasm/register.hpp>
#include <ember/disasm/x64_decoder.hpp>
#include <ember/ir/ssa.hpp>

namespace ember {

namespace {

[[nodiscard]] bool is_rsp_adjust(const Instruction& insn, Mnemonic mn) noexcept {
    if (insn.mnemonic != mn || insn.num_operands != 2) return false;
    if (insn.operands[0].kind != Operand::Kind::Register ||
        canonical_reg(insn.operands[0].reg) != Reg::Rsp) {
        return false;
    }
    return insn.operands[1].kind == Operand::Kind::Immediate;
}

[[nodiscard]] std::optional<addr_t>
follow_trivial_wrapper(const Binary& b, addr_t target) noexcept {
    X64Decoder dec;

    auto decode_at = [&](addr_t ip) -> std::optional<Instruction> {
        auto span = b.bytes_at(ip);
        if (span.empty()) return std::nullopt;
        auto decoded = dec.decode(span, ip);
        if (!decoded) return std::nullopt;
        return *decoded;
    };

    auto first = decode_at(target);
    if (!first) return std::nullopt;

    addr_t ip = target;
    if (first->mnemonic == Mnemonic::Endbr64) {
        ip += first->length;
        first = decode_at(ip);
        if (!first) return std::nullopt;
    }

    bool saw_shadow = false;
    if (is_rsp_adjust(*first, Mnemonic::Sub)) {
        saw_shadow = true;
        ip += first->length;
        first = decode_at(ip);
        if (!first) return std::nullopt;
    }

    if (first->mnemonic == Mnemonic::Jmp &&
        first->num_operands == 1 &&
        first->operands[0].kind == Operand::Kind::Relative) {
        return first->operands[0].rel.target;
    }

    if (first->mnemonic != Mnemonic::Call ||
        first->num_operands != 1 ||
        first->operands[0].kind != Operand::Kind::Relative) {
        return std::nullopt;
    }

    addr_t callee = first->operands[0].rel.target;
    ip += first->length;

    auto second = decode_at(ip);
    if (!second) return std::nullopt;
    if (saw_shadow) {
        if (!is_rsp_adjust(*second, Mnemonic::Add)) return std::nullopt;
        ip += second->length;
        second = decode_at(ip);
        if (!second) return std::nullopt;
    }

    if (second->mnemonic != Mnemonic::Ret) return std::nullopt;
    if (callee == target) return std::nullopt;
    return callee;
}

[[nodiscard]] int arg_reg_index(std::span<const Reg> args, Reg r) noexcept {
    const Reg c = canonical_reg(r);
    for (std::size_t i = 0; i < args.size(); ++i) {
        if (c == args[i]) return static_cast<int>(i);
    }
    return -1;
}

enum class DstRole : u8 { WriteOnly, ReadWrite, ReadOnly };

[[nodiscard]] DstRole dst_role(Mnemonic m) noexcept {
    switch (m) {
        case Mnemonic::Mov:  case Mnemonic::Movzx:
        case Mnemonic::Movsx:case Mnemonic::Movsxd:
        case Mnemonic::Lea:  case Mnemonic::Pop:
            return DstRole::WriteOnly;

        case Mnemonic::Add: case Mnemonic::Sub:
        case Mnemonic::Adc: case Mnemonic::Sbb:
        case Mnemonic::And: case Mnemonic::Or: case Mnemonic::Xor:
        case Mnemonic::Neg: case Mnemonic::Not:
        case Mnemonic::Shl: case Mnemonic::Shr: case Mnemonic::Sar:
        case Mnemonic::Inc: case Mnemonic::Dec:
        case Mnemonic::Imul: case Mnemonic::Xchg:
            return DstRole::ReadWrite;

        default:
            return DstRole::ReadOnly;
    }
}

}  // namespace

u8 infer_arity(const Binary& b, addr_t target, Abi abi) noexcept {
    if (b.arch() != Arch::X86_64) return 0;
    const auto args = int_arg_regs(abi);
    const u8 max_arity = static_cast<u8>(args.size());

    // Transparently follow trivial wrappers (`jmp target`, `call target; ret`,
    // and the Win64 shadow-space variant) so forwarding stubs inherit the
    // underlying callee's arity instead of appearing variadic or arg-less.
    for (int hops = 0; hops < 6; ++hops) {
        auto hop_target = follow_trivial_wrapper(b, target);
        if (!hop_target) break;
        target = *hop_target;
    }

    auto entry_bytes = b.bytes_at(target);
    if (entry_bytes.empty()) return max_arity;

    std::array<bool, kMaxAbiIntArgs> written{};
    int max_live_in = -1;

    X64Decoder dec;
    addr_t ip = target;
    for (int step = 0; step < 128; ++step) {
        auto span = b.bytes_at(ip);
        if (span.empty()) break;
        auto decoded = dec.decode(span, ip);
        if (!decoded) break;
        const Instruction& insn = *decoded;

        const DstRole role = dst_role(insn.mnemonic);
        const bool dst_writes = (role == DstRole::WriteOnly || role == DstRole::ReadWrite);
        const bool dst_reads  = (role == DstRole::ReadOnly  || role == DstRole::ReadWrite);

        auto touch = [&](Reg r, bool read, bool write) {
            const int idx = arg_reg_index(args, r);
            if (idx < 0) return;
            const auto u = static_cast<std::size_t>(idx);
            if (read && !written[u]) {
                if (idx > max_live_in) max_live_in = idx;
            }
            if (write) written[u] = true;
        };

        for (u8 j = 0; j < insn.num_operands; ++j) {
            const Operand& op = insn.operands[j];
            const bool is_dst = (j == 0);
            const bool read  = is_dst ? dst_reads  : true;
            const bool write = is_dst ? dst_writes : false;

            if (op.kind == Operand::Kind::Register) {
                touch(op.reg, read, write);
            } else if (op.kind == Operand::Kind::Memory) {
                if (op.mem.base  != Reg::None) touch(op.mem.base,  true, false);
                if (op.mem.index != Reg::None) touch(op.mem.index, true, false);
            }
        }

        if (insn.mnemonic == Mnemonic::Ret  ||
            insn.mnemonic == Mnemonic::Jmp  ||
            insn.mnemonic == Mnemonic::Ud2  ||
            insn.mnemonic == Mnemonic::Hlt) break;

        ip += insn.length;
    }

    return static_cast<u8>(max_live_in + 1);
}

u8 infer_arity(const Binary& b, addr_t target) noexcept {
    return infer_arity(b, target, abi_for(b.format(), b.arch(), b.endian()));
}

}  // namespace ember
