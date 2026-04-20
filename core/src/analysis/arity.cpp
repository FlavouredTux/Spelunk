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
    const auto args = int_arg_regs(abi);
    const u8 max_arity = static_cast<u8>(args.size());

    // Transparently follow a single leading unconditional `jmp <rel>` so
    // wrappers report the underlying callee's arity. Depth-limited to avoid
    // pathological chains.
    for (int hops = 0; hops < 4; ++hops) {
        auto span = b.bytes_at(target);
        if (span.empty()) break;
        X64Decoder dec0;
        auto decoded = dec0.decode(span, target);
        if (!decoded) break;
        const Instruction& insn = *decoded;
        if (insn.mnemonic != Mnemonic::Jmp) break;
        if (insn.num_operands != 1) break;
        if (insn.operands[0].kind != Operand::Kind::Relative) break;
        const addr_t hop_target = insn.operands[0].rel.target;
        if (hop_target == target) break;  // self-loop
        target = hop_target;
    }

    auto entry_bytes = b.bytes_at(target);
    if (entry_bytes.empty()) return max_arity;

    std::array<bool, 6> written{};
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
    return infer_arity(b, target, abi_for(b.format(), b.arch()));
}

}  // namespace ember
