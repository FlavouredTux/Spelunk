#include "ir_interpreter.hpp"
#include "ir_interpreter_cfg.hpp"

#include <format>
#include <array>
#include <limits>
#include <stdexcept>
#include <utility>

namespace spelunk::test {
namespace {

unsigned width(IrType type) {
    switch (type) {
        case IrType::I1: return 1;
        case IrType::I8: return 8;
        case IrType::I16: return 16;
        case IrType::I32: return 32;
        case IrType::I64: return 64;
        default: throw std::runtime_error("unsupported value type");
    }
}

u64 mask(unsigned bits) {
    return bits == 64 ? std::numeric_limits<u64>::max() : (u64{1} << bits) - 1;
}

class Machine {
public:
    explicit Machine(const MachineInput& input) : values_(input.values), input_(input) {
        result.memory = input.memory;
    }

    u64 read(const IrValue& value) const {
        const auto bits = width(value.type);
        if (value.kind == IrValueKind::Imm) {
            return static_cast<u64>(value.imm) & mask(bits);
        }
        const auto key = ssa_key(value);
        if (!key) throw std::runtime_error("operand has no value");
        const auto found = values_.find(*key);
        if (found == values_.end()) throw std::runtime_error("undefined SSA value");
        return found->second & mask(bits);
    }

    void write(const IrValue& value, u64 bits) {
        if (value.kind == IrValueKind::Imm) {
            throw std::runtime_error("immediate destination");
        }
        const auto key = ssa_key(value);
        if (!key) throw std::runtime_error("missing destination");
        // Static uniqueness is checked before execution. A loop revisits
        // the same definition and produces its next dynamic value.
        values_.insert_or_assign(*key, bits & mask(width(value.type)));
    }

    void execute(const IrInst& inst) {
        const auto arity = [&](u8 expected) {
            if (inst.src_count != expected) {
                throw std::runtime_error("wrong operand count");
            }
        };
        if (inst.segment != Reg::None) throw std::runtime_error("segmented memory");
        switch (inst.op) {
            case IrOp::Call: {
                arity(0);
                if (!input_.call) throw std::runtime_error("unsupported call");
                std::vector<u64> args;
                for (const auto& value : call_args_) args.push_back(read(value));
                auto returned = input_.call(inst.target1, args, result.memory);
                if (!returned) throw std::runtime_error(returned.error());
                call_return_ = *returned;
                call_args_.clear();
                ++result.call_count;
                return;
            }
            case IrOp::Clobber: {
                arity(0);
                if (!input_.call || !call_return_)
                    throw std::runtime_error("clobber without modeled call");
                if (inst.dst.kind != IrValueKind::Reg)
                    throw std::runtime_error("unsupported clobber destination");
                if (canonical_reg(inst.dst.reg) == Reg::Rax) write(inst.dst, *call_return_);
                else if (auto key = ssa_key(inst.dst); key) values_.erase(*key);
                return;
            }
            case IrOp::Intrinsic: {
                if (input_.call && inst.name.starts_with("call.args.")) {
                    if (inst.src_count > 3) throw std::runtime_error("call pack too large");
                    if (inst.name == "call.args.1") call_args_.clear();
                    for (u8 i = 0; i < inst.src_count; ++i) call_args_.push_back(inst.srcs[i]);
                    return;
                }
                if (!input_.intrinsic || inst.src_count > 3)
                    throw std::runtime_error("unsupported intrinsic");
                std::array<u64, 3> args{};
                for (u8 i = 0; i < inst.src_count; ++i) args[i] = read(inst.srcs[i]);
                auto result_value = input_.intrinsic(inst,
                    std::span<const u64>{args.data(), inst.src_count});
                if (!result_value) throw std::runtime_error(result_value.error());
                write(inst.dst, *result_value);
                return;
            }
            case IrOp::Nop: arity(0); return;
            case IrOp::Return:
                if (inst.src_count > 1) throw std::runtime_error("wrong return arity");
                if (inst.src_count == 1) result.returned = read(inst.srcs[0]);
                return;
            case IrOp::Load: {
                arity(1);
                const auto bytes = memory_width(inst.dst.type);
                const auto address = memory_address(read(inst.srcs[0]), bytes);
                u64 value = 0;
                for (std::size_t i = 0; i < bytes; ++i) {
                    value |= static_cast<u64>(result.memory[address + i]) << (i * 8);
                }
                write(inst.dst, value);
                return;
            }
            case IrOp::Store: {
                arity(2);
                const auto bytes = memory_width(inst.srcs[1].type);
                const auto address = memory_address(read(inst.srcs[0]), bytes);
                const u64 value = read(inst.srcs[1]);
                for (std::size_t i = 0; i < bytes; ++i) {
                    result.memory[address + i] = static_cast<u8>(value >> (i * 8));
                }
                return;
            }
            case IrOp::Select:
                arity(3);
                if (inst.srcs[0].type != IrType::I1 ||
                    inst.srcs[1].type != inst.dst.type ||
                    inst.srcs[2].type != inst.dst.type) {
                    throw std::runtime_error("select type mismatch");
                }
                // Read both SSA operands so a malformed dead arm cannot pass.
                {
                    const u64 yes = read(inst.srcs[1]);
                    const u64 no = read(inst.srcs[2]);
                    write(inst.dst, read(inst.srcs[0]) ? yes : no);
                }
                return;
            default: break;
        }
        switch (inst.op) {
            case IrOp::Assign: case IrOp::Neg: case IrOp::Not:
            case IrOp::ZExt: case IrOp::SExt: case IrOp::Trunc: {
                arity(1);
                const auto source_bits = width(inst.srcs[0].type);
                const auto dest_bits = width(inst.dst.type);
                u64 value = read(inst.srcs[0]);
                if (inst.op == IrOp::ZExt || inst.op == IrOp::SExt) {
                    if (dest_bits < source_bits) throw std::runtime_error("narrow extension");
                } else if (inst.op == IrOp::Trunc) {
                    if (dest_bits > source_bits) throw std::runtime_error("wide truncation");
                } else if (dest_bits != source_bits) {
                    throw std::runtime_error("unary type mismatch");
                }
                if (inst.op == IrOp::Neg) value = u64{0} - value;
                if (inst.op == IrOp::Not) value = ~value;
                if (inst.op == IrOp::SExt &&
                    (value & (u64{1} << (source_bits - 1))) != 0) {
                    value |= ~mask(source_bits);
                }
                write(inst.dst, value);
                return;
            }
            default: break;
        }
        // Reject unsupported instructions before touching their operands.
        switch (inst.op) {
            case IrOp::Add: case IrOp::Sub: case IrOp::Mul:
            case IrOp::And: case IrOp::Or: case IrOp::Xor:
            case IrOp::Shl: case IrOp::Lshr: case IrOp::Ashr:
            case IrOp::CmpEq: case IrOp::CmpNe:
            case IrOp::CmpUlt: case IrOp::CmpUle: case IrOp::CmpUgt: case IrOp::CmpUge:
            case IrOp::CmpSlt: case IrOp::CmpSle: case IrOp::CmpSgt: case IrOp::CmpSge:
            case IrOp::AddCarry: case IrOp::SubBorrow:
            case IrOp::AddOverflow: case IrOp::SubOverflow:
                break;
            default: throw std::runtime_error("unsupported opcode");
        }
        arity(2);
        const auto bits = width(inst.srcs[0].type);
        const bool comparison = (inst.op >= IrOp::CmpEq && inst.op <= IrOp::CmpSge) ||
            inst.op == IrOp::AddCarry || inst.op == IrOp::SubBorrow ||
            inst.op == IrOp::AddOverflow || inst.op == IrOp::SubOverflow;
        const bool shift = inst.op == IrOp::Shl || inst.op == IrOp::Lshr ||
                           inst.op == IrOp::Ashr;
        if ((!shift && inst.srcs[0].type != inst.srcs[1].type) ||
            (comparison ? inst.dst.type != IrType::I1
                        : inst.dst.type != inst.srcs[0].type)) {
            throw std::runtime_error("binary type mismatch");
        }
        const u64 a = read(inst.srcs[0]);
        const u64 b = read(inst.srcs[1]);
        const auto count = static_cast<unsigned>(b & (bits == 64 ? 63u : 31u));
        // Flipping the sign bit orders two's-complement values without signed
        // overflow or implementation-dependent signed right shifts.
        const u64 signed_a = a ^ (u64{1} << (bits - 1));
        const u64 signed_b = b ^ (u64{1} << (bits - 1));
        u64 value = 0;
        switch (inst.op) {
            case IrOp::Add: value = a + b; break;
            case IrOp::Sub: value = a - b; break;
            case IrOp::Mul: value = a * b; break;
            case IrOp::AddCarry: value = b > mask(bits) - a; break;
            case IrOp::SubBorrow: value = a < b; break;
            case IrOp::AddOverflow:
                value = ((~(a ^ b) & (a ^ (a + b))) >> (bits - 1)) & 1;
                break;
            case IrOp::SubOverflow:
                value = (((a ^ b) & (a ^ (a - b))) >> (bits - 1)) & 1;
                break;
            case IrOp::And: value = a & b; break;
            case IrOp::Or: value = a | b; break;
            case IrOp::Xor: value = a ^ b; break;
            case IrOp::Shl: value = a << count; break;
            case IrOp::Lshr: value = a >> count; break;
            case IrOp::Ashr:
                value = a >> count;
                if ((a & (u64{1} << (bits - 1))) != 0 && count != 0) {
                    value |= count >= bits ? mask(bits) : mask(bits) ^ mask(bits - count);
                }
                break;
            case IrOp::CmpEq: value = a == b; break;
            case IrOp::CmpNe: value = a != b; break;
            case IrOp::CmpUlt: value = a < b; break;
            case IrOp::CmpUle: value = a <= b; break;
            case IrOp::CmpUgt: value = a > b; break;
            case IrOp::CmpUge: value = a >= b; break;
            case IrOp::CmpSlt: value = signed_a < signed_b; break;
            case IrOp::CmpSle: value = signed_a <= signed_b; break;
            case IrOp::CmpSgt: value = signed_a > signed_b; break;
            case IrOp::CmpSge: value = signed_a >= signed_b; break;
            default: throw std::runtime_error("unsupported opcode");
        }
        write(inst.dst, value);
    }

    Execution result;

private:
    static std::size_t memory_width(IrType type) {
        const auto bits = width(type);
        if (bits == 1) throw std::runtime_error("sub-byte memory access");
        return bits / 8;
    }

    std::size_t memory_address(u64 address, std::size_t bytes) const {
        if (address > result.memory.size() || bytes > result.memory.size() - address) {
            throw std::runtime_error("memory access out of bounds");
        }
        return static_cast<std::size_t>(address);
    }

    std::map<SsaKey, u64> values_;
    const MachineInput& input_;
    std::vector<IrValue> call_args_;
    std::optional<u64> call_return_;
};

}  // namespace

std::expected<Execution, std::string>
interpret(const IrFunction& function, const MachineInput& input,
          std::size_t step_limit) {
    try {
        validate_interpreter_cfg(function, input);
    } catch (const std::runtime_error& error) {
        return std::unexpected(std::format("invalid CFG/SSA: {}", error.what()));
    }
    addr_t block_address = function.start;
    std::size_t index = 0;
    try {
        Machine machine(input);
        std::optional<addr_t> predecessor;
        std::size_t steps = 0;
        const auto tick = [&] {
            if (steps == step_limit) throw std::runtime_error("execution step limit exceeded");
            ++steps;
        };
        for (;;) {
            const auto& block = function.blocks[function.block_at.at(block_address)];
            index = 0;
            // All phi operands are read before any phi destination is changed.
            // This preserves loop-carried swaps and self-referential phis.
            std::vector<std::pair<IrValue, u64>> incoming;
            for (; index < block.insts.size(); ++index) {
                const auto& inst = block.insts[index];
                if (inst.op == IrOp::Nop) { tick(); continue; }
                if (inst.op != IrOp::Phi) break;
                tick();
                if (!predecessor) throw std::runtime_error("phi without predecessor");
                for (std::size_t pi = 0; pi < inst.phi_preds.size(); ++pi) {
                    if (inst.phi_preds[pi] == *predecessor) {
                        incoming.emplace_back(inst.dst, machine.read(inst.phi_operands[pi]));
                        break;
                    }
                }
            }
            for (const auto& [destination, value] : incoming) machine.write(destination, value);
            for (; index < block.insts.size(); ++index) {
                tick();
                const auto& inst = block.insts[index];
                if (inst.op == IrOp::Branch || inst.op == IrOp::CondBranch) {
                    predecessor = block_address;
                    block_address = inst.op == IrOp::Branch || machine.read(inst.srcs[0])
                        ? inst.target1 : inst.target2;
                    break;
                }
                machine.execute(inst);
                if (inst.op == IrOp::Return) return std::move(machine.result);
            }
        }
    } catch (const std::runtime_error& error) {
        return std::unexpected(std::format("block {:#x}, instruction {}: {}",
                                           block_address, index, error.what()));
    }
}

}  // namespace spelunk::test
