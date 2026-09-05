#include "ir_interpreter.hpp"

#include <array>
#include <format>
#include <limits>
#include <stdexcept>
#include <utility>

namespace ember::test {
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
    explicit Machine(const MachineInput& input) : values_(input.values) {
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
        if (!values_.emplace(*key, bits & mask(width(value.type))).second) {
            throw std::runtime_error("SSA value defined twice");
        }
    }

    void execute(const IrInst& inst) {
        const auto arity = [&](u8 expected) {
            if (inst.src_count != expected) {
                throw std::runtime_error("wrong operand count");
            }
        };
        if (inst.segment != Reg::None) throw std::runtime_error("segmented memory");
        switch (inst.op) {
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
                break;
            default: throw std::runtime_error("unsupported opcode");
        }
        arity(2);
        const auto bits = width(inst.srcs[0].type);
        const bool comparison = inst.op >= IrOp::CmpEq && inst.op <= IrOp::CmpSge;
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
};

}  // namespace

std::expected<Execution, std::string>
interpret(const IrFunction& function, const MachineInput& input) {
    if (function.blocks.size() != 1 || !function.blocks[0].successors.empty()) {
        return std::unexpected("interpreter requires one straight-line block");
    }
    Machine machine(input);
    const auto& instructions = function.blocks[0].insts;
    std::size_t index = 0;
    try {
        for (; index < instructions.size(); ++index) {
            const auto& inst = instructions[index];
            machine.execute(inst);
            if (inst.op == IrOp::Return) {
                if (index + 1 != instructions.size()) {
                    throw std::runtime_error("instructions after return");
                }
                return std::move(machine.result);
            }
        }
        return std::unexpected("block has no return");
    } catch (const std::runtime_error& error) {
        return std::unexpected(std::format("instruction {}: {}", index, error.what()));
    }
}

}  // namespace ember::test
