#include "support/ir_interpreter.hpp"
#include "support/ir_semantics_compare.hpp"

#include <array>
#include <bit>
#include <charconv>
#include <cstdio>
#include <format>
#include <initializer_list>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <vector>


namespace {
using namespace spelunk;
using namespace spelunk::test;

constexpr std::array types{IrType::I1, IrType::I8, IrType::I16, IrType::I32, IrType::I64};
constexpr std::array binary_ops{
    IrOp::Add, IrOp::Sub, IrOp::Mul, IrOp::And, IrOp::Or, IrOp::Xor,
    IrOp::Shl, IrOp::Lshr, IrOp::Ashr,
    IrOp::CmpEq, IrOp::CmpNe, IrOp::CmpUlt, IrOp::CmpUle, IrOp::CmpUgt,
    IrOp::CmpUge, IrOp::CmpSlt, IrOp::CmpSle, IrOp::CmpSgt, IrOp::CmpSge};
CleanupVerifier verifier;

bool check(bool condition, std::string_view message) {
    if (!condition) std::fprintf(stderr, "FAIL: %.*s\n",
                                static_cast<int>(message.size()), message.data());
    return condition;
}

bool is_compare(IrOp op) { return op >= IrOp::CmpEq && op <= IrOp::CmpSge; }

IrValue imm(u64 bits, IrType type) {
    const auto width = type_bits(type);
    if (width < 64) {
        const u64 mask = (u64{1} << width) - 1;
        bits &= mask;
        if (bits & (u64{1} << (width - 1))) bits |= ~mask;
    }
    return IrValue::make_imm(std::bit_cast<i64>(bits), type);
}

struct Program {
    IrFunction fn;
    explicit Program(std::string name) {
        fn.name = std::move(name);
        fn.start = 0x1000;
        fn.end = 0x2000;
        IrBlock block;
        block.start = fn.start;
        block.end = fn.end;
        block.kind = BlockKind::Return;
        fn.block_at[block.start] = 0;
        fn.blocks.push_back(std::move(block));
    }
    void append(IrOp op, IrValue dst, std::initializer_list<IrValue> srcs) {
        IrInst inst;
        inst.op = op;
        inst.dst = dst;
        inst.src_count = static_cast<u8>(srcs.size());
        std::size_t index = 0;
        for (const auto& src : srcs) inst.srcs[index++] = src;
        fn.blocks[0].insts.push_back(std::move(inst));
    }
    IrValue value(IrOp op, IrType type, std::initializer_list<IrValue> srcs) {
        auto dst = IrValue::make_temp(fn.next_temp_id++, type);
        append(op, dst, srcs);
        return dst;
    }
    void store(IrValue address, IrValue value) { append(IrOp::Store, {}, {address, value}); }
    void ret(IrValue value) { append(IrOp::Return, {}, {value}); }
};

// SplitMix64 gives reproducible programs without a library-dependent random
// distribution. Its initial seed is printed on failure and accepted by --seed.
struct Random {
    u64 state;
    u64 next() {
        u64 value = (state += 0x9e3779b97f4a7c15ULL);
        value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9ULL;
        value = (value ^ (value >> 27)) * 0x94d049bb133111ebULL;
        return value ^ (value >> 31);
    }
    std::size_t index(std::size_t count) { return static_cast<std::size_t>(next() % count); }
};

MachineInput input_for(u64 seed, u64 a = 0, u64 b = 0, u64 p = 16, u64 q = 16) {
    MachineInput input;
    for (auto [reg, bits] : std::array{
            std::pair{Reg::Rdi, a}, std::pair{Reg::Rsi, b},
            std::pair{Reg::Rdx, p}, std::pair{Reg::Rcx, q}}) {
        input.values.emplace(*ssa_key(IrValue::make_reg(reg, IrType::I64)), bits);
    }
    Random random{seed};
    input.memory.resize(96);
    for (auto& byte : input.memory) byte = static_cast<u8>(random.next());
    return input;
}

bool oracle_checks() {
    const auto expect = [](IrOp op, IrType type, std::initializer_list<IrValue> args, u64 expected) {
        Program p("oracle");
        p.ret(p.value(op, type, args));
        const auto result = interpret(p.fn, {});
        return check(result && result->returned == expected, std::format("oracle {}", op_name(op)));
    };
    if (!expect(IrOp::Add, IrType::I8, {imm(255, IrType::I8), imm(2, IrType::I8)}, 1) ||
        !expect(IrOp::Mul, IrType::I64, {imm(~u64{0}, IrType::I64), imm(2, IrType::I64)}, ~u64{1}) ||
        !expect(IrOp::Neg, IrType::I64, {imm(u64{1} << 63, IrType::I64)}, u64{1} << 63) ||
        !expect(IrOp::SExt, IrType::I64, {imm(128, IrType::I8)}, 0xffffffffffffff80ULL) ||
        !expect(IrOp::ZExt, IrType::I64, {imm(128, IrType::I8)}, 128) ||
        !expect(IrOp::Trunc, IrType::I8, {imm(0x1234, IrType::I64)}, 0x34) ||
        !expect(IrOp::Ashr, IrType::I8, {imm(128, IrType::I8), imm(7, IrType::I8)}, 255) ||
        !expect(IrOp::Ashr, IrType::I8, {imm(128, IrType::I8), imm(8, IrType::I8)}, 255) ||
        !expect(IrOp::Lshr, IrType::I8, {imm(128, IrType::I8), imm(7, IrType::I8)}, 1) ||
        !expect(IrOp::Shl, IrType::I32, {imm(7, IrType::I32), imm(32, IrType::I32)}, 7) ||
        !expect(IrOp::CmpSlt, IrType::I1, {imm(128, IrType::I8), imm(0, IrType::I8)}, 1) ||
        !expect(IrOp::CmpUlt, IrType::I1, {imm(128, IrType::I8), imm(0, IrType::I8)}, 0)) return false;

    Program memory("oracle-memory");
    memory.store(imm(8, IrType::I64), imm(0x12345678, IrType::I32));
    memory.store(imm(9, IrType::I64), imm(0xabcd, IrType::I16));
    memory.ret(memory.value(IrOp::Load, IrType::I32, {imm(8, IrType::I64)}));
    const auto result = interpret(memory.fn, input_for(1));
    if (!check(result && result->returned == 0x12abcd78 &&
               result->memory[8] == 0x78 && result->memory[9] == 0xcd &&
               result->memory[10] == 0xab && result->memory[11] == 0x12,
               "little-endian overlapping stores")) return false;
    auto changed = memory.fn;
    changed.blocks[0].insts[1].srcs[1] = imm(0, IrType::I16);
    if (!check(interpret(changed, input_for(1)) != result, "oracle detects changed memory semantics")) return false;
    auto memory_only = memory.fn;
    memory_only.blocks[0].insts.back().srcs[0] = imm(0, IrType::I32);
    changed.blocks[0].insts.back().srcs[0] = imm(0, IrType::I32);
    const auto left = interpret(memory_only, input_for(1));
    const auto right = interpret(changed, input_for(1));
    if (!check(left && right && left->returned == right->returned && *left != *right,
               "equal return values cannot hide changed memory")) return false;

    Program invalid("unsupported");
    invalid.ret(invalid.value(IrOp::Div, IrType::I32, {imm(8, IrType::I32), imm(2, IrType::I32)}));
    if (!check(!interpret(invalid.fn, {}), "ambiguous division is rejected")) return false;
    invalid.fn.blocks[0].insts[0].op = IrOp::Call;
    if (!check(!interpret(invalid.fn, {}), "calls are rejected")) return false;
    Program missing("undefined");
    missing.ret(IrValue::make_temp(55, IrType::I32));
    if (!check(!interpret(missing.fn, {}), "undefined values are rejected")) return false;
    Program bounds("out-of-bounds");
    bounds.ret(bounds.value(IrOp::Load, IrType::I64, {imm(~u64{0}, IrType::I64)}));
    if (!check(!interpret(bounds.fn, input_for(1)), "out-of-bounds loads are rejected")) return false;
    Program wide("unsupported-width");
    wide.ret(IrValue::make_imm(0, IrType::I128));
    if (!check(!interpret(wide.fn, {}), "unsupported widths are rejected")) return false;
    memory.fn.blocks.push_back(memory.fn.blocks[0]);
    return check(!interpret(memory.fn, input_for(1)), "duplicate block addresses are rejected");
}

bool constant_cases() {
    for (IrType type : types) {
        const unsigned bits = type_bits(type);
        const u64 high = u64{1} << (bits - 1);
        const std::array<u64, 9> values{0, 1, 2, high - 1, high, high + 1, ~u64{0}, 31, 64};
        for (IrOp op : binary_ops) {
            for (u64 a : values) for (u64 b : values) {
                Program p(std::format("constant-{}-{}-{:x}-{:x}", type_name(type), op_name(op), a, b));
                p.ret(p.value(op, is_compare(op) ? IrType::I1 : type, {imm(a, type), imm(b, type)}));
                if (!verifier.verify(p.fn, {input_for(1)})) return false;
            }
        }
        for (IrOp op : {IrOp::Neg, IrOp::Not}) for (u64 a : values) {
            Program p(std::format("unary-{}-{}-{:x}", type_name(type), op_name(op), a));
            p.ret(p.value(op, type, {imm(a, type)}));
            if (!verifier.verify(p.fn, {input_for(1)})) return false;
        }
    }
    return true;
}

bool cast_cases() {
    for (IrType source : types) for (IrType destination : types) {
        const auto x = IrValue::make_reg(Reg::Rdi, source);
        for (IrOp extension : {IrOp::ZExt, IrOp::SExt}) {
            Program p(std::format("cast-{}-{}-{}", type_name(source),
                                  type_name(destination), op_name(extension)));
            const bool widens = type_bits(destination) >= type_bits(source);
            const auto cast = p.value(widens ? extension : IrOp::Trunc, destination, {x});
            p.ret(p.value(widens ? IrOp::Trunc : extension, source, {cast}));
            const u64 high = u64{1} << (type_bits(source) - 1);
            std::vector<MachineInput> inputs;
            for (u64 bits : {u64{0}, u64{1}, high - 1, high, high + 1, ~u64{0}}) {
                inputs.push_back(input_for(1, bits));
            }
            if (!verifier.verify(p.fn, inputs)) return false;
        }
    }
    return true;
}

bool partial_register_cases() {
    for (IrType narrow : {IrType::I1, IrType::I8, IrType::I16, IrType::I32}) {
        const u64 low_mask = (u64{1} << type_bits(narrow)) - 1;
        {
            Program p("dynamic-partial-register-xor");
            const auto old = IrValue::make_reg(Reg::Rdi, IrType::I64);
            const auto data = IrValue::make_reg(Reg::Rsi, IrType::I64);
            const auto high = p.value(IrOp::And, IrType::I64, {old, imm(~low_mask, IrType::I64)});
            const auto low = p.value(IrOp::Trunc, narrow, {data});
            const auto wide = p.value(IrOp::ZExt, IrType::I64, {low});
            const auto merged = p.value(IrOp::Or, IrType::I64, {high, wide});
            const auto mixed = p.value(IrOp::Xor, IrType::I64, {merged, old});
            p.ret(p.value(IrOp::Trunc, narrow, {mixed}));
            std::vector<MachineInput> inputs;
            for (u64 a : {u64{0}, u64{1}, low_mask, ~u64{0}, u64{0x123456789abcdef0}})
                for (u64 b : {u64{0}, u64{1}, low_mask, ~u64{0}})
                    inputs.push_back(input_for(1, a, b));
            if (!verifier.verify(p.fn, inputs)) return false;
        }
        for (u64 retained : {u64{0}, u64{1}}) {
            for (bool reverse : {false, true}) {
                for (u64 literal : {u64{0}, u64{100}, low_mask, ~u64{0}}) {
                    Program p("partial-register-low-bits");
                    const auto input = IrValue::make_reg(Reg::Rdi, IrType::I64);
                    const auto mask = imm(~low_mask | retained, IrType::I64);
                    const auto high = p.value(IrOp::And, IrType::I64,
                        reverse ? std::initializer_list<IrValue>{mask, input}
                                : std::initializer_list<IrValue>{input, mask});
                    const auto bits = imm(literal, IrType::I64);
                    const auto merged = p.value(IrOp::Or, IrType::I64,
                        reverse ? std::initializer_list<IrValue>{bits, high}
                                : std::initializer_list<IrValue>{high, bits});
                    p.ret(p.value(IrOp::Trunc, narrow, {merged}));
                    std::vector<MachineInput> inputs;
                    for (u64 value : {u64{0}, u64{1}, low_mask, ~u64{0},
                                      u64{0x123456789abcdef0}})
                        inputs.push_back(input_for(1, value));
                    if (!verifier.verify(p.fn, inputs)) return false;
                }
            }
        }
    }
    return true;
}

bool memory_cases() {
    const auto p = IrValue::make_reg(Reg::Rdx, IrType::I64);
    const auto q = IrValue::make_reg(Reg::Rcx, IrType::I64);
    for (IrType first : {IrType::I8, IrType::I16, IrType::I32, IrType::I64}) {
        for (IrType second : {IrType::I8, IrType::I16, IrType::I32, IrType::I64}) {
            Program program(std::format("overlap-{}-{}", type_name(first), type_name(second)));
            program.store(p, imm(0x123456789abcdef0ULL, first));
            const auto snapshot = program.value(IrOp::Load, first, {p});
            program.store(q, imm(0xfedcba9876543210ULL, second));
            const auto current = program.value(IrOp::Load, first, {p});
            program.store(imm(72, IrType::I64), snapshot);
            program.ret(current);
            std::vector<MachineInput> inputs;
            // Alias through different SSA keys, partial overlap in either
            // direction, exactly adjacent storage, and disjoint storage.
            for (u64 address : {u64{16}, u64{15}, u64{17},
                               u64{16} + type_bits(first) / 8, u64{40}}) {
                inputs.push_back(input_for(1, 0, 0, 16, address));
            }
            if (!verifier.verify(program.fn, inputs)) return false;
        }
    }
    return true;
}

bool generated_case(u64 seed) {
    Random random{seed};
    const IrType type = types[1 + random.index(types.size() - 1)];
    const IrValue x = IrValue::make_reg(Reg::Rdi, type);
    const IrValue y = IrValue::make_reg(Reg::Rsi, type);
    const IrValue p = IrValue::make_reg(Reg::Rdx, IrType::I64);
    const IrValue q = IrValue::make_reg(Reg::Rcx, IrType::I64);
    Program program(std::format("seed-{}", seed));
    std::vector<IrValue> pool{x, y, imm(0, type), imm(1, type), imm(~u64{0}, type)};
    for (unsigned step = 0; step < 24; ++step) {
        const IrValue a = pool[random.index(pool.size())];
        const IrValue b = pool[random.index(pool.size())];
        IrValue result;
        switch (random.index(7)) {
            case 0: result = program.value(IrOp::Assign, type, {a}); break;
            case 1: {
                const IrType narrow = types[random.index(types.size())];
                if (type_bits(narrow) > type_bits(type)) {
                    const auto extended = program.value(IrOp::ZExt, narrow, {a});
                    result = program.value(IrOp::Trunc, type, {extended});
                } else {
                    const auto truncated = program.value(IrOp::Trunc, narrow, {a});
                    result = program.value(random.next() & 1 ? IrOp::ZExt : IrOp::SExt, type, {truncated});
                }
                break;
            }
            case 2:
                program.store(p, a);
                program.store(q, b);
                result = program.value(IrOp::Load, type, {p});
                break;
            case 3:
                result = program.value(random.next() & 1 ? IrOp::Neg : IrOp::Not, type, {a});
                break;
            default: {
                const IrOp op = binary_ops[random.index(binary_ops.size())];
                result = program.value(op, is_compare(op) ? IrType::I1 : type, {a, b});
                if (is_compare(op)) result = program.value(IrOp::Select, type, {result, a, b});
                break;
            }
        }
        pool.push_back(result);
    }
    // Keep the final expression observable even when earlier values are dead.
    program.store(imm(72, IrType::I64), pool.back());
    program.ret(pool.back());
    std::vector<MachineInput> inputs;
    for (u64 i = 0; i < 8; ++i) {
        const u64 a = i < 2 ? i : random.next();
        const u64 b = i == 0 ? ~u64{0} : random.next();
        const u64 q_address = std::array<u64, 4>{16, 17, 16 + type_bits(type) / 8, 40}[i % 4];
        inputs.push_back(input_for(seed ^ i, a, b, 16, q_address));
    }
    if (verifier.verify(program.fn, inputs)) return true;
    std::fprintf(stderr, "Replay: spelunk_ir_semantics_test --seed %s\n", std::to_string(seed).c_str());
    return false;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc == 3 && std::string_view(argv[1]) == "--seed") {
        u64 seed = 0;
        const std::string_view value(argv[2]);
        const auto parsed = std::from_chars(value.data(), value.data() + value.size(), seed);
        if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size()) return 2;
        return generated_case(seed) ? 0 : 1;
    }
    if (argc != 1) {
        std::fprintf(stderr, "usage: spelunk_ir_semantics_test [--seed N]\n");
        return 2;
    }
    if (!oracle_checks() || !constant_cases() || !cast_cases() ||
        !partial_register_cases() || !memory_cases()) return 1;
    for (u64 seed = 1; seed <= 256; ++seed) if (!generated_case(seed)) return 1;
    std::printf("Verified %zu cleanup programs across %zu executions\n", verifier.programs, verifier.executions);
    return 0;
}
