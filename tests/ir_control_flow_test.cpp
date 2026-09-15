#include "support/ir_interpreter.hpp"
#include "support/ir_semantics_compare.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdio>
#include <format>
#include <initializer_list>
#include <string>
#include <string_view>
#include <utility>

namespace {
using namespace spelunk;
using namespace spelunk::test;

constexpr addr_t entry = 0x1000;
constexpr addr_t yes = 0x1100;
constexpr addr_t no = 0x1200;
constexpr addr_t merge = 0x1300;
constexpr addr_t body = 0x1400;
constexpr addr_t exit_block = 0x1500;
CleanupVerifier verifier;

bool check(bool condition, std::string_view message) {
    if (!condition) std::fprintf(stderr, "FAIL: %.*s\n",
                                static_cast<int>(message.size()), message.data());
    return condition;
}

IrValue imm(i64 value, IrType type = IrType::I32) { return IrValue::make_imm(value, type); }
IrValue arg(Reg reg, IrType type = IrType::I32) { return IrValue::make_reg(reg, type); }

struct Program {
    IrFunction fn;
    addr_t current = entry;

    explicit Program(std::string name) {
        fn.name = std::move(name);
        fn.start = entry;
    }
    void block(addr_t address) {
        current = address;
        IrBlock next;
        next.start = address;
        next.end = address + 0x40;
        fn.end = std::max(fn.end, next.end);
        fn.block_at[address] = fn.blocks.size();
        fn.blocks.push_back(std::move(next));
    }
    IrInst& append(IrOp op, IrValue dst, std::initializer_list<IrValue> sources) {
        IrInst inst;
        inst.op = op;
        inst.dst = dst;
        inst.src_count = static_cast<u8>(sources.size());
        std::copy(sources.begin(), sources.end(), inst.srcs.begin());
        fn.blocks[fn.block_at.at(current)].insts.push_back(std::move(inst));
        return fn.blocks[fn.block_at.at(current)].insts.back();
    }
    IrValue temp(IrType type = IrType::I32) { return IrValue::make_temp(fn.next_temp_id++, type); }
    IrValue value(IrOp op, std::initializer_list<IrValue> sources, IrType type = IrType::I32) {
        const auto result = temp(type);
        append(op, result, sources);
        return result;
    }
    void phi(IrValue dst, std::initializer_list<std::pair<addr_t, IrValue>> incoming) {
        auto& inst = append(IrOp::Phi, dst, {});
        for (const auto& [pred, value] : incoming) {
            inst.phi_preds.push_back(pred);
            inst.phi_operands.push_back(value);
        }
    }
    void branch(addr_t target) {
        append(IrOp::Branch, {}, {}).target1 = target;
        auto& b = fn.blocks[fn.block_at.at(current)];
        b.kind = BlockKind::Unconditional;
        b.successors = {target};
    }
    void branch(IrValue condition, addr_t taken, addr_t fallthrough) {
        auto& inst = append(IrOp::CondBranch, {}, {condition});
        inst.target1 = taken;
        inst.target2 = fallthrough;
        auto& b = fn.blocks[fn.block_at.at(current)];
        b.kind = BlockKind::Conditional;
        b.successors = {taken, fallthrough};
    }
    void store(IrValue address, IrValue value) { append(IrOp::Store, {}, {address, value}); }
    void ret(IrValue value) {
        append(IrOp::Return, {}, {value});
        fn.blocks[fn.block_at.at(current)].kind = BlockKind::Return;
    }
    IrFunction finish() {
        for (const auto& b : fn.blocks) {
            for (addr_t successor : b.successors) {
                auto& predecessors = fn.blocks[fn.block_at.at(successor)].predecessors;
                if (std::find(predecessors.begin(), predecessors.end(), b.start) == predecessors.end()) {
                    predecessors.push_back(b.start);
                }
            }
        }
        return std::move(fn);
    }
};

MachineInput input(u64 x = 0, u64 y = 0, u64 z = 0) {
    MachineInput state;
    state.memory.resize(64, 0xa5);
    state.values[*ssa_key(arg(Reg::Rdi))] = x;
    state.values[*ssa_key(arg(Reg::Rsi))] = y;
    state.values[*ssa_key(arg(Reg::Rdx))] = z;
    return state;
}

bool expected(const IrFunction& fn, const MachineInput& state, u64 result) {
    const auto actual = interpret(fn, state);
    if (actual && actual->returned == result) return true;
    std::fprintf(stderr, "FAIL: oracle %s expected %s, got %s\n", fn.name.c_str(),
                 std::format("{:#x}", result).c_str(),
                 actual ? std::format("{:#x}", actual->returned.value_or(0)).c_str() : actual.error().c_str());
    return false;
}

IrFunction diamond(i64 amount, bool trivial = false, bool nested = false) {
    Program p("diamond");
    p.block(entry);
    const auto condition = p.value(IrOp::CmpNe, {arg(Reg::Rdi), imm(0)}, IrType::I1);
    p.branch(condition, yes, no);
    p.block(yes);
    const auto left = p.value(IrOp::Add, {arg(Reg::Rsi), imm(amount)});
    p.store(imm(8, IrType::I64), left);
    p.branch(merge);
    p.block(no);
    const auto right = p.value(IrOp::Sub, {arg(Reg::Rsi), imm(amount)});
    p.store(imm(8, IrType::I64), right);
    p.branch(merge);
    p.block(merge);
    const auto joined = p.temp();
    // Deliberately reverse the incoming edge order.
    p.phi(joined, {{no, trivial ? arg(Reg::Rsi) : right},
                   {yes, trivial ? arg(Reg::Rsi) : left}});
    if (nested) {
        const auto nonzero = p.value(IrOp::CmpNe, {arg(Reg::Rdx), imm(0)}, IrType::I1);
        p.branch(nonzero, body, exit_block);
        p.block(body);
        p.ret(p.value(IrOp::Xor, {joined, imm(0x55)}));
        p.block(exit_block);
    }
    p.ret(joined);
    return p.finish();
}

IrFunction early_return() {
    Program p("early-return");
    p.block(entry);
    p.branch(p.value(IrOp::CmpEq, {arg(Reg::Rdi), imm(0)}, IrType::I1), yes, no);
    p.block(yes);
    p.ret(imm(7));
    p.block(no);
    p.store(imm(12, IrType::I64), arg(Reg::Rsi));
    p.ret(p.value(IrOp::Add, {arg(Reg::Rsi), imm(3)}));
    return p.finish();
}

IrFunction counted_loop(i64 increment, bool swap = false) {
    Program p(swap ? "loop-phi-swap" : "counted-loop");
    const auto index = p.temp();
    const auto accumulator = p.temp();
    const auto other = p.temp();
    const auto next_index = p.temp();
    const auto next_sum = p.temp();
    p.block(entry);
    p.branch(merge);
    p.block(merge);
    p.phi(index, {{body, next_index}, {entry, imm(0)}});
    p.phi(accumulator, {{entry, arg(Reg::Rsi)}, {body, swap ? other : next_sum}});
    if (swap) p.phi(other, {{body, accumulator}, {entry, arg(Reg::Rdx)}});
    p.branch(p.value(IrOp::CmpUlt, {index, arg(Reg::Rdi)}, IrType::I1), body, exit_block);
    p.block(body);
    p.append(IrOp::Add, next_index, {index, imm(1)});
    if (!swap) p.append(IrOp::Add, next_sum, {accumulator, imm(increment)});
    p.store(imm(16, IrType::I64), accumulator);
    p.branch(merge);
    p.block(exit_block);
    p.ret(accumulator);
    return p.finish();
}

IrFunction invariant_loop() {
    Program p("loop-self-phi");
    const auto index = p.temp();
    const auto invariant = p.temp();
    const auto next = p.temp();
    p.block(entry);
    p.branch(merge);
    p.block(merge);
    p.phi(index, {{entry, imm(0)}, {body, next}});
    p.phi(invariant, {{body, invariant}, {entry, arg(Reg::Rsi)}});
    p.branch(p.value(IrOp::CmpUlt, {index, arg(Reg::Rdi)}, IrType::I1), body, exit_block);
    p.block(body);
    p.append(IrOp::Add, next, {index, imm(1)});
    p.store(imm(8, IrType::I64), invariant);
    p.branch(merge);
    p.block(exit_block);
    p.ret(invariant);
    return p.finish();
}

bool oracle_cases() {
    const auto d = diamond(5);
    if (!expected(d, input(1, 10), 15) || !expected(d, input(0, 10), 5)) return false;
    // Untaken arms contain SSA operands with no dynamic value; only the
    // selected edge may be read. Storage order must not choose the entry.
    auto reordered = d;
    std::reverse(reordered.blocks.begin(), reordered.blocks.end());
    for (std::size_t i = 0; i < reordered.blocks.size(); ++i) {
        reordered.block_at[reordered.blocks[i].start] = i;
    }
    if (!expected(reordered, input(1, 10), 15)) return false;
    const auto early = early_return();
    const auto result = interpret(early, input(0, 99));
    if (!check(result && result->returned == 7 && result->memory == input().memory,
               "early return skips later stores")) return false;
    if (!expected(early, input(1, 99), 102)) return false;
    auto poisoned = early;
    poisoned.blocks[poisoned.block_at.at(no)].insts[0].srcs[0] = imm(1000, IrType::I64);
    if (!expected(poisoned, input(0, 99), 7) ||
        !check(!interpret(poisoned, input(1, 99)),
               "out-of-bounds access fails only on the executed path")) return false;
    const auto loop = counted_loop(3);
    for (u64 count : {u64{0}, u64{1}, u64{2}, u64{7}}) {
        if (!expected(loop, input(count, 10), 10 + 3 * count)) return false;
        if (!expected(counted_loop(0, true), input(count, 11, 29), count % 2 ? 29 : 11)) return false;
        if (!expected(invariant_loop(), input(count, 37), 37)) return false;
    }
    // Swapping incoming operands simulates a broken edge mapping.
    auto changed = d;
    auto& phi = changed.blocks[changed.block_at.at(merge)].insts[0];
    std::swap(phi.phi_operands[0], phi.phi_operands[1]);
    if (!check(interpret(changed, input(1, 10)) != interpret(d, input(1, 10)),
               "oracle detects wrong phi input")) return false;
    return true;
}

bool rejected(const IrFunction& fn, std::string_view reason, std::size_t limit = 10000) {
    const auto result = interpret(fn, input(3, 11, 29), limit);
    return check(!result && result.error().find(reason) != std::string::npos, reason);
}

bool malformed_cases() {
    const auto d = diamond(5);
    auto bad = d;
    bad.blocks[0].insts.back().target1 = 0xdead;
    bad.blocks[0].successors[0] = 0xdead;
    if (!rejected(bad, "branch target is missing")) return false;
    bad = d;
    bad.blocks[bad.block_at.at(merge)].insts[0].phi_preds.pop_back();
    if (!rejected(bad, "invalid phi operand list")) return false;
    bad = d;
    bad.blocks[bad.block_at.at(merge)].insts[0].phi_preds[0] = yes;
    if (!rejected(bad, "phi predecessors")) return false;
    bad = d;
    bad.blocks[0].insts.back().srcs[0].type = IrType::I32;
    if (!rejected(bad, "branch condition is not i1")) return false;
    bad = d;
    bad.blocks[bad.block_at.at(merge)].insts.back().srcs[0] =
        bad.blocks[bad.block_at.at(yes)].insts[0].dst;
    if (!rejected(bad, "does not dominate")) return false;
    bad = d;
    bad.blocks[bad.block_at.at(no)].insts[0].dst = bad.blocks[bad.block_at.at(yes)].insts[0].dst;
    if (!rejected(bad, "SSA value defined twice")) return false;
    bad = d;
    bad.blocks[bad.block_at.at(merge)].predecessors.clear();
    if (!rejected(bad, "inconsistent predecessor metadata")) return false;
    bad = d;
    bad.blocks[bad.block_at.at(merge)].insts[0].phi_operands[0].type = IrType::I64;
    if (!rejected(bad, "phi type mismatch")) return false;
    bad = d;
    bad.blocks[0].insts.back().srcs[0] = IrValue::make_temp(900, IrType::I1);
    if (!rejected(bad, "undefined SSA value")) return false;
    bad = d;
    bad.blocks[0].insts.back().op = IrOp::BranchIndirect;
    if (!rejected(bad, "unsupported opcode")) return false;
    if (!rejected(counted_loop(3), "step limit", 0) ||
        !rejected(counted_loop(3), "step limit", 3)) return false;
    Program infinite("infinite-loop");
    infinite.block(entry);
    infinite.branch(merge);
    infinite.block(merge);
    infinite.branch(merge);
    return rejected(infinite.finish(), "step limit", 25);
}

bool fixed_cases() {
    std::vector<MachineInput> states;
    for (u64 x : {u64{0}, u64{1}}) for (u64 y : {u64{0}, u64{1}, u64{0x80000000}, u64{0xffffffff}}) {
        for (u64 z : {u64{0}, u64{1}}) states.push_back(input(x, y, z));
    }
    for (bool trivial : {false, true}) for (bool nested : {false, true}) {
        if (!verifier.verify(diamond(5, trivial, nested), states)) return false;
    }
    if (!verifier.verify(early_return(), states)) return false;
    states.clear();
    for (u64 count : {u64{0}, u64{1}, u64{2}, u64{7}, u64{16}}) {
        states.push_back(input(count, 0xfffffff0, 29));
    }
    return verifier.verify(counted_loop(3), states) &&
           verifier.verify(counted_loop(0, true), states) &&
           verifier.verify(invariant_loop(), states);
}

bool seeded_case(u64 seed) {
    // A fixed integer mixer keeps program and input selection portable.
    u64 state = seed;
    const auto next = [&]() {
        state += 0x9e3779b97f4a7c15ULL;
        u64 x = state;
        x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
        x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
        return x ^ (x >> 31);
    };
    const auto amount = static_cast<i64>(next() % 257);
    IrFunction fn;
    switch (next() % 4) {
        case 0: fn = diamond(amount, next() % 2 != 0, true); break;
        case 1: fn = counted_loop(amount); break;
        case 2: fn = counted_loop(0, true); break;
        default: fn = invariant_loop(); break;
    }
    fn.name += std::format("-seed-{}", seed);
    std::vector<MachineInput> states;
    for (u64 n : {u64{0}, u64{1}, u64{2}, u64{3}, u64{7}, u64{16}}) {
        const u64 y = next() & 0xffffffff;
        const u64 z = next() & 0xffffffff;
        states.push_back(input(n, y, z));
    }
    if (verifier.verify(fn, states)) return true;
    std::fprintf(stderr, "Replay: spelunk_ir_control_flow_test --seed %s\n", std::to_string(seed).c_str());
    return false;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc == 3 && std::string_view(argv[1]) == "--seed") {
        u64 seed = 0;
        const std::string_view value(argv[2]);
        const auto parsed = std::from_chars(value.data(), value.data() + value.size(), seed);
        if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size()) return 2;
        return seeded_case(seed) ? 0 : 1;
    }
    if (argc != 1) return 2;
    if (!oracle_cases() || !malformed_cases() || !fixed_cases()) return 1;
    for (u64 seed = 1; seed <= 128; ++seed) if (!seeded_case(seed)) return 1;
    std::printf("Verified %zu control-flow programs across %zu executions\n",
                verifier.programs, verifier.executions);
    return 0;
}
