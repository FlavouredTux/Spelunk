#include "support/ir_interpreter.hpp"

#include <array>
#include <bit>
#include <charconv>
#include <cstdio>
#include <iostream>
#include <iomanip>
#include <map>
#include <set>
#include <string>

#include <spelunk/analysis/cfg_builder.hpp>
#include <spelunk/disasm/x64_decoder.hpp>
#include <spelunk/ir/passes.hpp>
#include <spelunk/ir/x64_lifter.hpp>

namespace {
using namespace spelunk;

u64 high_product(u64 a, u64 b) {
    const u64 al = static_cast<u32>(a), ah = a >> 32;
    const u64 bl = static_cast<u32>(b), bh = b >> 32;
    const u64 low = al * bl;
    const u64 cross = ah * bl + (low >> 32);
    const u64 middle = al * bh + static_cast<u32>(cross);
    return ah * bh + (cross >> 32) + (middle >> 32);
}

std::expected<u64, std::string> intrinsic(const IrInst& inst,
                                         std::span<const u64> args) {
    // Entry PF is explicitly seeded to zero for fixtures whose result does
    // not depend on entry flags. Flag-consuming fixtures initialize PF.
    if (inst.name == "parity" && args.empty()) return 0;
    if (args.size() != 2) return std::unexpected("unsupported intrinsic arity");
    if (inst.name == "mulh.u.64" || inst.name == "mulx.high" || inst.name == "mulx.high32") {
        if (inst.dst.type == IrType::I32) return (args[0] * args[1]) >> 32;
        return high_product(args[0], args[1]);
    }
    if (inst.name == "mulh.s.64") {
        return high_product(args[0], args[1]) -
            ((args[0] >> 63) ? args[1] : 0) - ((args[1] >> 63) ? args[0] : 0);
    }
    if (inst.name == "mulx.low" || inst.name == "mulx.low32") return args[0] * args[1];
    const unsigned width = type_bits(inst.dst.type);
    if (inst.name != "rotr" + std::to_string(width) &&
        inst.name != "rotl" + std::to_string(width))
        return std::unexpected("unsupported intrinsic: " + inst.name);
    const u64 mask = width == 64 ? ~u64{0} : (u64{1} << width) - 1;
    u64 value = args[0] & mask;
    const bool right = inst.name.starts_with("rotr");
    // Bit-at-a-time reference, independent of the emitted shift expression.
    for (u64 n = args[1] % width; n != 0; --n) {
        value = right ? (value >> 1) | ((value & 1) << (width - 1))
                      : ((value << 1) | (value >> (width - 1))) & mask;
    }
    return value;
}

struct CallSpec { std::string name; u8 arity; };
using CallSpecs = std::map<addr_t, CallSpec>;

void discard_unused_call_transport(IrFunction& fn) {
    // SSA construction inserts cyclic phis for all caller-clobbered lanes.
    // After projecting the declared arguments, ignore only transport values
    // with no path to an executed operation, not unknown live register reads.
    std::map<SsaKey, const IrInst*> definitions;
    std::set<SsaKey> live;
    for (const auto& block : fn.blocks) for (const auto& inst : block.insts) {
        if (auto key = ssa_key(inst.dst)) definitions[*key] = &inst;
        if (inst.op != IrOp::Phi && inst.op != IrOp::Clobber)
            for (u8 i = 0; i < inst.src_count; ++i)
                if (auto key = ssa_key(inst.srcs[i])) live.insert(*key);
    }
    std::vector<SsaKey> pending(live.begin(), live.end());
    while (!pending.empty()) {
        const auto key = pending.back(); pending.pop_back();
        const auto found = definitions.find(key);
        if (found == definitions.end()) continue;
        const auto use = [&](const IrValue& value) {
            if (auto source = ssa_key(value); source && live.insert(*source).second) pending.push_back(*source);
        };
        for (u8 i = 0; i < found->second->src_count; ++i) use(found->second->srcs[i]);
        for (const auto& value : found->second->phi_operands) use(value);
    }
    for (auto& block : fn.blocks) for (auto& inst : block.insts)
        if (inst.op == IrOp::Phi || inst.op == IrOp::Clobber)
            if (auto key = ssa_key(inst.dst); key && !live.contains(*key)) inst = IrInst{};
}

bool project_integer_calls(IrFunction& fn, const CallSpecs& specs) {
    for (auto& block : fn.blocks) {
        std::vector<IrInst*> packs;
        for (auto& inst : block.insts) {
            if (inst.op == IrOp::Intrinsic && inst.name.starts_with("call.args."))
                packs.push_back(&inst);
            if (inst.op == IrOp::Intrinsic &&
                (inst.name.starts_with("call.fp_args.") ||
                 inst.name == "call.stack_pointer"))
                inst = IrInst{};
            if (inst.op == IrOp::CallIndirect) return false;
            if (inst.op != IrOp::Call) continue;
            auto spec = specs.find(inst.target1);
            if (spec == specs.end()) return false;
            for (auto* pack : packs) {
                if (pack->name == "call.args.1") pack->src_count = spec->second.arity;
                else *pack = IrInst{};
            }
            packs.clear();
        }
    }
    return true;
}

std::expected<u64, std::string> invoke_fixture(
    const CallSpecs& specs, addr_t target, std::span<const u64> args, std::span<u8> memory) {
    auto found = specs.find(target);
    if (found == specs.end() || args.size() != found->second.arity)
        return std::unexpected("unknown call or wrong arity");
    const auto& name = found->second.name;
    if (name == "call_step") return (args[0] * 3) ^ args[1];
    if (name == "call_clobber") return args[0] ^ 0x55;
    if (name == "call_note") return args[0] * 7 + args[1];
    if (name != "call_mutate" || args[0] > memory.size() || memory.size() - args[0] < 8)
        return std::unexpected("invalid call memory access");
    u64 old = 0;
    for (unsigned i = 0; i < 8; ++i) old |= u64{memory[args[0] + i]} << (8 * i);
    const u64 updated = old + args[1];
    for (unsigned i = 0; i < 8; ++i) memory[args[0] + i] = static_cast<u8>(updated >> (8 * i));
    return old ^ args[1];
}
}  // namespace

int main(int argc, char** argv) {
    using namespace spelunk;
    if (argc != 2) return 2;
    auto binary = load_binary(argv[1]);
    if (!binary) return 3;
    CallSpecs call_specs;
    for (const auto& [name, arity] : std::array{
            std::pair{"call_step", u8{2}}, std::pair{"call_mutate", u8{2}},
            std::pair{"call_clobber", u8{1}}, std::pair{"call_note", u8{2}}}) {
        if (const auto* symbol = (*binary)->find_by_name(name))
            call_specs.emplace(symbol->addr, CallSpec{name, arity});
    }
    X64Decoder decoder;
    CfgBuilder builder(**binary, decoder);
    std::map<std::string, std::pair<IrFunction, IrFunction>> functions;
    std::string name;
    std::string memory_hex;
    u64 a = 0, b = 0, c = 0;
    while (std::cin >> name >> a >> b >> c >> memory_hex) {
        auto it = functions.find(name);
        if (it == functions.end()) {
            const auto* symbol = (*binary)->find_by_name(name);
            if (!symbol) return 4;
            auto cfg = builder.build(symbol->addr, name);
            if (!cfg) return 5;
            if (name == "branch_phi" && cfg->blocks.size() < 4) {
                std::fprintf(stderr, "branch fixture lost its diamond CFG\n");
                return 13;
            }
            auto ir = X64Lifter{}.lift(*cfg);
            if (!ir) return 6;
            // All fixtures return integers; discard the alternative FP lane.
            for (auto& block : ir->blocks)
                for (auto& inst : block.insts)
                    if (inst.op == IrOp::Return) inst.src_count = 1;
            // Only the declared integer argument lanes belong to these calls.
            // Do not let the lifter's generic FP/unused argument packs invent
            // reads from unspecified registers in the test oracle.
            if (!project_integer_calls(*ir, call_specs)) return 15;
            if (!SsaBuilder{}.convert(*ir)) return 7;
            discard_unused_call_transport(*ir);
            if (name.starts_with("loop_")) {
                bool has_phi = false;
                for (const auto& block : ir->blocks)
                    for (const auto& inst : block.insts) has_phi |= inst.op == IrOp::Phi;
                if (!has_phi || ir->blocks.size() < 2) {
                    std::fprintf(stderr, "%s: fixture lost loop/phi coverage\n", name.c_str());
                    return 14;
                }
            }
            IrFunction cleaned = *ir;
            if (!run_cleanup(cleaned)) return 8;
            it = functions.emplace(name, std::pair{std::move(*ir), std::move(cleaned)}).first;
        }
        test::MachineInput input;
        if (memory_hex.size() % 2 != 0 || memory_hex.size() > 1024) return 11;
        for (std::size_t i = 0; i < memory_hex.size(); i += 2) {
            unsigned byte = 0;
            const auto parsed = std::from_chars(memory_hex.data() + i,
                memory_hex.data() + i + 2, byte, 16);
            if (parsed.ec != std::errc{} || parsed.ptr != memory_hex.data() + i + 2)
                return 12;
            input.memory.push_back(static_cast<u8>(byte));
        }
        const std::size_t observable_size = input.memory.size();
        // The native caller has a private stack too. Only its explicit target
        // buffer is observable after return; frame scratch is not compared.
        input.memory.resize(observable_size + 8192);
        input.intrinsic = intrinsic;
        input.call = [&](addr_t target, std::span<const u64> args, std::span<u8> memory) {
            return invoke_fixture(call_specs, target, args, memory.first(observable_size));
        };
        const std::array regs{Reg::Rax, Reg::Rbx, Reg::Rcx, Reg::Rdx,
                              Reg::Rsi, Reg::Rdi, Reg::Rbp, Reg::Rsp, Reg::R8, Reg::R9,
                              Reg::R10, Reg::R11, Reg::R12, Reg::R13, Reg::R14, Reg::R15};
        for (Reg reg : regs) input.values[*ssa_key(IrValue::make_reg(reg, IrType::I64))] = 0;
        input.values[*ssa_key(IrValue::make_reg(Reg::Rdi, IrType::I64))] = a;
        input.values[*ssa_key(IrValue::make_reg(Reg::Rsi, IrType::I64))] = b;
        input.values[*ssa_key(IrValue::make_reg(Reg::Rdx, IrType::I64))] = c;
        for (Flag flag : {Flag::Cf, Flag::Of, Flag::Sf, Flag::Zf})
            input.values[*ssa_key(IrValue::make_flag(flag))] = 0;
        input.values[*ssa_key(IrValue::make_reg(Reg::Rsp, IrType::I64))] = input.memory.size() - 56;
        auto before = test::interpret(it->second.first, input);
        auto after = test::interpret(it->second.second, input);
        if (!before || !after) {
            std::fprintf(stderr, "%s: before=%s after=%s\n%s\n%s\n", name.c_str(),
                before ? "ok" : before.error().c_str(), after ? "ok" : after.error().c_str(),
                format_ir_function(it->second.first).c_str(),
                format_ir_function(it->second.second).c_str());
            return 9;
        }
        before->memory.resize(observable_size);
        after->memory.resize(observable_size);
        if (*before != *after) {
            std::fprintf(stderr, "%s: cleanup changed execution\n%s\n%s\n", name.c_str(),
                format_ir_function(it->second.first).c_str(),
                format_ir_function(it->second.second).c_str());
            return 10;
        }
        std::cout << name << ' ' << before->returned.value_or(0) << ' '
                  << after->returned.value_or(0) << ' ';
        for (u8 byte : after->memory)
            std::cout << std::hex << std::setw(2) << std::setfill('0') << unsigned(byte);
        std::cout << std::dec << ' ' << after->call_count << '\n';
    }
}
