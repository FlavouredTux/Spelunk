#include "support/ir_interpreter.hpp"

#include <array>
#include <bit>
#include <cstdio>
#include <iostream>
#include <map>
#include <string>

#include <ember/analysis/cfg_builder.hpp>
#include <ember/disasm/x64_decoder.hpp>
#include <ember/ir/passes.hpp>
#include <ember/ir/x64_lifter.hpp>

namespace {
using namespace ember;

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
}  // namespace

int main(int argc, char** argv) {
    using namespace ember;
    if (argc != 2) return 2;
    auto binary = load_binary(argv[1]);
    if (!binary) return 3;
    X64Decoder decoder;
    CfgBuilder builder(**binary, decoder);
    std::map<std::string, std::pair<IrFunction, IrFunction>> functions;
    std::string name;
    u64 a = 0, b = 0, c = 0;
    while (std::cin >> name >> a >> b >> c) {
        auto it = functions.find(name);
        if (it == functions.end()) {
            const auto* symbol = (*binary)->find_by_name(name);
            if (!symbol) return 4;
            auto cfg = builder.build(symbol->addr, name);
            if (!cfg) return 5;
            auto ir = X64Lifter{}.lift(*cfg);
            if (!ir) return 6;
            // All fixtures return integers; discard the alternative FP lane.
            for (auto& block : ir->blocks)
                for (auto& inst : block.insts)
                    if (inst.op == IrOp::Return) inst.src_count = 1;
            if (!SsaBuilder{}.convert(*ir)) return 7;
            IrFunction cleaned = *ir;
            if (!run_cleanup(cleaned)) return 8;
            it = functions.emplace(name, std::pair{std::move(*ir), std::move(cleaned)}).first;
        }
        test::MachineInput input;
        input.memory.resize(64);
        input.intrinsic = intrinsic;
        const std::array regs{Reg::Rax, Reg::Rbx, Reg::Rcx, Reg::Rdx,
                              Reg::Rsi, Reg::Rdi, Reg::Rbp, Reg::Rsp};
        for (Reg reg : regs) input.values[*ssa_key(IrValue::make_reg(reg, IrType::I64))] = 0;
        input.values[*ssa_key(IrValue::make_reg(Reg::Rdi, IrType::I64))] = a;
        input.values[*ssa_key(IrValue::make_reg(Reg::Rsi, IrType::I64))] = b;
        input.values[*ssa_key(IrValue::make_reg(Reg::Rdx, IrType::I64))] = c;
        for (Flag flag : {Flag::Cf, Flag::Of, Flag::Sf, Flag::Zf})
            input.values[*ssa_key(IrValue::make_flag(flag))] = 0;
        if (name == "xchg_address") input.memory[16] = 3;
        const auto before = test::interpret(it->second.first, input);
        const auto after = test::interpret(it->second.second, input);
        if (!before || !after) {
            std::fprintf(stderr, "%s: before=%s after=%s\n%s\n%s\n", name.c_str(),
                before ? "ok" : before.error().c_str(), after ? "ok" : after.error().c_str(),
                format_ir_function(it->second.first).c_str(),
                format_ir_function(it->second.second).c_str());
            return 9;
        }
        if (*before != *after) {
            std::fprintf(stderr, "%s: cleanup changed execution\n", name.c_str());
            return 10;
        }
        std::cout << name << ' ' << before->returned.value_or(0) << ' '
                  << after->returned.value_or(0) << ' ' << unsigned(after->memory[16]) << '\n';
    }
}
