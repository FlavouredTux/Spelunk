#pragma once

// Shared harness for the structurer tests: a synthetic PPC binary, IR
// builders and the failure counter.

#include <ember/decompile/emitter.hpp>
#include <ember/analysis/frame.hpp>
#include <ember/analysis/import_sigs.hpp>
#include <ember/analysis/type_infer_local.hpp>
#include <ember/binary/binary.hpp>
#include <ember/ir/ir.hpp>
#include <ember/structure/region.hpp>
#include <ember/structure/structurer.hpp>
#include <cstdio>
#include <array>
#include <format>
#include <string>
#include <vector>

inline int fails = 0;

class MockPpcBinary final : public ember::Binary {
public:
    MockPpcBinary() {
        ember::Symbol symbol;
        symbol.name = "ppc_void_callback";
        symbol.addr = 0x1000;
        symbol.size = 0x24;
        symbol.kind = ember::SymbolKind::Function;
        symbols_.push_back(std::move(symbol));

        // mixed_callee consumes f1, r3, f2, r4 in that first-use order.
        put(0x100, 0xd02b0000);  // stfs f1,0(r11)
        put(0x104, 0x906b0000);  // stw  r3,0(r11)
        put(0x108, 0xd04b0004);  // stfs f2,4(r11)
        put(0x10c, 0x908b0008);  // stw  r4,8(r11)
        put(0x110, 0x4e800020);  // blr
        ember::Symbol mixed;
        mixed.name = "mixed_callee";
        mixed.addr = 0x1100;
        mixed.size = 0x14;
        mixed.kind = ember::SymbolKind::Function;
        symbols_.push_back(std::move(mixed));

        ember::Symbol mag;
        mag.name = "PSVecMag";
        mag.addr = 0x1800;
        mag.size = 0x44;
        mag.kind = ember::SymbolKind::Function;
        symbols_.push_back(std::move(mag));

        ember::Symbol subtract;
        subtract.name = "PSVECSubtract";
        subtract.addr = 0x1900;
        subtract.size = 0x24;
        subtract.kind = ember::SymbolKind::Function;
        symbols_.push_back(std::move(subtract));

        ember::Symbol scale;
        scale.name = "PSVECScale";
        scale.addr = 0x1a00;
        scale.size = 0x1c;
        scale.kind = ember::SymbolKind::Function;
        symbols_.push_back(std::move(scale));

        ember::Symbol stack_nine;
        stack_nine.name = "stack_nine";
        stack_nine.addr = 0x1b00;
        stack_nine.size = 0x20;
        stack_nine.kind = ember::SymbolKind::Function;
        symbols_.push_back(std::move(stack_nine));

        ember::Symbol make_vec;
        make_vec.name = "make_vec";
        make_vec.addr = 0x1d00;
        make_vec.size = 0x20;
        make_vec.kind = ember::SymbolKind::Function;
        symbols_.push_back(std::move(make_vec));

        ember::Symbol consume_header;
        consume_header.name = "consume_header";
        consume_header.addr = 0x1f00;
        consume_header.size = 0x20;
        consume_header.kind = ember::SymbolKind::Function;
        symbols_.push_back(std::move(consume_header));

        ember::Symbol set_fog;
        set_fog.name = "GXSetFog";
        set_fog.addr = 0x2100;
        set_fog.size = 0x20;
        set_fog.kind = ember::SymbolKind::Function;
        symbols_.push_back(std::move(set_fog));

        ember::Symbol fmod;
        fmod.name = "fmod";
        fmod.addr = 0x2400;
        fmod.size = 4;
        fmod.kind = ember::SymbolKind::Function;
        symbols_.push_back(std::move(fmod));

        ember::Symbol sdata_global;
        sdata_global.name = "work_ptr";
        sdata_global.addr = 0x805ae0f8;
        sdata_global.size = 4;
        sdata_global.kind = ember::SymbolKind::Object;
        symbols_.push_back(std::move(sdata_global));

        ember::Symbol sdata2_global;
        sdata2_global.name = "scale_value";
        sdata2_global.addr = 0x805b3a68;
        sdata2_global.size = 4;
        sdata2_global.kind = ember::SymbolKind::Object;
        symbols_.push_back(std::move(sdata2_global));

        section_.name = ".text";
        section_.vaddr = 0x1000;
        section_.size = text_.size();
        section_.flags.readable = true;
        section_.flags.executable = true;
        section_.flags.allocated = true;
        section_.data = text_;
    }
    [[nodiscard]] ember::Format format() const noexcept override {
        return ember::Format::Dol;
    }
    [[nodiscard]] ember::Arch arch() const noexcept override {
        return ember::Arch::Ppc32;
    }
    [[nodiscard]] ember::Endian endian() const noexcept override {
        return ember::Endian::Big;
    }
    [[nodiscard]] ember::addr_t entry_point() const noexcept override { return 0x1000; }
    [[nodiscard]] std::span<const ember::Section> sections() const noexcept override {
        return std::span<const ember::Section>(&section_, 1);
    }
    [[nodiscard]] std::span<const ember::Symbol> symbols() const noexcept override {
        return symbols_;
    }
    [[nodiscard]] std::span<const std::byte> image() const noexcept override { return {}; }
    [[nodiscard]] std::optional<ember::addr_t>
    ppc_small_data_base(bool read_only) const noexcept override {
        return read_only ? 0x805b7260 : 0x805b5f00;
    }

protected:
    [[nodiscard]] std::vector<ember::Symbol>& mutable_symbols() noexcept override {
        return symbols_;
    }

private:
    void put(std::size_t off, ember::u32 word) {
        text_[off + 0] = static_cast<std::byte>(word >> 24);
        text_[off + 1] = static_cast<std::byte>(word >> 16);
        text_[off + 2] = static_cast<std::byte>(word >> 8);
        text_[off + 3] = static_cast<std::byte>(word);
    }

    std::array<std::byte, 0x120> text_{};
    ember::Section section_{};
    std::vector<ember::Symbol> symbols_;
};

inline void check(bool cond, const char* ctx) {
    if (!cond) {
        std::fprintf(stderr, "FAIL: %s\n", ctx);
        ++fails;
    }
}

inline ember::IrInst make_ret(ember::addr_t pc) {
    ember::IrInst ri;
    ri.op          = ember::IrOp::Return;
    ri.source_addr = pc;
    return ri;
}

inline ember::IrInst make_call_imm(ember::addr_t pc, ember::addr_t target) {
    ember::IrInst ci;
    ci.op          = ember::IrOp::Call;
    ci.source_addr = pc;
    ci.target1     = target;
    return ci;
}

inline ember::IrInst make_clobber(ember::IrValue dst) {
    ember::IrInst ci;
    ci.op = ember::IrOp::Clobber;
    ci.dst = dst;
    return ci;
}

inline ember::IrInst make_branch(ember::addr_t pc, ember::addr_t target) {
    ember::IrInst bi;
    bi.op          = ember::IrOp::Branch;
    bi.source_addr = pc;
    bi.target1     = target;
    return bi;
}

inline ember::IrInst make_cond_branch(ember::addr_t pc, ember::IrValue condition,
                               ember::addr_t taken,
                               ember::addr_t fallthrough) {
    ember::IrInst bi;
    bi.op          = ember::IrOp::CondBranch;
    bi.source_addr = pc;
    bi.srcs[0]     = condition;
    bi.src_count   = 1;
    bi.target1     = taken;
    bi.target2     = fallthrough;
    return bi;
}

inline ember::IrInst make_phi(ember::IrValue dst, std::initializer_list<ember::IrValue> ops) {
    ember::IrInst pi;
    pi.op  = ember::IrOp::Phi;
    pi.dst = dst;
    for (ember::IrValue op : ops) pi.phi_operands.push_back(op);
    return pi;
}

inline ember::IrInst make_add(ember::IrValue dst, ember::IrValue a, ember::IrValue b) {
    ember::IrInst ai;
    ai.op        = ember::IrOp::Add;
    ai.dst       = dst;
    ai.srcs[0]   = a;
    ai.srcs[1]   = b;
    ai.src_count = 2;
    return ai;
}

inline ember::IrInst make_mul(ember::IrValue dst, ember::IrValue a, ember::IrValue b) {
    ember::IrInst mi;
    mi.op        = ember::IrOp::Mul;
    mi.dst       = dst;
    mi.srcs[0]   = a;
    mi.srcs[1]   = b;
    mi.src_count = 2;
    return mi;
}

inline ember::IrInst make_load(ember::IrValue dst, ember::IrValue addr) {
    ember::IrInst li;
    li.op        = ember::IrOp::Load;
    li.dst       = dst;
    li.srcs[0]   = addr;
    li.src_count = 1;
    return li;
}

inline ember::IrInst make_store(ember::IrValue addr, ember::IrValue value) {
    ember::IrInst si;
    si.op        = ember::IrOp::Store;
    si.srcs[0]   = addr;
    si.srcs[1]   = value;
    si.src_count = 2;
    return si;
}

inline ember::IrInst make_assign(ember::IrValue dst, ember::IrValue src) {
    ember::IrInst ai;
    ai.op        = ember::IrOp::Assign;
    ai.dst       = dst;
    ai.srcs[0]   = src;
    ai.src_count = 1;
    return ai;
}

inline ember::IrInst make_ret_value(ember::addr_t pc, ember::IrValue value) {
    ember::IrInst ri = make_ret(pc);
    ri.srcs[0] = value;
    ri.src_count = 1;
    return ri;
}

// Defined in structurer_fail_ppc_test.cpp.
int run_ppc_structurer_tests();

// Defined in structurer_control_flow_test.cpp.
int run_structurer_control_flow_tests();
