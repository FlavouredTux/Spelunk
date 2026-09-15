#pragma once

// Shared harness for the structurer tests: a synthetic PPC binary, IR
// builders and the failure counter.

#include <spelunk/decompile/emitter.hpp>
#include <spelunk/analysis/frame.hpp>
#include <spelunk/analysis/import_sigs.hpp>
#include <spelunk/analysis/type_infer_local.hpp>
#include <spelunk/binary/binary.hpp>
#include <spelunk/ir/ir.hpp>
#include <spelunk/structure/region.hpp>
#include <spelunk/structure/structurer.hpp>
#include <cstdio>
#include <array>
#include <format>
#include <string>
#include <vector>

inline int fails = 0;

class MockPpcBinary final : public spelunk::Binary {
public:
    MockPpcBinary() {
        spelunk::Symbol symbol;
        symbol.name = "ppc_void_callback";
        symbol.addr = 0x1000;
        symbol.size = 0x24;
        symbol.kind = spelunk::SymbolKind::Function;
        symbols_.push_back(std::move(symbol));

        // mixed_callee consumes f1, r3, f2, r4 in that first-use order.
        put(0x100, 0xd02b0000);  // stfs f1,0(r11)
        put(0x104, 0x906b0000);  // stw  r3,0(r11)
        put(0x108, 0xd04b0004);  // stfs f2,4(r11)
        put(0x10c, 0x908b0008);  // stw  r4,8(r11)
        put(0x110, 0x4e800020);  // blr
        spelunk::Symbol mixed;
        mixed.name = "mixed_callee";
        mixed.addr = 0x1100;
        mixed.size = 0x14;
        mixed.kind = spelunk::SymbolKind::Function;
        symbols_.push_back(std::move(mixed));

        spelunk::Symbol mag;
        mag.name = "PSVecMag";
        mag.addr = 0x1800;
        mag.size = 0x44;
        mag.kind = spelunk::SymbolKind::Function;
        symbols_.push_back(std::move(mag));

        spelunk::Symbol subtract;
        subtract.name = "PSVECSubtract";
        subtract.addr = 0x1900;
        subtract.size = 0x24;
        subtract.kind = spelunk::SymbolKind::Function;
        symbols_.push_back(std::move(subtract));

        spelunk::Symbol scale;
        scale.name = "PSVECScale";
        scale.addr = 0x1a00;
        scale.size = 0x1c;
        scale.kind = spelunk::SymbolKind::Function;
        symbols_.push_back(std::move(scale));

        spelunk::Symbol stack_nine;
        stack_nine.name = "stack_nine";
        stack_nine.addr = 0x1b00;
        stack_nine.size = 0x20;
        stack_nine.kind = spelunk::SymbolKind::Function;
        symbols_.push_back(std::move(stack_nine));

        spelunk::Symbol make_vec;
        make_vec.name = "make_vec";
        make_vec.addr = 0x1d00;
        make_vec.size = 0x20;
        make_vec.kind = spelunk::SymbolKind::Function;
        symbols_.push_back(std::move(make_vec));

        spelunk::Symbol consume_header;
        consume_header.name = "consume_header";
        consume_header.addr = 0x1f00;
        consume_header.size = 0x20;
        consume_header.kind = spelunk::SymbolKind::Function;
        symbols_.push_back(std::move(consume_header));

        spelunk::Symbol set_fog;
        set_fog.name = "GXSetFog";
        set_fog.addr = 0x2100;
        set_fog.size = 0x20;
        set_fog.kind = spelunk::SymbolKind::Function;
        symbols_.push_back(std::move(set_fog));

        spelunk::Symbol fmod;
        fmod.name = "fmod";
        fmod.addr = 0x2400;
        fmod.size = 4;
        fmod.kind = spelunk::SymbolKind::Function;
        symbols_.push_back(std::move(fmod));

        spelunk::Symbol sdata_global;
        sdata_global.name = "work_ptr";
        sdata_global.addr = 0x805ae0f8;
        sdata_global.size = 4;
        sdata_global.kind = spelunk::SymbolKind::Object;
        symbols_.push_back(std::move(sdata_global));

        spelunk::Symbol sdata2_global;
        sdata2_global.name = "scale_value";
        sdata2_global.addr = 0x805b3a68;
        sdata2_global.size = 4;
        sdata2_global.kind = spelunk::SymbolKind::Object;
        symbols_.push_back(std::move(sdata2_global));

        section_.name = ".text";
        section_.vaddr = 0x1000;
        section_.size = text_.size();
        section_.flags.readable = true;
        section_.flags.executable = true;
        section_.flags.allocated = true;
        section_.data = text_;
    }
    [[nodiscard]] spelunk::Format format() const noexcept override {
        return spelunk::Format::Dol;
    }
    [[nodiscard]] spelunk::Arch arch() const noexcept override {
        return spelunk::Arch::Ppc32;
    }
    [[nodiscard]] spelunk::Endian endian() const noexcept override {
        return spelunk::Endian::Big;
    }
    [[nodiscard]] spelunk::addr_t entry_point() const noexcept override { return 0x1000; }
    [[nodiscard]] std::span<const spelunk::Section> sections() const noexcept override {
        return std::span<const spelunk::Section>(&section_, 1);
    }
    [[nodiscard]] std::span<const spelunk::Symbol> symbols() const noexcept override {
        return symbols_;
    }
    [[nodiscard]] std::span<const std::byte> image() const noexcept override { return {}; }
    [[nodiscard]] std::optional<spelunk::addr_t>
    ppc_small_data_base(bool read_only) const noexcept override {
        return read_only ? 0x805b7260 : 0x805b5f00;
    }

protected:
    [[nodiscard]] std::vector<spelunk::Symbol>& mutable_symbols() noexcept override {
        return symbols_;
    }

private:
    void put(std::size_t off, spelunk::u32 word) {
        text_[off + 0] = static_cast<std::byte>(word >> 24);
        text_[off + 1] = static_cast<std::byte>(word >> 16);
        text_[off + 2] = static_cast<std::byte>(word >> 8);
        text_[off + 3] = static_cast<std::byte>(word);
    }

    std::array<std::byte, 0x120> text_{};
    spelunk::Section section_{};
    std::vector<spelunk::Symbol> symbols_;
};

inline void check(bool cond, const char* ctx) {
    if (!cond) {
        std::fprintf(stderr, "FAIL: %s\n", ctx);
        ++fails;
    }
}

inline spelunk::IrInst make_ret(spelunk::addr_t pc) {
    spelunk::IrInst ri;
    ri.op          = spelunk::IrOp::Return;
    ri.source_addr = pc;
    return ri;
}

inline spelunk::IrInst make_call_imm(spelunk::addr_t pc, spelunk::addr_t target) {
    spelunk::IrInst ci;
    ci.op          = spelunk::IrOp::Call;
    ci.source_addr = pc;
    ci.target1     = target;
    return ci;
}

inline spelunk::IrInst make_clobber(spelunk::IrValue dst) {
    spelunk::IrInst ci;
    ci.op = spelunk::IrOp::Clobber;
    ci.dst = dst;
    return ci;
}

inline spelunk::IrInst make_branch(spelunk::addr_t pc, spelunk::addr_t target) {
    spelunk::IrInst bi;
    bi.op          = spelunk::IrOp::Branch;
    bi.source_addr = pc;
    bi.target1     = target;
    return bi;
}

inline spelunk::IrInst make_cond_branch(spelunk::addr_t pc, spelunk::IrValue condition,
                               spelunk::addr_t taken,
                               spelunk::addr_t fallthrough) {
    spelunk::IrInst bi;
    bi.op          = spelunk::IrOp::CondBranch;
    bi.source_addr = pc;
    bi.srcs[0]     = condition;
    bi.src_count   = 1;
    bi.target1     = taken;
    bi.target2     = fallthrough;
    return bi;
}

inline spelunk::IrInst make_phi(spelunk::IrValue dst, std::initializer_list<spelunk::IrValue> ops) {
    spelunk::IrInst pi;
    pi.op  = spelunk::IrOp::Phi;
    pi.dst = dst;
    for (spelunk::IrValue op : ops) pi.phi_operands.push_back(op);
    return pi;
}

inline spelunk::IrInst make_add(spelunk::IrValue dst, spelunk::IrValue a, spelunk::IrValue b) {
    spelunk::IrInst ai;
    ai.op        = spelunk::IrOp::Add;
    ai.dst       = dst;
    ai.srcs[0]   = a;
    ai.srcs[1]   = b;
    ai.src_count = 2;
    return ai;
}

inline spelunk::IrInst make_mul(spelunk::IrValue dst, spelunk::IrValue a, spelunk::IrValue b) {
    spelunk::IrInst mi;
    mi.op        = spelunk::IrOp::Mul;
    mi.dst       = dst;
    mi.srcs[0]   = a;
    mi.srcs[1]   = b;
    mi.src_count = 2;
    return mi;
}

inline spelunk::IrInst make_load(spelunk::IrValue dst, spelunk::IrValue addr) {
    spelunk::IrInst li;
    li.op        = spelunk::IrOp::Load;
    li.dst       = dst;
    li.srcs[0]   = addr;
    li.src_count = 1;
    return li;
}

inline spelunk::IrInst make_store(spelunk::IrValue addr, spelunk::IrValue value) {
    spelunk::IrInst si;
    si.op        = spelunk::IrOp::Store;
    si.srcs[0]   = addr;
    si.srcs[1]   = value;
    si.src_count = 2;
    return si;
}

inline spelunk::IrInst make_assign(spelunk::IrValue dst, spelunk::IrValue src) {
    spelunk::IrInst ai;
    ai.op        = spelunk::IrOp::Assign;
    ai.dst       = dst;
    ai.srcs[0]   = src;
    ai.src_count = 1;
    return ai;
}

inline spelunk::IrInst make_ret_value(spelunk::addr_t pc, spelunk::IrValue value) {
    spelunk::IrInst ri = make_ret(pc);
    ri.srcs[0] = value;
    ri.src_count = 1;
    return ri;
}

// Defined in structurer_fail_ppc_test.cpp.
int run_ppc_structurer_tests();

// Defined in structurer_control_flow_test.cpp.
int run_structurer_control_flow_tests();
