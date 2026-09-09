#include "structurer_fail_common.hpp"
#include "../core/src/decompile/emitter_internal.hpp"

using namespace ember;
using ember::emit::Emitter;

namespace {
class VirtualBinary final : public Binary {
public:
    explicit VirtualBinary(bool copy_table = false, bool floating = false) {
        const std::array<u32,6> words{0x81230014, 0x8189000c, 0x7d8903a6,
                                     floating ? 0xfc201090u : (copy_table ? 0x7d244b78u : 0x38800007u),
                                     0x4e800421, 0x4e800020};
        for(std::size_t i=0;i<words.size();++i)
            for(unsigned j=0;j<4;++j)
                bytes[i*4+j]=static_cast<std::byte>((words[i]>>((3-j)*8))&255u);
        section.name=".text";section.vaddr=0x5000;section.size=bytes.size();
        section.flags.allocated=true;section.flags.readable=true;section.flags.executable=true;
        section.data=bytes;
    }
    Format format() const noexcept override{return Format::Dol;}
    Arch arch() const noexcept override{return Arch::Ppc32;}
    Endian endian() const noexcept override{return Endian::Big;}
    addr_t entry_point() const noexcept override{return 0x5000;}
    std::span<const Section> sections() const noexcept override{return {&section,1};}
    std::span<const Symbol> symbols() const noexcept override{return syms;}
    std::span<const std::byte> image() const noexcept override{return bytes;}
protected:
    std::vector<Symbol>& mutable_symbols() noexcept override{return syms;}
private:
    std::array<std::byte,24> bytes{};Section section;std::vector<Symbol> syms;
};
struct VirtualIR {
    IrFunction fn;
    Emitter::CallArgPack pack;
    IrInst call;
    explicit VirtualIR(bool wide=false, bool copy_table=false) {
        const auto type=wide?IrType::I64:IrType::I32;
        const auto object=IrValue::make_reg(Reg::PpcR3,type);
        auto table=IrValue::make_reg(Reg::PpcR9,type);table.version=1;
        auto target=IrValue::make_reg(Reg::PpcR12,type);target.version=1;
        const auto field=IrValue::make_temp(0,type),slot=IrValue::make_temp(1,type);
        fn.start=0x5000;fn.end=0x5018;fn.name="virtual_test";fn.next_temp_id=2;
        IrBlock block;block.start=fn.start;block.end=fn.end;
        block.insts.push_back(make_add(field,object,IrValue::make_imm(wide?24:20,type)));
        auto load=make_load(table,field);load.source_addr=0x5000;block.insts.push_back(load);
        block.insts.push_back(make_add(slot,table,IrValue::make_imm(wide?24:12,type)));
        load=make_load(target,slot);load.source_addr=0x5004;block.insts.push_back(load);
        call.op=IrOp::CallIndirect;call.srcs[0]=target;call.src_count=1;call.source_addr=0x5010;
        block.insts.push_back(call);
        fn.blocks.push_back(block);fn.block_at[fn.start]=0;
        pack.ints={object,copy_table?table:IrValue::make_imm(7,type),
                   IrValue::make_imm(0xdead,type),IrValue::make_imm(0xbeef,type),
                   IrValue::make_imm(0xfeed,type),IrValue::make_imm(0xcafe,type),table};
    }
    void setup(Emitter& e,bool wide=false) {
        e.fn=&fn;e.abi=wide?Abi::Ppc64ElfV2Le:Abi::Ppc32Sysv;
        e.self_arity=1;e.self_arg_layout.emplace_back(Reg::PpcR3,wide?IrType::I64:IrType::I32,true);
        e.self_arg_names[0]="object";e.self_arg_type_names[0]="void*";
        e.ssa_uses.scan(fn);e.ssa_uses.scan_visible(fn,{});
    }
};
void check_virtual(bool copy_table) {
    VirtualBinary binary(copy_table);VirtualIR ir(false,copy_table);Emitter e(&binary);ir.setup(e);
    const auto result=e.render_ppc_virtual_call(ir.call,ir.pack);
    check(result.has_value(),"PPC virtual dispatch recognized");if(!result)return;
    check(result->expr.find("object->vfn_3(")!=std::string::npos,"four-byte PPC32 slot stride");
    check(result->expr.find("vptr +0x14")!=std::string::npos,"nonzero vptr displacement preserved");
    check(result->used_args.size()==2,"receiver plus explicit argument, not stale register snapshots");
    check(result->expr.find("/* r4 */")!=std::string::npos,"explicit argument retains its ABI lane");
    check(result->expr.find("/* r9 */") == std::string::npos,"dispatch scratch register is not an argument");
    if(copy_table)check(result->used_args[1].reg==Reg::PpcR9,"explicit vtable copy into r4 remains an argument");
    else check(result->expr.find("0xdead")==std::string::npos,"stale constants omitted");
    auto wrong=ir.pack;wrong.ints[0]=IrValue::make_reg(Reg::PpcR4,IrType::I32);
    check(!e.render_ppc_virtual_call(ir.call,wrong),"unrelated receiver does not become a virtual method");
}
}
int main() {
    check_virtual(false);check_virtual(true);
    {
        VirtualBinary memory;VirtualIR ir;Emitter saved(&memory);ir.setup(saved);
        auto& body=ir.fn.blocks.front().insts;
        body.insert(body.end()-1,make_store(IrValue::make_temp(0,IrType::I32),IrValue::make_imm(0,IrType::I32)));
        saved.analyze(ir.fn);
        check(!saved.render_ppc_virtual_call(ir.call,ir.pack),
              "a target captured before a vptr overwrite must not be reloaded as a member call");
    }
    {
        VirtualBinary floating(false,true);VirtualIR ir;Emitter fp(&floating);ir.setup(fp);
        fp.self_arity=3;
        fp.self_arg_layout.emplace_back(Reg::PpcF1,IrType::F64);
        fp.self_arg_layout.emplace_back(Reg::PpcF2,IrType::F64);
        fp.self_arg_names[1]="unused";fp.self_arg_names[2]="amount";
        ir.pack.fps.push_back(IrValue::make_reg(Reg::PpcF2,IrType::F64));
        auto call=fp.render_ppc_virtual_call(ir.call,ir.pack);
        check(call && call->expr.find("/* f1 */ amount")!=std::string::npos,
              "fresh floating arguments retain their independent ABI lanes");
    }
    VirtualIR wide(true);Emitter e(nullptr);wide.setup(e,true);
    auto result=e.render_ppc_virtual_call(wide.call,wide.pack);
    check(result && result->expr.find("vfn_3(")!=std::string::npos,"PPC64 retains eight-byte slot stride");
    wide.fn.blocks.front().insts[2].srcs[1]=IrValue::make_imm(12,IrType::I64);
    check(!e.render_ppc_virtual_call(wide.call,wide.pack),
          "unaligned PPC64 vtable offsets are not turned into method slots");
    VirtualBinary binary;VirtualIR typed;Emitter known(&binary);typed.setup(known);
    Annotations ann;ann.renames[0x6000]="known_method";
    ann.signatures[0x6000]=FunctionSig{.return_type="float",.params={{"void*","self"},{"float","amount"}},.variadic=false};
    std::map<addr_t,addr_t> resolutions{{0x5010,0x6000}};
    known.annotations=&ann;known.options.call_resolutions=&resolutions;
    typed.pack.fps.push_back(IrValue::make_imm(0x3f800000,IrType::F32));
    auto rendered=known.render_indirect_call(typed.call,0,typed.pack,{});
    check(rendered.expr.find("known_method(")!=std::string::npos && rendered.used_args.size()==2,
          "resolved mixed signature takes priority over virtual argument heuristics");
    check(known.call_result_reg(typed.call)==Reg::PpcF1 && known.known_call_return_c_type(typed.call)=="float",
          "resolved floating return uses the correct PPC lane and C type");
    return fails?1:0;
}
