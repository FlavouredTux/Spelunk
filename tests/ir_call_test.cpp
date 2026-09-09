#include "support/ir_interpreter.hpp"
#include <cstdio>

namespace {
using namespace ember;
using namespace ember::test;
int failures=0;
void check(bool ok,const char* message){if(!ok){std::fprintf(stderr,"FAIL: %s\n",message);++failures;}}
IrFunction function(bool read_clobbered=false) {
    IrFunction fn;fn.start=0x1000;fn.end=0x1010;
    IrBlock block;block.start=fn.start;block.end=fn.end;block.kind=BlockKind::Return;
    IrInst pack;pack.op=IrOp::Intrinsic;pack.name="call.args.1";
    pack.srcs[0]=IrValue::make_imm(41,IrType::I64);pack.src_count=1;
    block.insts.push_back(pack);
    IrInst call;call.op=IrOp::Call;call.target1=0x2000;block.insts.push_back(call);
    IrInst clobber;clobber.op=IrOp::Clobber;clobber.dst=IrValue::make_reg(Reg::Rax,IrType::I64);
    clobber.dst.version=1;block.insts.push_back(clobber);
    if(read_clobbered){clobber.dst.reg=Reg::Rdi;block.insts.push_back(clobber);}
    IrInst ret;ret.op=IrOp::Return;ret.srcs[0]=clobber.dst;ret.src_count=1;block.insts.push_back(ret);
    fn.block_at[fn.start]=0;fn.blocks.push_back(block);return fn;
}
}
int main() {
    MachineInput input;input.memory.resize(8,0xa5);
    input.call=[](addr_t target,std::span<const u64> args,std::span<u8> memory)->std::expected<u64,std::string>{
        if(target!=0x2000 || args.size()!=1 || args[0]!=41)return std::unexpected("unknown call or arguments");
        memory[3]=0x42;return 0;
    };
    auto result=interpret(function(),input);
    check(result && result->returned==0 && result->call_count==1 && result->memory[3]==0x42,
          "call-only callback receives args, mutates memory and returns zero through RAX");
    check(!interpret(function(true),input),"caller-clobbered register reads are rejected");
    check(!interpret(function(),{}),"calls require an explicit oracle");
    auto wrong=function();wrong.blocks[0].insts[1].target1=0x9999;
    check(!interpret(wrong,input),"unmodeled call targets fail");
    auto delayed=function();IrInst assign;assign.op=IrOp::Assign;
    assign.dst=IrValue::make_temp(0,IrType::I64);assign.srcs[0]=IrValue::make_imm(1,IrType::I64);assign.src_count=1;
    delayed.blocks[0].insts.insert(delayed.blocks[0].insts.begin()+2,assign);
    check(!interpret(delayed,input),"clobbers must belong to the immediately preceding call");
    auto bad_pack=function();bad_pack.blocks[0].insts[0].name="call.args.2";
    check(!interpret(bad_pack,input),"orphan continuation argument packs fail");
    auto unknown_pack=function();unknown_pack.blocks[0].insts[0].name="call.args.99";
    check(!interpret(unknown_pack,input),"unknown argument pack names fail");
    auto missing_call=function();missing_call.blocks[0].insts.erase(missing_call.blocks[0].insts.begin()+1,
                                                                 missing_call.blocks[0].insts.begin()+3);
    missing_call.blocks[0].insts.back().srcs[0]=IrValue::make_imm(0,IrType::I64);
    check(!interpret(missing_call,input),"unconsumed call packs fail");
    return failures?1:0;
}
