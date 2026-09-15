// Project the fixture's declared integer ABI onto the shared test interpreter.
// Endianness and call oracles are test adapters, never production IR rewrites.
#include "support/ir_interpreter.hpp"

#include <spelunk/analysis/cfg_builder.hpp>
#include <spelunk/binary/binary.hpp>
#include <spelunk/decompile/emitter.hpp>
#include <spelunk/disasm/decoder.hpp>
#include <spelunk/ir/lifter.hpp>
#include <spelunk/ir/passes.hpp>
#include <spelunk/ir/ssa.hpp>
#include <spelunk/structure/structurer.hpp>

#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>

namespace {
using namespace spelunk;
constexpr addr_t data_base=0x10000, observe_addr=0x110000, mutate_addr=0x110010;
constexpr addr_t stack_top=0x28000, stop=0x120000;
constexpr std::size_t data_size=256;

IrInst operation(IrOp op, IrValue dst, std::initializer_list<IrValue> args) {
    IrInst result; result.op=op;result.dst=dst;result.src_count=static_cast<u8>(args.size());
    std::copy(args.begin(),args.end(),result.srcs.begin());return result;
}
IrFunction adapt(IrFunction fn) {
    const auto temp=[&](IrType type){return IrValue::make_temp(fn.next_temp_id++,type);};
    for(auto& block:fn.blocks) {
        std::vector<IrInst> projected;
        std::vector<IrValue> arguments;
        std::optional<IrValue> returned;
        for(auto inst:block.insts) {
            if(inst.op==IrOp::Intrinsic && inst.name.starts_with("call.args.")) {
                if(inst.name=="call.args.1")arguments.clear();
                for(u8 i=0;i<inst.src_count;++i)arguments.push_back(inst.srcs[i]);
                continue;
            }
            if(inst.op==IrOp::Intrinsic && inst.name.starts_with("call.fp_args."))continue;
            if(inst.op==IrOp::CallIndirect)throw std::runtime_error("unmodeled indirect call");
            if(inst.op==IrOp::Call) {
                if((inst.target1!=observe_addr && inst.target1!=mutate_addr) || arguments.empty())
                    throw std::runtime_error("unmodeled call target or missing declared argument");
                const auto old=temp(IrType::I32);
                projected.push_back(operation(IrOp::Load,old,{IrValue::make_imm(data_base,IrType::I32)}));
                returned=temp(IrType::I32);
                auto invoke=operation(IrOp::Intrinsic,*returned,{arguments[0],old});
                invoke.name=inst.target1==observe_addr?"ppc.test.observe":"ppc.test.mutate";
                projected.push_back(std::move(invoke));
                if(inst.target1==mutate_addr) {
                    const auto updated=temp(IrType::I32);
                    projected.push_back(operation(IrOp::Add,updated,{old,arguments[0]}));
                    projected.push_back(operation(IrOp::Store,{},
                        {IrValue::make_imm(data_base,IrType::I32),updated}));
                }
                arguments.clear();continue;
            }
            if(inst.op==IrOp::Clobber && inst.dst.kind==IrValueKind::Reg &&
                canonical_reg(inst.dst.reg)==Reg::PpcR3) {
                if(!returned)throw std::runtime_error("return clobber without call");
                inst=operation(IrOp::Assign,inst.dst,{*returned});
            }
            if(inst.op==IrOp::Return) {
                if(inst.src_count!=2 || !is_float_type(inst.srcs[1].type))
                    throw std::runtime_error("unexpected PPC integer return shape");
                inst.src_count=1; // fixture prototypes explicitly return uint32_t, not f1
            }
            projected.push_back(std::move(inst));
        }
        block.insts=std::move(projected);
    }
    // Remove only dead transport definitions after dropping unused ABI lanes.
    // A live clobber, floating operation or unknown intrinsic must still fail.
    bool changed=true;
    while(changed) {
        changed=false;std::set<SsaKey> used;
        for(const auto& block:fn.blocks)for(const auto& inst:block.insts) {
            for(u8 i=0;i<inst.src_count;++i)if(auto k=ssa_key(inst.srcs[i]))used.insert(*k);
            for(const auto& v:inst.phi_operands)if(auto k=ssa_key(v))used.insert(*k);
        }
        for(auto& block:fn.blocks)for(auto& inst:block.insts) {
            if(inst.op!=IrOp::Clobber && inst.op!=IrOp::Phi && inst.op!=IrOp::Assign)continue;
            if(auto key=ssa_key(inst.dst);key && !used.contains(*key)){inst=IrInst{};changed=true;}
        }
    }
    for(auto& block:fn.blocks) {
        std::vector<IrInst> projected;
        for(auto inst:block.insts) {
            const auto swap=[&](IrValue input,IrValue output) {
                auto s=operation(IrOp::Intrinsic,output,{input});
                s.name="ppc.test.bswap"+std::to_string(type_bits(input.type));return s;
            };
            if(inst.op==IrOp::Load && type_bits(inst.dst.type)>8) {
                const auto destination=inst.dst;inst.dst=temp(destination.type);
                projected.push_back(inst);projected.push_back(swap(inst.dst,destination));
            } else if(inst.op==IrOp::Store && type_bits(inst.srcs[1].type)>8) {
                const auto value=temp(inst.srcs[1].type);
                projected.push_back(swap(inst.srcs[1],value));inst.srcs[1]=value;
                projected.push_back(inst);
            } else projected.push_back(inst);
        }
        block.insts=std::move(projected);
    }
    return fn;
}
std::string hex_memory(std::span<const u8> bytes) {
    constexpr char digits[]="0123456789abcdef";std::string out;
    for(u8 byte:bytes){out+=digits[byte>>4];out+=digits[byte&15];}return out;
}
std::string execute(const IrFunction& fn, std::array<u32,3> args,const std::string& memory) {
    test::MachineInput input;input.memory.resize(0x30000,0xa5);
    if(memory.size()!=data_size*2)throw std::runtime_error("wrong input memory size");
    for(std::size_t i=0;i<data_size;++i)
        input.memory[data_base+i]=static_cast<u8>(std::stoul(memory.substr(i*2,2),nullptr,16));
    for(unsigned i=0;i<32;++i)input.values[*ssa_key(IrValue::make_reg(static_cast<Reg>(static_cast<unsigned>(Reg::PpcR0)+i),IrType::I32))]=0;
    const auto set=[&](Reg reg,u32 value){input.values[*ssa_key(IrValue::make_reg(reg,IrType::I32))]=value;};
    set(Reg::PpcR1,static_cast<u32>(stack_top));set(Reg::PpcLr,static_cast<u32>(stop));set(Reg::PpcCtr,0);
    for(unsigned i=0;i<3;++i)set(static_cast<Reg>(static_cast<unsigned>(Reg::PpcR3)+i),args[i]);
    for(unsigned i=0;i<=static_cast<unsigned>(Flag::Cr7So);++i)
        input.values[*ssa_key(IrValue::make_flag(static_cast<Flag>(i)))]=0;
    std::string trace;
    input.intrinsic=[&](const IrInst& inst,std::span<const u64> values)->std::expected<u64,std::string>{
        if(inst.name.starts_with("ppc.test.bswap")) {
            const unsigned width=type_bits(inst.dst.type);
            if(values.size()!=1 || is_float_type(inst.dst.type) || (width!=16 && width!=32 && width!=64))
                return std::unexpected("unsupported byte swap");
            u64 out=0;for(unsigned i=0;i<width/8;++i)out=(out<<8)|((values[0]>>(i*8))&255u);
            return out;
        }
        if((inst.name!="ppc.test.observe" && inst.name!="ppc.test.mutate") || values.size()!=2)
            return std::unexpected("unsupported intrinsic: "+inst.name);
        const bool observe=inst.name=="ppc.test.observe";
        if(!trace.empty())trace+=';';
        trace+=(observe?"observe":"mutate")+std::string(":")+std::to_string(values[0])+":"+std::to_string(values[1]);
        return observe?static_cast<u32>(values[0]^0x55u):static_cast<u32>(values[1]);
    };
    auto result=test::interpret(fn,input);
    if(!result)throw std::runtime_error(result.error());
    if(!result->returned)throw std::runtime_error("missing integer return");
    return std::to_string(*result->returned & 0xffffffffu)+" "+
        hex_memory(std::span{result->memory}.subspan(data_base,data_size))+" "+(trace.empty()?"-":trace);
}
struct Prepared {IrFunction before,after;};
void negative_controls() {
    IrFunction loop;loop.start=0x1000;loop.end=0x1008;
    IrBlock block;block.start=loop.start;block.end=0x1004;
    block.kind=BlockKind::Unconditional;block.successors={0x1004};
    auto branch=operation(IrOp::Branch,{},{});branch.target1=0x1004;block.insts.push_back(branch);
    loop.blocks.push_back(block);loop.block_at[loop.start]=0;
    block.start=0x1004;block.end=0x1008;block.predecessors={0x1000,0x1004};
    loop.blocks.push_back(block);loop.block_at[0x1004]=1;
    const auto stopped=test::interpret(loop,{},8);
    if(stopped || stopped.error().find("step limit")==std::string::npos)
        throw std::runtime_error("interpreter accepted instruction-limit exhaustion");
    auto unknown=loop;
    auto call=operation(IrOp::Call,{},{});call.target1=0x9999;
    unknown.blocks.front().insts.insert(unknown.blocks.front().insts.begin(),call);
    bool rejected=false;
    try { (void)adapt(unknown); } catch(const std::runtime_error&) { rejected=true; }
    if(!rejected)throw std::runtime_error("adapter accepted an unmodeled call");
    auto bad_intrinsic=loop;
    auto intrinsic=operation(IrOp::Intrinsic,IrValue::make_temp(0,IrType::I32),{});
    intrinsic.name="unsupported.test.operation";
    bad_intrinsic.blocks.front().insts.insert(bad_intrinsic.blocks.front().insts.begin(),intrinsic);
    rejected=false;
    try { (void)execute(bad_intrinsic,{0,0,0},std::string(data_size*2,'0')); }
    catch(const std::runtime_error& error) {rejected=std::string(error.what()).find("unsupported intrinsic")!=std::string::npos;}
    if(!rejected)throw std::runtime_error("interpreter accepted an unknown intrinsic");
}
}
int main(int argc,char** argv) {
    if(argc==2 && std::string_view(argv[1])=="--self-test") {
        try {negative_controls();return 0;}
        catch(const std::exception& error){std::cerr<<error.what()<<"\n";return 1;}
    }
    if(argc!=3)return 2;
    try {
        auto binary=spelunk::load_binary(argv[1]);if(!binary)throw std::runtime_error(binary.error().message);
        auto decoder=spelunk::make_decoder(**binary);auto lifter=spelunk::make_lifter(**binary);
        if(!decoder || !lifter)throw std::runtime_error("missing PPC decoder/lifter");
        std::filesystem::create_directories(argv[2]);
        Annotations annotations;
        for(const auto& s:(*binary)->symbols())if(s.kind==SymbolKind::Function){
            annotations.signatures[s.addr]=FunctionSig{.return_type="uint32_t",
                .params={{s.name=="memory_overlap"?"uint8_t*":"uint32_t","a"},{"uint32_t","b"},{"uint32_t","c"}},.variadic=false};
        }
        for(const auto& [address,name]:std::array<std::pair<addr_t,const char*>,2>{{{observe_addr,"observe"},{mutate_addr,"mutate"}}}) {
            annotations.renames[address]=name;
            annotations.signatures[address]=FunctionSig{.return_type="uint32_t",.params={{"uint32_t","value"}},.variadic=false};
        }
        std::map<std::string,Prepared> cache;
        std::string name,memory;u32 a,b,c;
        while(std::cin>>name>>a>>b>>c>>memory) {
            auto found=cache.find(name);
            if(found==cache.end()) {
                const auto* symbol=(*binary)->find_by_name(name);if(!symbol)throw std::runtime_error("unknown fixture");
                const CfgBuilder builder(**binary,**decoder);auto cfg=builder.build(symbol->addr,name);
                if(!cfg)throw std::runtime_error(cfg.error().message);
                auto ir=(*lifter)->lift(*cfg);if(!ir)throw std::runtime_error(ir.error().message);
                if(auto ssa=SsaBuilder{}.convert(*ir);!ssa)throw std::runtime_error(ssa.error().message);
                auto cleaned=*ir;if(auto ok=run_cleanup(cleaned);!ok)throw std::runtime_error(ok.error().message);
                auto sf=Structurer{}.structure(cleaned);if(!sf)throw std::runtime_error(sf.error().message);
                auto pseudo=PseudoCEmitter{}.emit(*sf,binary->get(),&annotations,{});
                if(!pseudo)throw std::runtime_error(pseudo.error().message);
                const std::filesystem::path root=argv[2];
                std::ofstream(root/(name+".c"))<<*pseudo;
                std::ofstream(root/(name+".before.ir"))<<format_ir_function(*ir);
                std::ofstream(root/(name+".after.ir"))<<format_ir_function(cleaned);
                auto before=adapt(*ir),after=adapt(cleaned);
                std::ofstream(root/(name+".adapted-before.ir"))<<format_ir_function(before);
                std::ofstream(root/(name+".adapted-after.ir"))<<format_ir_function(after);
                found=cache.emplace(name,Prepared{std::move(before),std::move(after)}).first;
            }
            try {
                std::cout<<name<<" "<<execute(found->second.before,{a,b,c},memory)<<" "
                         <<execute(found->second.after,{a,b,c},memory)<<"\n";
            } catch(const std::exception& e) {throw std::runtime_error(name+": "+e.what());}
        }
    }catch(const std::exception& e){std::cerr<<e.what()<<"\n";return 1;}
}
