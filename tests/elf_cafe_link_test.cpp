#include <ember/binary/elf.hpp>
#include <ember/common/bytes.hpp>
#include <ember/analysis/pipeline.hpp>
#include <array>
#include <cstdio>
#include <string>
#include <vector>

namespace {
using namespace ember;
void put32(std::vector<std::byte>& b, std::size_t off, u32 x) {
    for (unsigned j = 0; j < 4; ++j) b[off+j] = static_cast<std::byte>((x >> ((3-j)*8)) & 255u);
}
void put16(std::vector<std::byte>& b, std::size_t off, u16 x) {
    b[off] = static_cast<std::byte>(x >> 8); b[off+1] = static_cast<std::byte>(x & 255u);
}
u32 add_string(std::vector<std::byte>& bytes, const char* text) {
    const auto offset = static_cast<u32>(bytes.size());
    do { bytes.push_back(static_cast<std::byte>(*text)); } while (*text++);
    return offset;
}
struct Fixture {
    struct Part {
        u32 type=1, flags=0, addr=0, link=0, info=0, entsize=0, nobits=0;
        std::vector<std::byte> data;
    };
    std::array<Part, 14> parts;
    Fixture() {
        parts[0].type=0;
        auto& text=parts[1]; text.addr=0x02000000; text.flags=6; text.data.resize(32);
        put32(text.data,0,0x48000001); // unresolved bl: must acquire a reachable import veneer
        put32(text.data,4,0x3c600000); put32(text.data,8,0x38630000);
        put32(text.data,12,0x3c800000); put32(text.data,16,0x4e800020);
        put32(text.data,20,0x3ca00000); put32(text.data,24,0x38a50000);
        auto& data=parts[2]; data.addr=0x10000000; data.flags=3; data.data.resize(32);
        put32(data.data,12,0xdeadbeef);
        for (std::size_t i : {3u,4u}) {
            parts[i].type=0x80000002; parts[i].flags=i==3?6:2;
            parts[i].addr=i==3?0xc0000000:0xc0000100;
            parts[i].data.resize(8); put32(parts[i].data,0,1);
            add_string(parts[i].data,"coreinit"); parts[i].data.resize(24);
        }
        auto& symbols=parts[5]; symbols.type=2; symbols.link=6; symbols.entsize=16;
        auto& strings=parts[6]; strings.type=3; strings.data.push_back(std::byte{0});
        symbols.data.resize(6*16);
        const auto sym=[&](std::size_t i,const char* name,u32 value,u8 info,u16 section) {
            put32(symbols.data,i*16,add_string(strings.data,name));
            put32(symbols.data,i*16+4,value); symbols.data[i*16+12]=static_cast<std::byte>(info);
            put16(symbols.data,i*16+14,section);
        };
        sym(1,"OSBlockMove",0xc0000008,0x12,3);
        sym(2,"MEMDefaultHeap",0xc0000108,0x11,4);
        sym(3,"object",0x10000010,0x11,2);
        sym(4,"local_function",0x02000010,0x12,1);
        sym(5,"tls_object",4,0x16,10);
        const auto rela=[&](std::size_t table,u32 site,u32 symbol,u32 type,u32 addend=0) {
            auto& p=parts[table]; p.type=4; p.link=5; p.entsize=12;
            const auto at=p.data.size(); p.data.resize(at+12);
            put32(p.data,at,site);put32(p.data,at+4,(symbol<<8)|type);put32(p.data,at+8,addend);
        };
        parts[7].info=1;
        rela(7,0x02000000,1,10);
        rela(7,0x02000006,3,6,0x8000);
        rela(7,0x0200000a,3,4,0x8000);
        rela(7,0x0200000e,4,251,0x10000);
        rela(7,0x02000016,4,252);
        rela(7,0x0200001a,4,253);
        parts[8].info=2;
        rela(8,0x10000000,3,1,4);
        rela(8,0x10000004,2,1);
        rela(8,0x10000008,4,26);
        rela(8,0x1000000c,5,68);
        rela(8,0x10000010,5,78,8);
        rela(8,0x10000014,3,250);
        parts[9].type=3;
        parts[10].type=8;parts[10].addr=0x10001000;parts[10].flags=0x04000003;parts[10].nobits=16;
        parts[11].info=10;rela(11,0x10001000,3,1);
        parts[12].type=0x80000001;parts[12].flags=6;parts[12].addr=0x10002000;
        parts[12].data.resize(24);put32(parts[12].data,0,1);put32(parts[12].data,12,24);
        add_string(parts[12].data,"ExportedFn");
        parts[13].info=12;rela(13,0x10002008,4,1,4);
    }
    std::vector<std::byte> bytes() {
        parts[9].data={std::byte{0}};
        std::array<u32,14> names{};
        const std::array<const char*,14> labels{"", ".text", ".data", ".fimport_coreinit", ".dimport_coreinit",
            ".symtab", ".strtab", ".rela.text", ".rela.data", ".shstrtab", ".tbss", ".rela.tbss", ".fexports", ".rela.exports"};
        for(std::size_t i=1;i<parts.size();++i) names[i]=add_string(parts[9].data,labels[i]);
        std::vector<std::byte> b(52+parts.size()*40);
        b[0]=std::byte{0x7f}; b[1]=std::byte{'E'}; b[2]=std::byte{'L'};b[3]=std::byte{'F'};
        b[4]=std::byte{1};b[5]=std::byte{2};b[6]=std::byte{1};b[7]=std::byte{0xca};b[8]=std::byte{0xfe};
        put16(b,16,0xfe01);put16(b,18,20);put32(b,20,1);put32(b,24,0x02000000);
        put32(b,32,52);put16(b,40,52);put16(b,46,40);put16(b,48,14);put16(b,50,9);
        for(std::size_t i=1;i<parts.size();++i) {
            const auto& p=parts[i];const auto at=52+i*40;
            put32(b,at,names[i]);put32(b,at+4,p.type);put32(b,at+8,p.flags);put32(b,at+12,p.addr);
            put32(b,at+16,static_cast<u32>(b.size()));
            put32(b,at+20,p.nobits?p.nobits:static_cast<u32>(p.data.size()));
            put32(b,at+24,p.link);put32(b,at+28,p.info);put32(b,at+32,4);put32(b,at+36,p.entsize);
            b.insert(b.end(),p.data.begin(),p.data.end());
        }
        return b;
    }
};
int failures=0;
void check(bool ok,const char* text) {if(!ok){std::fprintf(stderr,"FAIL: %s\n",text);++failures;}}
u32 word(const Binary& b,addr_t addr) {
    auto bytes=b.bytes_at(addr);return bytes.size()>=4?read_be_at<u32>(bytes.data()):0;
}
}
int main() {
    Fixture fixture;
    auto loaded=ElfBinary::load_from_buffer(fixture.bytes());
    if(!loaded){std::fprintf(stderr,"%s\n",loaded.error().message.c_str());return 1;}
    const auto& b=**loaded;
    const auto* import=b.find_by_name("coreinit!OSBlockMove");
    check(import && import->is_import,"module-qualified function import");
    check(!b.sections()[3].flags.executable && !b.sections()[12].flags.executable,
          "import/export metadata is not scanned as machine code");
    const u32 branch=word(b,0x02000000);
    const u32 stub=0x02000000+(branch&0x03fffffc);
    check((branch&0xfc000003)==0x48000001 && stub!=0x02000000,"branch is relocated without changing opcode/link bit");
    const auto* alias=b.import_at_plt(stub);
    check(alias && alias->name=="coreinit!OSBlockMove","reachable veneer has import identity");
    check(word(b,stub)==0x3d60c000 && word(b,stub+4)==0x616b0008,"veneer points at symbolic import slot");
    check(b.sections().back().file_offset >= b.image().size(), "synthetic veneer has no valid file offset");
    check(!b.import_at_plt(0xc0000010),"import slot lookup does not bleed into next slot");
    check(!b.import_at_plt(0xc0000108),"data import is not callable");
    const auto* data=b.find_by_name("coreinit!MEMDefaultHeap");
    check(data && data->kind==SymbolKind::Object && data->is_import,"data import metadata");
    check(b.bytes_at(0xc0000108).empty(),"module-name bytes must not masquerade as imported global contents");
    check(word(b,0x10000000)==0x10000014,"internal ADDR32 including addend");
    check(word(b,0x10000004)==0xc0000108,"data-import pointer stays symbolic");
    check(word(b,0x10000008)==0xf2000008,"REL32 uses relocation VA as place");
    check(word(b,0x02000004)==0x3c601001 && word(b,0x02000008)==0x38638010,"HA rounding and LO preserve opcodes");
    check(word(b,0x0200000c)==0x3c800001 && word(b,0x02000014)==0x3ca0ffff &&
          word(b,0x02000018)==0x38a5fff6,"GHS relative halfword relocations");
    check(word(b,0x1000000c)==0xdeadbeef,"runtime TLS module index is not guessed");
    check(word(b,0x10000010)==12,"local TLS offset relocation");
    check(word(b,0x10001000)==0x10000010,"BSS relocation has owned zero-filled storage");
    const auto* exported=b.find_by_name("ExportedFn");
    check(exported && exported->is_export && exported->addr==0x02000014,"export table read after relocation");
    check(b.relocations().size()==14,"all relocation records retained");
    std::size_t pending=0;for(const auto& r:b.relocations()) pending+=!r.applied;
    check(pending==2,"TLS module and unknown relocation explicitly unapplied");
    auto disasm=format_disasm_range(b,0x02000000,0x02000004);
    check(disasm && disasm->find("OSBlockMove")!=std::string::npos,"disassembly names relocated import calls");
    auto pseudo=format_struct(b,{0x02000000,0x14,"import_caller"},true,nullptr);
    check(pseudo && pseudo->find("OSBlockMove(")!=std::string::npos &&
          pseudo->find("coreinit!OSBlockMove(")==std::string::npos,
          "pseudo-C renders the relocated import as a callable C identifier");
    Fixture duplicate_export;
    duplicate_export.parts[12].data.resize(24);
    add_string(duplicate_export.parts[12].data,"local_function");
    put32(duplicate_export.parts[13].data,8,0);
    auto duplicate=ElfBinary::load_from_buffer(duplicate_export.bytes());
    check(duplicate && (*duplicate)->find_by_name("local_function") &&
          (*duplicate)->find_by_name("local_function")->is_export,
          "export status survives a duplicate ELF symbol");
    Fixture repeated_import;
    put32(repeated_import.parts[1].data,28,0x48000001);
    auto& extra=repeated_import.parts[7].data;
    const auto at=extra.size();extra.resize(at+12);
    put32(extra,at,0x0200001c);put32(extra,at+4,(1u<<8)|10u);
    auto repeated=ElfBinary::load_from_buffer(repeated_import.bytes());
    check(repeated && (*repeated)->sections().size()==15,
          "repeated imported calls reuse a reachable veneer");
    for(int mode=0;mode<13;++mode) {
        Fixture bad;
        switch(mode) {
            case 0:bad.parts[3].data.resize(7);break;
            case 1:put32(bad.parts[3].data,0,100);break;
            case 2:for(std::size_t i=8;i<bad.parts[3].data.size();++i)bad.parts[3].data[i]=std::byte{'x'};break;
            case 3:put32(bad.parts[5].data,20,0xc0000009);break;
            case 4:bad.parts[7].link=13;break;
            case 5:put32(bad.parts[7].data,4,0xff00000a);break;
            case 6:put32(bad.parts[7].data,0,0x02000020);break;
            case 7:put32(bad.parts[1].data,0,0x60000000);break;
            case 8:put32(bad.parts[12].data,12,0xffffff);break;
            case 9:bad.parts[7].data.pop_back();break;
            case 10:bad.parts[10].nobits=65u*1024u*1024u;break;
            case 11:put32(bad.parts[8].data,3*12+4,(3u<<8)|68u);break;
            case 12:put32(bad.parts[3].data,0,0);break;
        }
        check(!ElfBinary::load_from_buffer(bad.bytes()),"malformed Cafe linkage is rejected");
    }
    return failures?1:0;
}
