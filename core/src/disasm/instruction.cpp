#include <ember/disasm/instruction.hpp>

#include <cstddef>
#include <format>
#include <string>

namespace ember {

std::string_view mnemonic_name(Mnemonic m) noexcept {
    switch (m) {
        case Mnemonic::Invalid:  return "???";
        case Mnemonic::Mov:      return "mov";
        case Mnemonic::Movzx:    return "movzx";
        case Mnemonic::Movsx:    return "movsx";
        case Mnemonic::Movsxd:   return "movsxd";
        case Mnemonic::Lea:      return "lea";
        case Mnemonic::Xchg:     return "xchg";
        case Mnemonic::Push:     return "push";
        case Mnemonic::Pop:      return "pop";
        case Mnemonic::Pushf:    return "pushf";
        case Mnemonic::Popf:     return "popf";
        case Mnemonic::Addi:     return "addi";
        case Mnemonic::Addis:    return "addis";
        case Mnemonic::Ld:       return "ld";
        case Mnemonic::Ldu:      return "ldu";
        case Mnemonic::Lwa:      return "lwa";
        case Mnemonic::Std:      return "std";
        case Mnemonic::Stdu:     return "stdu";
        case Mnemonic::Lwz:      return "lwz";
        case Mnemonic::Stw:      return "stw";
        case Mnemonic::Lbz:      return "lbz";
        case Mnemonic::Stb:      return "stb";
        case Mnemonic::Lhz:      return "lhz";
        case Mnemonic::Sth:      return "sth";
        case Mnemonic::Lha:      return "lha";
        case Mnemonic::Lwzu:     return "lwzu";
        case Mnemonic::Lbzu:     return "lbzu";
        case Mnemonic::Lhzu:     return "lhzu";
        case Mnemonic::Lhau:     return "lhau";
        case Mnemonic::Stwu:     return "stwu";
        case Mnemonic::Stbu:     return "stbu";
        case Mnemonic::Sthu:     return "sthu";
        case Mnemonic::Lmw:      return "lmw";
        case Mnemonic::Stmw:     return "stmw";
        case Mnemonic::Lwzx:     return "lwzx";
        case Mnemonic::Stwx:     return "stwx";
        case Mnemonic::Lbzx:     return "lbzx";
        case Mnemonic::Stbx:     return "stbx";
        case Mnemonic::Lhzx:     return "lhzx";
        case Mnemonic::Sthx:     return "sthx";
        case Mnemonic::Lhax:     return "lhax";
        case Mnemonic::Lwzux:    return "lwzux";
        case Mnemonic::Stwux:    return "stwux";
        case Mnemonic::Lbzux:    return "lbzux";
        case Mnemonic::Stbux:    return "stbux";
        case Mnemonic::Lhzux:    return "lhzux";
        case Mnemonic::Sthux:    return "sthux";
        case Mnemonic::Lhaux:    return "lhaux";
        case Mnemonic::Lfs:      return "lfs";
        case Mnemonic::Lfsu:     return "lfsu";
        case Mnemonic::Lfd:      return "lfd";
        case Mnemonic::Lfdu:     return "lfdu";
        case Mnemonic::Stfs:     return "stfs";
        case Mnemonic::Stfsu:    return "stfsu";
        case Mnemonic::Stfd:     return "stfd";
        case Mnemonic::Stfdu:    return "stfdu";
        case Mnemonic::Lfsx:     return "lfsx";
        case Mnemonic::Lfsux:    return "lfsux";
        case Mnemonic::Lfdx:     return "lfdx";
        case Mnemonic::Lfdux:    return "lfdux";
        case Mnemonic::Stfsx:    return "stfsx";
        case Mnemonic::Stfsux:   return "stfsux";
        case Mnemonic::Stfdx:    return "stfdx";
        case Mnemonic::Stfdux:   return "stfdux";
        case Mnemonic::PsqL:     return "psq_l";
        case Mnemonic::PsqLu:    return "psq_lu";
        case Mnemonic::PsqSt:    return "psq_st";
        case Mnemonic::PsqStu:   return "psq_stu";
        case Mnemonic::PsOp4:    return "ps.op4";
        case Mnemonic::Fadds:    return "fadds";
        case Mnemonic::Fsubs:    return "fsubs";
        case Mnemonic::Fmuls:    return "fmuls";
        case Mnemonic::Fdivs:    return "fdivs";
        case Mnemonic::Fmadds:   return "fmadds";
        case Mnemonic::Fmsubs:   return "fmsubs";
        case Mnemonic::Fnmadds:  return "fnmadds";
        case Mnemonic::Fnmsubs:  return "fnmsubs";
        case Mnemonic::Fadd:     return "fadd";
        case Mnemonic::Fsub:     return "fsub";
        case Mnemonic::Fmul:     return "fmul";
        case Mnemonic::Fdiv:     return "fdiv";
        case Mnemonic::Fmadd:    return "fmadd";
        case Mnemonic::Fmsub:    return "fmsub";
        case Mnemonic::Fnmadd:   return "fnmadd";
        case Mnemonic::Fnmsub:   return "fnmsub";
        case Mnemonic::Fcmpu:    return "fcmpu";
        case Mnemonic::Fcmpo:    return "fcmpo";
        case Mnemonic::Fabs:     return "fabs";
        case Mnemonic::Fmr:      return "fmr";
        case Mnemonic::Fneg:     return "fneg";
        case Mnemonic::Frsp:     return "frsp";
        case Mnemonic::Fctiw:    return "fctiw";
        case Mnemonic::Fctiwz:   return "fctiwz";
        case Mnemonic::FpOp:     return "fp.op";
        case Mnemonic::Mulli:    return "mulli";
        case Mnemonic::Rlwinm:   return "rlwinm";
        case Mnemonic::Rlwimi:   return "rlwimi";
        case Mnemonic::Add:      return "add";
        case Mnemonic::Addc:     return "addc";
        case Mnemonic::Adde:     return "adde";
        case Mnemonic::Sub:      return "sub";
        case Mnemonic::Subfc:    return "subfc";
        case Mnemonic::Adc:      return "adc";
        case Mnemonic::Sbb:      return "sbb";
        case Mnemonic::Inc:      return "inc";
        case Mnemonic::Dec:      return "dec";
        case Mnemonic::Neg:      return "neg";
        case Mnemonic::Mul:      return "mul";
        case Mnemonic::Imul:     return "imul";
        case Mnemonic::Div:      return "div";
        case Mnemonic::Idiv:     return "idiv";
        case Mnemonic::Divw:     return "divw";
        case Mnemonic::Divwu:    return "divwu";
        case Mnemonic::And:      return "and";
        case Mnemonic::Or:       return "or";
        case Mnemonic::Orc:      return "orc";
        case Mnemonic::Xor:      return "xor";
        case Mnemonic::Not:      return "not";
        case Mnemonic::Shl:      return "shl";
        case Mnemonic::Shr:      return "shr";
        case Mnemonic::Sar:      return "sar";
        case Mnemonic::Rol:      return "rol";
        case Mnemonic::Ror:      return "ror";
        case Mnemonic::Rcl:      return "rcl";
        case Mnemonic::Rcr:      return "rcr";
        case Mnemonic::Extsb:    return "extsb";
        case Mnemonic::Extsh:    return "extsh";
        case Mnemonic::Cntlzw:   return "cntlzw";
        case Mnemonic::Crand:    return "crand";
        case Mnemonic::Crandc:   return "crandc";
        case Mnemonic::Creqv:    return "creqv";
        case Mnemonic::Crnand:   return "crnand";
        case Mnemonic::Crnor:    return "crnor";
        case Mnemonic::Cror:     return "cror";
        case Mnemonic::Crorc:    return "crorc";
        case Mnemonic::Crxor:    return "crxor";
        case Mnemonic::Mfcr:     return "mfcr";
        case Mnemonic::Mtcrf:    return "mtcrf";
        case Mnemonic::Mfspr:    return "mfspr";
        case Mnemonic::Mtspr:    return "mtspr";
        case Mnemonic::Mfmsr:    return "mfmsr";
        case Mnemonic::Mtmsr:    return "mtmsr";
        case Mnemonic::Mftb:     return "mftb";
        case Mnemonic::Mulhw:    return "mulhw";
        case Mnemonic::Mulhwu:   return "mulhwu";
        case Mnemonic::Addze:    return "addze";
        case Mnemonic::Subfze:   return "subfze";
        case Mnemonic::Andc:     return "andc";
        case Mnemonic::Nor:      return "nor";
        case Mnemonic::Subfe:    return "subfe";
        case Mnemonic::Cmp:      return "cmp";
        case Mnemonic::Cmpl:     return "cmpl";
        case Mnemonic::Cmn:      return "cmn";
        case Mnemonic::Test:     return "test";
        case Mnemonic::Jmp:      return "jmp";
        case Mnemonic::Call:     return "call";
        case Mnemonic::Ret:      return "ret";
        case Mnemonic::Leave:    return "leave";
        case Mnemonic::Jo:       return "jo";
        case Mnemonic::Jno:      return "jno";
        case Mnemonic::Jb:       return "jb";
        case Mnemonic::Jae:      return "jae";
        case Mnemonic::Je:       return "je";
        case Mnemonic::Jne:      return "jne";
        case Mnemonic::Jbe:      return "jbe";
        case Mnemonic::Ja:       return "ja";
        case Mnemonic::Js:       return "js";
        case Mnemonic::Jns:      return "jns";
        case Mnemonic::Jp:       return "jp";
        case Mnemonic::Jnp:      return "jnp";
        case Mnemonic::Jl:       return "jl";
        case Mnemonic::Jge:      return "jge";
        case Mnemonic::Jle:      return "jle";
        case Mnemonic::Jg:       return "jg";
        case Mnemonic::Beq:      return "beq";
        case Mnemonic::Bne:      return "bne";
        case Mnemonic::Blt:      return "blt";
        case Mnemonic::Bge:      return "bge";
        case Mnemonic::Bgt:      return "bgt";
        case Mnemonic::Ble:      return "ble";
        case Mnemonic::Bdnz:     return "bdnz";
        case Mnemonic::Bdz:      return "bdz";
        case Mnemonic::Bc:       return "bc";
        case Mnemonic::Bclr:     return "bclr";
        case Mnemonic::Nop:      return "nop";
        case Mnemonic::Hlt:      return "hlt";
        case Mnemonic::Int:      return "int";
        case Mnemonic::Int3:     return "int3";
        case Mnemonic::Syscall:  return "syscall";
        case Mnemonic::Ud2:      return "ud2";
        case Mnemonic::Lahf:     return "lahf";
        case Mnemonic::Sahf:     return "sahf";
        case Mnemonic::Cmc:      return "cmc";
        case Mnemonic::Clc:      return "clc";
        case Mnemonic::Stc:      return "stc";
        case Mnemonic::Cli:      return "cli";
        case Mnemonic::Sti:      return "sti";
        case Mnemonic::Cld:      return "cld";
        case Mnemonic::StdDir:   return "std";
        case Mnemonic::Isync:    return "isync";
        case Mnemonic::Sync:     return "sync";
        case Mnemonic::Rfi:      return "rfi";
        case Mnemonic::Sc:       return "sc";
        case Mnemonic::Twi:      return "twi";
        case Mnemonic::Dcbf:     return "dcbf";
        case Mnemonic::Dcbst:    return "dcbst";
        case Mnemonic::Dcbi:     return "dcbi";
        case Mnemonic::Dcbz:     return "dcbz";
        case Mnemonic::Icbi:     return "icbi";
        case Mnemonic::Cdq:      return "cdq";
        case Mnemonic::Cqo:      return "cqo";
        case Mnemonic::Cwde:     return "cwde";
        case Mnemonic::Cdqe:     return "cdqe";
        case Mnemonic::Endbr64:  return "endbr64";
        case Mnemonic::Endbr32:  return "endbr32";
        case Mnemonic::Cpuid:    return "cpuid";
        case Mnemonic::Rdtsc:    return "rdtsc";
        case Mnemonic::Rdtscp:   return "rdtscp";
        case Mnemonic::Rdmsr:    return "rdmsr";
        case Mnemonic::Wrmsr:    return "wrmsr";
        case Mnemonic::Rdpmc:    return "rdpmc";
        case Mnemonic::Pause:    return "pause";

        case Mnemonic::Seto:   return "seto";
        case Mnemonic::Setno:  return "setno";
        case Mnemonic::Setb:   return "setb";
        case Mnemonic::Setae:  return "setae";
        case Mnemonic::Sete:   return "sete";
        case Mnemonic::Setne:  return "setne";
        case Mnemonic::Setbe:  return "setbe";
        case Mnemonic::Seta:   return "seta";
        case Mnemonic::Sets:   return "sets";
        case Mnemonic::Setns:  return "setns";
        case Mnemonic::Setp:   return "setp";
        case Mnemonic::Setnp:  return "setnp";
        case Mnemonic::Setl:   return "setl";
        case Mnemonic::Setge:  return "setge";
        case Mnemonic::Setle:  return "setle";
        case Mnemonic::Setg:   return "setg";

        case Mnemonic::Cmovo:  return "cmovo";
        case Mnemonic::Cmovno: return "cmovno";
        case Mnemonic::Cmovb:  return "cmovb";
        case Mnemonic::Cmovae: return "cmovae";
        case Mnemonic::Cmove:  return "cmove";
        case Mnemonic::Cmovne: return "cmovne";
        case Mnemonic::Cmovbe: return "cmovbe";
        case Mnemonic::Cmova:  return "cmova";
        case Mnemonic::Cmovs:  return "cmovs";
        case Mnemonic::Cmovns: return "cmovns";
        case Mnemonic::Cmovp:  return "cmovp";
        case Mnemonic::Cmovnp: return "cmovnp";
        case Mnemonic::Cmovl:  return "cmovl";
        case Mnemonic::Cmovge: return "cmovge";
        case Mnemonic::Cmovle: return "cmovle";
        case Mnemonic::Cmovg:  return "cmovg";

        case Mnemonic::Movsb:  return "movsb";
        case Mnemonic::Movsd:  return "movsd";
        case Mnemonic::Movsq:  return "movsq";
        case Mnemonic::Cmpsb:  return "cmpsb";
        case Mnemonic::Cmpsd:  return "cmpsd";
        case Mnemonic::Cmpsq:  return "cmpsq";
        case Mnemonic::Stosb:  return "stosb";
        case Mnemonic::Stosd:  return "stosd";
        case Mnemonic::Stosq:  return "stosq";
        case Mnemonic::Lodsb:  return "lodsb";
        case Mnemonic::Lodsd:  return "lodsd";
        case Mnemonic::Lodsq:  return "lodsq";
        case Mnemonic::Scasb:  return "scasb";
        case Mnemonic::Scasd:  return "scasd";
        case Mnemonic::Scasq:  return "scasq";

        case Mnemonic::Bt:       return "bt";
        case Mnemonic::Bts:      return "bts";
        case Mnemonic::Btr:      return "btr";
        case Mnemonic::Btc:      return "btc";
        case Mnemonic::Bswap:    return "bswap";
        case Mnemonic::Cmpxchg:  return "cmpxchg";
        case Mnemonic::Xadd:     return "xadd";

        case Mnemonic::Movd:         return "movd";
        case Mnemonic::MovqGpr:      return "movq";
        case Mnemonic::Movdqa:       return "movdqa";
        case Mnemonic::MovdqaStore:  return "movdqa";
        case Mnemonic::Movdqu:       return "movdqu";
        case Mnemonic::MovdquStore:  return "movdqu";
        case Mnemonic::MovqXmm:      return "movq";
        case Mnemonic::MovdStore:    return "movd";
        case Mnemonic::MovqGprStore: return "movq";
        case Mnemonic::Pxor:         return "pxor";
        case Mnemonic::Pand:         return "pand";
        case Mnemonic::Pandn:        return "pandn";
        case Mnemonic::Por:          return "por";
        case Mnemonic::Pcmpeqb:      return "pcmpeqb";
        case Mnemonic::Pminub:       return "pminub";
        case Mnemonic::Pmovmskb:     return "pmovmskb";
        case Mnemonic::Movups:       return "movups";
        case Mnemonic::MovupsStore:  return "movups";
        case Mnemonic::Movaps:       return "movaps";
        case Mnemonic::MovapsStore:  return "movaps";
        case Mnemonic::Movhps:       return "movhps";
        case Mnemonic::Movlps:       return "movlps";
        case Mnemonic::Andps:        return "andps";
        case Mnemonic::Andnps:       return "andnps";
        case Mnemonic::Orps:         return "orps";
        case Mnemonic::Xorps:        return "xorps";
        case Mnemonic::Addps:        return "addps";
        case Mnemonic::Mulps:        return "mulps";
        case Mnemonic::Subps:        return "subps";
        case Mnemonic::Divps:        return "divps";
        case Mnemonic::Andpd:        return "andpd";
        case Mnemonic::Andnpd:       return "andnpd";
        case Mnemonic::Orpd:         return "orpd";
        case Mnemonic::Xorpd:        return "xorpd";
        case Mnemonic::Addpd:        return "addpd";
        case Mnemonic::Mulpd:        return "mulpd";
        case Mnemonic::Subpd:        return "subpd";
        case Mnemonic::Divpd:        return "divpd";
        case Mnemonic::Punpcklbw:    return "punpcklbw";
        case Mnemonic::Punpcklwd:    return "punpcklwd";
        case Mnemonic::Punpckldq:    return "punpckldq";
        case Mnemonic::Punpcklqdq:   return "punpcklqdq";
        case Mnemonic::Punpckhqdq:   return "punpckhqdq";
        case Mnemonic::Pshufd:       return "pshufd";
        case Mnemonic::Pshuflw:      return "pshuflw";
        case Mnemonic::Pshufhw:      return "pshufhw";
        case Mnemonic::MovqStore:    return "movq";
        case Mnemonic::Pcmpeqd:      return "pcmpeqd";
        case Mnemonic::Pcmpeqw:      return "pcmpeqw";
        case Mnemonic::Paddb:        return "paddb";
        case Mnemonic::Paddw:        return "paddw";
        case Mnemonic::Paddd:        return "paddd";
        case Mnemonic::Paddq:        return "paddq";
        case Mnemonic::Psubb:        return "psubb";
        case Mnemonic::Psubw:        return "psubw";
        case Mnemonic::Psubd:        return "psubd";
        case Mnemonic::Psubq:        return "psubq";
        case Mnemonic::Pmullw:       return "pmullw";
        case Mnemonic::Pmulhw:       return "pmulhw";
        case Mnemonic::Pmulhuw:      return "pmulhuw";
        case Mnemonic::Pmuludq:      return "pmuludq";
        case Mnemonic::Pmaddwd:      return "pmaddwd";
        case Mnemonic::Psubusb:      return "psubusb";
        case Mnemonic::Psubusw:      return "psubusw";
        case Mnemonic::Paddusb:      return "paddusb";
        case Mnemonic::Paddusw:      return "paddusw";
        case Mnemonic::Psubsb:       return "psubsb";
        case Mnemonic::Psubsw:       return "psubsw";
        case Mnemonic::Paddsb:       return "paddsb";
        case Mnemonic::Paddsw:       return "paddsw";
        case Mnemonic::Pmaxub:       return "pmaxub";
        case Mnemonic::Pminsw:       return "pminsw";
        case Mnemonic::Pmaxsw:       return "pmaxsw";
        case Mnemonic::Pavgb:        return "pavgb";
        case Mnemonic::Pavgw:        return "pavgw";
        case Mnemonic::Pcmpgtb:      return "pcmpgtb";
        case Mnemonic::Pcmpgtw:      return "pcmpgtw";
        case Mnemonic::Pcmpgtd:      return "pcmpgtd";
        case Mnemonic::Punpckhbw:    return "punpckhbw";
        case Mnemonic::Punpckhwd:    return "punpckhwd";
        case Mnemonic::Punpckhdq:    return "punpckhdq";
        case Mnemonic::Shufps:       return "shufps";
        case Mnemonic::Shufpd:       return "shufpd";
        case Mnemonic::Pextrw:       return "pextrw";
        case Mnemonic::Psllw:        return "psllw";
        case Mnemonic::Pslld:        return "pslld";
        case Mnemonic::Psllq:        return "psllq";
        case Mnemonic::Pslldq:       return "pslldq";
        case Mnemonic::Psrlw:        return "psrlw";
        case Mnemonic::Psrld:        return "psrld";
        case Mnemonic::Psrlq:        return "psrlq";
        case Mnemonic::Psrldq:       return "psrldq";
        case Mnemonic::Psraw:        return "psraw";
        case Mnemonic::Psrad:        return "psrad";
        case Mnemonic::Pinsrw:       return "pinsrw";
        case Mnemonic::Bsf:          return "bsf";
        case Mnemonic::Bsr:          return "bsr";
        case Mnemonic::Popcnt:       return "popcnt";
        case Mnemonic::Shld:         return "shld";
        case Mnemonic::Shrd:         return "shrd";

        case Mnemonic::MovssLoad:     return "movss";
        case Mnemonic::MovssStore:    return "movss";
        case Mnemonic::Addss:         return "addss";
        case Mnemonic::Subss:         return "subss";
        case Mnemonic::Mulss:         return "mulss";
        case Mnemonic::Divss:         return "divss";
        case Mnemonic::Sqrtss:        return "sqrtss";
        case Mnemonic::Minss:         return "minss";
        case Mnemonic::Maxss:         return "maxss";
        case Mnemonic::Cvtsi2ss:      return "cvtsi2ss";
        case Mnemonic::Cvttss2si:     return "cvttss2si";
        case Mnemonic::Cvtss2sd:      return "cvtss2sd";
        case Mnemonic::Ucomiss:       return "ucomiss";
        case Mnemonic::Comiss:        return "comiss";

        case Mnemonic::MovsdXmm:      return "movsd";
        case Mnemonic::MovsdXmmStore: return "movsd";
        case Mnemonic::Addsd:         return "addsd";
        case Mnemonic::Subsd:         return "subsd";
        case Mnemonic::Mulsd:         return "mulsd";
        case Mnemonic::Divsd:         return "divsd";
        case Mnemonic::Sqrtsd:        return "sqrtsd";
        case Mnemonic::Minsd:         return "minsd";
        case Mnemonic::Maxsd:         return "maxsd";
        case Mnemonic::Cvtsi2sd:      return "cvtsi2sd";
        case Mnemonic::Cvttsd2si:     return "cvttsd2si";
        case Mnemonic::Cvtsd2ss:      return "cvtsd2ss";
        case Mnemonic::Ucomisd:       return "ucomisd";
        case Mnemonic::Comisd:        return "comisd";

        case Mnemonic::Minps:         return "minps";
        case Mnemonic::Maxps:         return "maxps";
        case Mnemonic::Minpd:         return "minpd";
        case Mnemonic::Maxpd:         return "maxpd";

        // ---- AArch64 ----------------------------------------------------
        case Mnemonic::A64Add:    return "add";
        case Mnemonic::A64Sub:    return "sub";
        case Mnemonic::A64Adds:   return "adds";
        case Mnemonic::A64Subs:   return "subs";
        case Mnemonic::A64And:    return "and";
        case Mnemonic::A64Orr:    return "orr";
        case Mnemonic::A64Eor:    return "eor";
        case Mnemonic::A64Bic:    return "bic";
        case Mnemonic::A64Orn:    return "orn";
        case Mnemonic::A64Eon:    return "eon";
        case Mnemonic::A64Ands:   return "ands";
        case Mnemonic::A64Bics:   return "bics";
        case Mnemonic::A64Mul:    return "mul";
        case Mnemonic::A64Madd:   return "madd";
        case Mnemonic::A64Msub:   return "msub";
        case Mnemonic::A64Smaddl: return "smaddl";
        case Mnemonic::A64Umaddl: return "umaddl";
        case Mnemonic::A64Smsubl: return "smsubl";
        case Mnemonic::A64Umsubl: return "umsubl";
        case Mnemonic::A64Smulh:  return "smulh";
        case Mnemonic::A64Umulh:  return "umulh";
        case Mnemonic::A64Sdiv:   return "sdiv";
        case Mnemonic::A64Udiv:   return "udiv";
        case Mnemonic::A64Lsl:    return "lsl";
        case Mnemonic::A64Lsr:    return "lsr";
        case Mnemonic::A64Asr:    return "asr";
        case Mnemonic::A64Ror:    return "ror";
        case Mnemonic::A64Lslv:   return "lslv";
        case Mnemonic::A64Lsrv:   return "lsrv";
        case Mnemonic::A64Asrv:   return "asrv";
        case Mnemonic::A64Rorv:   return "rorv";
        case Mnemonic::A64Mov:    return "mov";
        case Mnemonic::A64Movz:   return "movz";
        case Mnemonic::A64Movn:   return "movn";
        case Mnemonic::A64Movk:   return "movk";
        case Mnemonic::A64Mvn:    return "mvn";
        case Mnemonic::A64Neg:    return "neg";
        case Mnemonic::A64Negs:   return "negs";
        case Mnemonic::A64Adr:    return "adr";
        case Mnemonic::A64Adrp:   return "adrp";
        case Mnemonic::A64Sbfm:   return "sbfm";
        case Mnemonic::A64Ubfm:   return "ubfm";
        case Mnemonic::A64Bfm:    return "bfm";
        case Mnemonic::A64Sxtb:   return "sxtb";
        case Mnemonic::A64Sxth:   return "sxth";
        case Mnemonic::A64Sxtw:   return "sxtw";
        case Mnemonic::A64Uxtb:   return "uxtb";
        case Mnemonic::A64Uxth:   return "uxth";
        case Mnemonic::A64Uxtw:   return "uxtw";
        case Mnemonic::A64Clz:    return "clz";
        case Mnemonic::A64Cls:    return "cls";
        case Mnemonic::A64Rbit:   return "rbit";
        case Mnemonic::A64Rev:    return "rev";
        case Mnemonic::A64Rev16:  return "rev16";
        case Mnemonic::A64Rev32:  return "rev32";
        case Mnemonic::A64Csel:   return "csel";
        case Mnemonic::A64Csinc:  return "csinc";
        case Mnemonic::A64Csinv:  return "csinv";
        case Mnemonic::A64Csneg:  return "csneg";
        case Mnemonic::A64Cset:   return "cset";
        case Mnemonic::A64Csetm:  return "csetm";
        case Mnemonic::A64Cinc:   return "cinc";
        case Mnemonic::A64Cinv:   return "cinv";
        case Mnemonic::A64Cneg:   return "cneg";
        case Mnemonic::A64Ccmp:   return "ccmp";
        case Mnemonic::A64Ccmn:   return "ccmn";
        case Mnemonic::A64Ldr:    return "ldr";
        case Mnemonic::A64Str:    return "str";
        case Mnemonic::A64Ldrb:   return "ldrb";
        case Mnemonic::A64Strb:   return "strb";
        case Mnemonic::A64Ldrh:   return "ldrh";
        case Mnemonic::A64Strh:   return "strh";
        case Mnemonic::A64Ldrsb:  return "ldrsb";
        case Mnemonic::A64Ldrsh:  return "ldrsh";
        case Mnemonic::A64Ldrsw:  return "ldrsw";
        case Mnemonic::A64Ldur:   return "ldur";
        case Mnemonic::A64Stur:   return "stur";
        case Mnemonic::A64Ldurb:  return "ldurb";
        case Mnemonic::A64Sturb:  return "sturb";
        case Mnemonic::A64Ldurh:  return "ldurh";
        case Mnemonic::A64Sturh:  return "sturh";
        case Mnemonic::A64Ldursb: return "ldursb";
        case Mnemonic::A64Ldursh: return "ldursh";
        case Mnemonic::A64Ldursw: return "ldursw";
        case Mnemonic::A64Ldp:    return "ldp";
        case Mnemonic::A64Stp:    return "stp";
        case Mnemonic::A64Ldpsw:  return "ldpsw";
        case Mnemonic::A64B:      return "b";
        case Mnemonic::A64Bl:     return "bl";
        case Mnemonic::A64Br:     return "br";
        case Mnemonic::A64Blr:    return "blr";
        case Mnemonic::A64Ret:    return "ret";
        case Mnemonic::A64Bcc:    return "b.cc";
        case Mnemonic::A64Cbz:    return "cbz";
        case Mnemonic::A64Cbnz:   return "cbnz";
        case Mnemonic::A64Tbz:    return "tbz";
        case Mnemonic::A64Tbnz:   return "tbnz";
        case Mnemonic::A64Nop:    return "nop";
        case Mnemonic::A64Brk:    return "brk";
        case Mnemonic::A64Svc:    return "svc";
        case Mnemonic::A64Hint:   return "hint";
        case Mnemonic::A64Hvc:    return "hvc";
        case Mnemonic::A64Smc:    return "smc";
        case Mnemonic::A64Udf:    return "udf";
        case Mnemonic::A64Eret:   return "eret";
        case Mnemonic::A64Drps:   return "drps";
        case Mnemonic::A64Mrs:    return "mrs";
        case Mnemonic::A64Msr:    return "msr";
        case Mnemonic::A64Dmb:    return "dmb";
        case Mnemonic::A64Dsb:    return "dsb";
        case Mnemonic::A64Isb:    return "isb";
        case Mnemonic::A64Sev:    return "sev";
        case Mnemonic::A64Wfe:    return "wfe";
        case Mnemonic::A64Wfi:    return "wfi";
        case Mnemonic::A64Yield:  return "yield";

        case Mnemonic::A32And:   return "and";
        case Mnemonic::A32Eor:   return "eor";
        case Mnemonic::A32Sub:   return "sub";
        case Mnemonic::A32Rsb:   return "rsb";
        case Mnemonic::A32Add:   return "add";
        case Mnemonic::A32Adc:   return "adc";
        case Mnemonic::A32Sbc:   return "sbc";
        case Mnemonic::A32Rsc:   return "rsc";
        case Mnemonic::A32Tst:   return "tst";
        case Mnemonic::A32Teq:   return "teq";
        case Mnemonic::A32Cmp:   return "cmp";
        case Mnemonic::A32Cmn:   return "cmn";
        case Mnemonic::A32Orr:   return "orr";
        case Mnemonic::A32Mov:   return "mov";
        case Mnemonic::A32Bic:   return "bic";
        case Mnemonic::A32Mvn:   return "mvn";
        case Mnemonic::A32Lsl:   return "lsl";
        case Mnemonic::A32Lsr:   return "lsr";
        case Mnemonic::A32Asr:   return "asr";
        case Mnemonic::A32Ror:   return "ror";
        case Mnemonic::A32Rrx:   return "rrx";
        case Mnemonic::A32Movw:  return "movw";
        case Mnemonic::A32Movt:  return "movt";
        case Mnemonic::A32Mul:   return "mul";
        case Mnemonic::A32Mla:   return "mla";
        case Mnemonic::A32Mls:   return "mls";
        case Mnemonic::A32Umull: return "umull";
        case Mnemonic::A32Umlal: return "umlal";
        case Mnemonic::A32Smull: return "smull";
        case Mnemonic::A32Smlal: return "smlal";
        case Mnemonic::A32Udiv:  return "udiv";
        case Mnemonic::A32Sdiv:  return "sdiv";
        case Mnemonic::A32Clz:   return "clz";
        case Mnemonic::A32Sxtb:  return "sxtb";
        case Mnemonic::A32Sxth:  return "sxth";
        case Mnemonic::A32Uxtb:  return "uxtb";
        case Mnemonic::A32Uxth:  return "uxth";
        case Mnemonic::A32Rev:   return "rev";
        case Mnemonic::A32Rev16: return "rev16";
        case Mnemonic::A32Ldr:   return "ldr";
        case Mnemonic::A32Str:   return "str";
        case Mnemonic::A32Ldrb:  return "ldrb";
        case Mnemonic::A32Strb:  return "strb";
        case Mnemonic::A32Ldrh:  return "ldrh";
        case Mnemonic::A32Strh:  return "strh";
        case Mnemonic::A32Ldrsb: return "ldrsb";
        case Mnemonic::A32Ldrsh: return "ldrsh";
        case Mnemonic::A32Ldrd:  return "ldrd";
        case Mnemonic::A32Strd:  return "strd";
        case Mnemonic::A32Ldm:   return "ldm";
        case Mnemonic::A32LdmPc: return "ldm";
        case Mnemonic::A32Stm:   return "stm";
        case Mnemonic::A32Push:  return "push";
        case Mnemonic::A32Pop:   return "pop";
        case Mnemonic::A32B:     return "b";
        case Mnemonic::A32Bl:    return "bl";
        case Mnemonic::A32Bx:    return "bx";
        case Mnemonic::A32Blx:   return "blx";
        case Mnemonic::A32Bcc:   return "b";
        case Mnemonic::A32Ret:   return "ret";
        case Mnemonic::A32Svc:   return "svc";
        case Mnemonic::A32Bkpt:  return "bkpt";
        case Mnemonic::A32Nop:   return "nop";
        case Mnemonic::A32Udf:   return "udf";
        case Mnemonic::A32Undef: return ".word";
    }
    return "???";
}

// ARM condition-code suffix (bits 31:28). AL/NV render empty - callers gate
// on that via kArmCondAL.
[[nodiscard]] std::string_view arm_cond_suffix(u8 cond) noexcept {
    switch (cond & 0xf) {
        case 0x0: return "eq"; case 0x1: return "ne";
        case 0x2: return "cs"; case 0x3: return "cc";
        case 0x4: return "mi"; case 0x5: return "pl";
        case 0x6: return "vs"; case 0x7: return "vc";
        case 0x8: return "hi"; case 0x9: return "ls";
        case 0xa: return "ge"; case 0xb: return "lt";
        case 0xc: return "gt"; case 0xd: return "le";
        default:  return "";   // AL / NV
    }
}

namespace {

[[nodiscard]] std::string_view size_keyword(u8 size) noexcept {
    switch (size) {
        case 1: return "byte ptr ";
        case 2: return "word ptr ";
        case 4: return "dword ptr ";
        case 8: return "qword ptr ";
        default: return "";
    }
}

[[nodiscard]] std::string format_imm_value(const Imm& i) {
    if (i.is_signed && i.value < 0) {
        const u64 abs_v = static_cast<u64>(0) - static_cast<u64>(i.value);
        return std::format("-{:#x}", abs_v);
    }
    return std::format("{:#x}", static_cast<u64>(i.value));
}

[[nodiscard]] std::string format_mem(const Mem& m, bool suppress_size, addr_t end_addr) {
    std::string result;
    if (!suppress_size) {
        result = size_keyword(m.size);
    }
    if (m.segment != Reg::None) {
        result += std::format("{}:", reg_name(m.segment));
    }
    result += "[";

    if (m.base == Reg::Rip && m.index == Reg::None) {
        const u64 target = end_addr + static_cast<u64>(m.disp);
        result += std::format("{:#x}", target);
    } else {
        std::string inside;
        if (m.base != Reg::None) {
            inside += reg_name(m.base);
        }
        if (m.index != Reg::None) {
            if (!inside.empty()) inside += m.subtract_index ? " - " : " + ";
            else if (m.subtract_index) inside += "-";
            inside += reg_name(m.index);
            if (m.scale != 1) {
                inside += std::format("*{}", static_cast<unsigned>(m.scale));
            }
        }
        if (m.writeback != Mem::Writeback::PostIndex &&
            (m.disp != 0 || inside.empty())) {
            if (!inside.empty()) {
                if (m.disp < 0) {
                    const u64 abs_v = static_cast<u64>(0) - static_cast<u64>(m.disp);
                    inside += std::format(" - {:#x}", abs_v);
                } else {
                    inside += std::format(" + {:#x}", static_cast<u64>(m.disp));
                }
            } else {
                if (m.disp < 0) {
                    const u64 abs_v = static_cast<u64>(0) - static_cast<u64>(m.disp);
                    inside += std::format("-{:#x}", abs_v);
                } else {
                    inside += std::format("{:#x}", static_cast<u64>(m.disp));
                }
            }
        }
        result += inside;
    }

    result += "]";
    if (m.writeback == Mem::Writeback::PreIndex) {
        result += "!";
    } else if (m.writeback == Mem::Writeback::PostIndex) {
        result += std::format(", #{}", m.disp);
    }
    return result;
}

}  // namespace

std::string format_operand(const Instruction& insn, const Operand& op) {
    const addr_t end_addr = insn.address + insn.length;
    switch (op.kind) {
        case Operand::Kind::None:
            return "";
        case Operand::Kind::Register: {
            std::string r(reg_name(op.reg));
            // ARM barrel shift on the register operand.
            if (op.arm_shift_reg != Reg::None) {
                static constexpr std::string_view kShift[4] =
                    {"lsl", "lsr", "asr", "ror"};
                r += std::format(", {} {}",
                                 kShift[static_cast<u8>(op.arm_shift)],
                                 reg_name(op.arm_shift_reg));
            } else if (!(op.arm_shift == ArmShift::Lsl && op.arm_shift_amt == 0)) {
                static constexpr std::string_view kShift[4] =
                    {"lsl", "lsr", "asr", "ror"};
                const bool is_a32 =
                    static_cast<u16>(insn.mnemonic) >=
                    static_cast<u16>(Mnemonic::A32And);
                if (is_a32 && op.arm_shift == ArmShift::Ror &&
                    op.arm_shift_amt == 0) {
                    r += ", rrx";
                } else {
                    r += std::format(", {} #{}",
                                     kShift[static_cast<u8>(op.arm_shift)],
                                     op.arm_shift_amt);
                }
            }
            return r;
        }
        case Operand::Kind::Memory:
            return format_mem(op.mem, insn.mnemonic == Mnemonic::Lea, end_addr);
        case Operand::Kind::Immediate:
            return format_imm_value(op.imm);
        case Operand::Kind::Relative:
            return std::format("{:#x}", op.rel.target);
    }
    return "";
}

std::string format_instruction(const Instruction& insn) {
    std::string s;
    if (insn.prefixes.lock)  s += "lock ";
    if (insn.prefixes.rep)   s += "rep ";
    if (insn.prefixes.repne) s += "repne ";
    s += mnemonic_name(insn.mnemonic);
    // ARM: append the S (flag-setting) suffix and the condition-code suffix.
    // Both are inert for other architectures (arm_setflags defaults false,
    // arm_cond defaults to AL).
    if (insn.arm_cond != kArmCondAL && insn.arm_cond != 0xF) {
        s += arm_cond_suffix(insn.arm_cond);
    }
    if (insn.arm_setflags) s += 's';
    // ARM block transfers carry (base, reglist-bitmask, flags); render the
    // list as `{r4, r5, lr}` rather than the raw operands.
    const bool is_block_xfer =
        insn.mnemonic == Mnemonic::A32Push || insn.mnemonic == Mnemonic::A32Pop ||
        insn.mnemonic == Mnemonic::A32Ldm  || insn.mnemonic == Mnemonic::A32LdmPc ||
        insn.mnemonic == Mnemonic::A32Stm ||
        // A returning LDM (`pop {.., pc}` / `ldm rN, {.., pc}`) decodes to
        // A32Ret but still carries the (base, reglist, flags) operand shape.
        (insn.mnemonic == Mnemonic::A32Ret && insn.num_operands >= 2 &&
         insn.operands[1].kind == Operand::Kind::Immediate);
    if (is_block_xfer) {
            const bool has_base = insn.mnemonic == Mnemonic::A32Ldm ||
                                  insn.mnemonic == Mnemonic::A32LdmPc ||
                                  insn.mnemonic == Mnemonic::A32Stm;
            const u32 list = insn.num_operands >= 2
                ? static_cast<u32>(insn.operands[1].imm.value) : 0;
            s += ' ';
            if (has_base && insn.num_operands >= 1) {
                s += reg_name(insn.operands[0].reg);
                s += ", ";
            }
            s += '{';
            bool first = true;
            for (unsigned r = 0; r < 16; ++r) {
                if (!(list & (1u << r))) continue;
                if (!first) s += ", ";
                s += reg_name(r < 13 ? static_cast<Reg>(
                                  static_cast<unsigned>(Reg::ArmR0) + r)
                              : r == 13 ? Reg::Asp
                              : r == 14 ? Reg::Alr : Reg::Apc);
                first = false;
            }
            s += '}';
            return s;
    }
    if (insn.num_operands > 0) {
        s += ' ';
        for (std::size_t i = 0; i < insn.num_operands; ++i) {
            if (i > 0) s += ", ";
            s += format_operand(insn, insn.operands[i]);
        }
    }
    return s;
}

}  // namespace ember
