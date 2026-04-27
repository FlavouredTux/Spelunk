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
        case Mnemonic::Addi:     return "addi";
        case Mnemonic::Addis:    return "addis";
        case Mnemonic::Ld:       return "ld";
        case Mnemonic::Std:      return "std";
        case Mnemonic::Lwz:      return "lwz";
        case Mnemonic::Stw:      return "stw";
        case Mnemonic::Add:      return "add";
        case Mnemonic::Sub:      return "sub";
        case Mnemonic::Adc:      return "adc";
        case Mnemonic::Sbb:      return "sbb";
        case Mnemonic::Inc:      return "inc";
        case Mnemonic::Dec:      return "dec";
        case Mnemonic::Neg:      return "neg";
        case Mnemonic::Mul:      return "mul";
        case Mnemonic::Imul:     return "imul";
        case Mnemonic::Div:      return "div";
        case Mnemonic::Idiv:     return "idiv";
        case Mnemonic::And:      return "and";
        case Mnemonic::Or:       return "or";
        case Mnemonic::Xor:      return "xor";
        case Mnemonic::Not:      return "not";
        case Mnemonic::Shl:      return "shl";
        case Mnemonic::Shr:      return "shr";
        case Mnemonic::Sar:      return "sar";
        case Mnemonic::Rol:      return "rol";
        case Mnemonic::Ror:      return "ror";
        case Mnemonic::Rcl:      return "rcl";
        case Mnemonic::Rcr:      return "rcr";
        case Mnemonic::Cmp:      return "cmp";
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
        case Mnemonic::Nop:      return "nop";
        case Mnemonic::Hlt:      return "hlt";
        case Mnemonic::Int:      return "int";
        case Mnemonic::Int3:     return "int3";
        case Mnemonic::Syscall:  return "syscall";
        case Mnemonic::Ud2:      return "ud2";
        case Mnemonic::Cdq:      return "cdq";
        case Mnemonic::Cqo:      return "cqo";
        case Mnemonic::Cwde:     return "cwde";
        case Mnemonic::Cdqe:     return "cdqe";
        case Mnemonic::Endbr64:  return "endbr64";
        case Mnemonic::Endbr32:  return "endbr32";

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
        case Mnemonic::Movdqa:       return "movdqa";
        case Mnemonic::MovdqaStore:  return "movdqa";
        case Mnemonic::Movdqu:       return "movdqu";
        case Mnemonic::MovdquStore:  return "movdqu";
        case Mnemonic::MovqXmm:      return "movq";
        case Mnemonic::MovdStore:    return "movd";
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
        case Mnemonic::MovqStore:    return "movq";
        case Mnemonic::Pcmpeqd:      return "pcmpeqd";
        case Mnemonic::Pcmpeqw:      return "pcmpeqw";
        case Mnemonic::Paddq:        return "paddq";
        case Mnemonic::Bsf:          return "bsf";
        case Mnemonic::Bsr:          return "bsr";
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
    }
    return "???";
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
            if (!inside.empty()) inside += " + ";
            inside += reg_name(m.index);
            if (m.scale != 1) {
                inside += std::format("*{}", static_cast<unsigned>(m.scale));
            }
        }
        if (m.disp != 0 || inside.empty()) {
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
    return result;
}

}  // namespace

std::string format_operand(const Instruction& insn, const Operand& op) {
    const addr_t end_addr = insn.address + insn.length;
    switch (op.kind) {
        case Operand::Kind::None:
            return "";
        case Operand::Kind::Register:
            return std::string(reg_name(op.reg));
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
