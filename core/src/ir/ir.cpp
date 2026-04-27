#include <ember/ir/ir.hpp>

#include <format>
#include <string>

namespace ember {

std::string_view op_name(IrOp op) noexcept {
    switch (op) {
        case IrOp::Nop:            return "nop";
        case IrOp::Assign:         return "assign";
        case IrOp::Load:           return "load";
        case IrOp::Store:          return "store";
        case IrOp::Add:            return "add";
        case IrOp::Sub:            return "sub";
        case IrOp::Mul:            return "mul";
        case IrOp::Div:            return "div";
        case IrOp::Mod:            return "mod";
        case IrOp::Select:         return "select";
        case IrOp::And:            return "and";
        case IrOp::Or:             return "or";
        case IrOp::Xor:            return "xor";
        case IrOp::Neg:            return "neg";
        case IrOp::Not:            return "not";
        case IrOp::Shl:            return "shl";
        case IrOp::Lshr:           return "lshr";
        case IrOp::Ashr:           return "ashr";
        case IrOp::CmpEq:          return "cmp.eq";
        case IrOp::CmpNe:          return "cmp.ne";
        case IrOp::CmpUlt:         return "cmp.ult";
        case IrOp::CmpUle:         return "cmp.ule";
        case IrOp::CmpUgt:         return "cmp.ugt";
        case IrOp::CmpUge:         return "cmp.uge";
        case IrOp::CmpSlt:         return "cmp.slt";
        case IrOp::CmpSle:         return "cmp.sle";
        case IrOp::CmpSgt:         return "cmp.sgt";
        case IrOp::CmpSge:         return "cmp.sge";
        case IrOp::ZExt:           return "zext";
        case IrOp::SExt:           return "sext";
        case IrOp::Trunc:          return "trunc";
        case IrOp::AddCarry:       return "add.carry";
        case IrOp::SubBorrow:      return "sub.borrow";
        case IrOp::AddOverflow:    return "add.overflow";
        case IrOp::SubOverflow:    return "sub.overflow";
        case IrOp::Branch:         return "br";
        case IrOp::BranchIndirect: return "br.ind";
        case IrOp::CondBranch:     return "cbr";
        case IrOp::Call:           return "call";
        case IrOp::CallIndirect:   return "call.ind";
        case IrOp::Return:         return "return";
        case IrOp::Unreachable:    return "unreachable";
        case IrOp::Phi:            return "phi";
        case IrOp::Clobber:        return "clobber";
        case IrOp::Intrinsic:      return "intrinsic";
    }
    return "?";
}

std::string format_ir_value(const IrValue& v) {
    switch (v.kind) {
        case IrValueKind::None:
            return "";
        case IrValueKind::Reg:
            if (v.version > 0) {
                return std::format("{}_{}", reg_name(v.reg), v.version);
            }
            return std::string(reg_name(v.reg));
        case IrValueKind::Temp:
            return std::format("t{}", v.temp);
        case IrValueKind::Imm:
            if (v.imm < 0) {
                const u64 abs_v = static_cast<u64>(0) - static_cast<u64>(v.imm);
                return std::format("-{:#x}", abs_v);
            }
            return std::format("{:#x}", static_cast<u64>(v.imm));
        case IrValueKind::Flag:
            if (v.version > 0) {
                return std::format("{}_{}", flag_name(v.flag), v.version);
            }
            return std::string(flag_name(v.flag));
    }
    return "?";
}

namespace {

[[nodiscard]] std::string format_srcs(const IrInst& i, std::size_t start = 0) {
    std::string s;
    for (std::size_t k = start; k < i.src_count; ++k) {
        if (k > start) s += ", ";
        s += format_ir_value(i.srcs[k]);
    }
    return s;
}

[[nodiscard]] std::string_view seg_prefix(Reg seg) noexcept {
    switch (seg) {
        case Reg::Fs: return "fs:";
        case Reg::Gs: return "gs:";
        case Reg::Cs: return "cs:";
        case Reg::Ds: return "ds:";
        case Reg::Es: return "es:";
        case Reg::Ss: return "ss:";
        default:      return "";
    }
}

}  // namespace

std::string format_ir_inst(const IrInst& inst) {
    switch (inst.op) {
        case IrOp::Nop:
            return "nop";

        case IrOp::Assign:
            return std::format("{} = {}", format_ir_value(inst.dst),
                               format_ir_value(inst.srcs[0]));

        case IrOp::Load: {
            const auto addr = format_ir_value(inst.srcs[0]);
            return std::format("{} = load {} {}[{}]",
                               format_ir_value(inst.dst),
                               type_name(inst.dst.type),
                               seg_prefix(inst.segment),
                               addr);
        }

        case IrOp::Store: {
            const auto addr = format_ir_value(inst.srcs[0]);
            const auto val  = format_ir_value(inst.srcs[1]);
            return std::format("store {} {}[{}], {}",
                               type_name(inst.srcs[1].type),
                               seg_prefix(inst.segment),
                               addr, val);
        }

        case IrOp::Neg:
        case IrOp::Not:
        case IrOp::ZExt:
        case IrOp::SExt:
        case IrOp::Trunc:
            return std::format("{} = {} {} {}", format_ir_value(inst.dst),
                               op_name(inst.op), type_name(inst.dst.type),
                               format_ir_value(inst.srcs[0]));

        case IrOp::Branch:
            if (inst.target1 != 0) {
                return std::format("br bb_{:x}", inst.target1);
            }
            return "br <unresolved>";

        case IrOp::BranchIndirect:
            return std::format("br.ind {}", format_ir_value(inst.srcs[0]));

        case IrOp::CondBranch:
            return std::format("cbr {}, bb_{:x}, bb_{:x}",
                               format_ir_value(inst.srcs[0]),
                               inst.target1, inst.target2);

        case IrOp::Call:
            return std::format("call {:#x}", inst.target1);

        case IrOp::CallIndirect:
            return std::format("call.ind {}", format_ir_value(inst.srcs[0]));

        case IrOp::Return: {
            if (inst.src_count == 0) return "return";
            std::string s = "return ";
            for (u8 k = 0; k < inst.src_count && k < inst.srcs.size(); ++k) {
                if (k > 0) s += ", ";
                s += format_ir_value(inst.srcs[k]);
            }
            return s;
        }

        case IrOp::Unreachable:
            return "unreachable";

        case IrOp::Intrinsic: {
            std::string s;
            if (inst.dst.kind != IrValueKind::None) {
                s = std::format("{} = ", format_ir_value(inst.dst));
            }
            s += std::format("intrinsic \"{}\"", inst.name);
            if (inst.src_count > 0) {
                s += "(";
                s += format_srcs(inst);
                s += ")";
            }
            return s;
        }

        case IrOp::Phi: {
            std::string s = std::format("{} = phi {}",
                                        format_ir_value(inst.dst),
                                        type_name(inst.dst.type));
            s += " (";
            for (std::size_t k = 0; k < inst.phi_operands.size(); ++k) {
                if (k > 0) s += ", ";
                addr_t pred = k < inst.phi_preds.size() ? inst.phi_preds[k] : 0;
                s += std::format("bb_{:x}: {}", pred,
                                 format_ir_value(inst.phi_operands[k]));
            }
            s += ")";
            return s;
        }

        case IrOp::Clobber:
            return std::format("{} = clobber  ; call-clobbered",
                               format_ir_value(inst.dst));

        case IrOp::Select:
            return std::format("{} = select {} {}, {}, {}",
                               format_ir_value(inst.dst),
                               type_name(inst.dst.type),
                               format_ir_value(inst.srcs[0]),
                               format_ir_value(inst.srcs[1]),
                               format_ir_value(inst.srcs[2]));

        default:
            // Binary ops and comparisons
            return std::format("{} = {} {} {}, {}",
                               format_ir_value(inst.dst),
                               op_name(inst.op),
                               type_name(inst.dst.type),
                               format_ir_value(inst.srcs[0]),
                               format_ir_value(inst.srcs[1]));
    }
}

std::string format_ir_function(const IrFunction& fn) {
    std::string s;
    s += std::format("function {} @ {:#x}\n",
                     fn.name.empty() ? "<unknown>" : fn.name, fn.start);
    s += std::format("  blocks: {}\n\n", fn.blocks.size());

    for (const auto& bb : fn.blocks) {
        std::string header = std::format("bb_{:x}", bb.start);
        if (bb.start == fn.start) header += "  (entry)";
        if (!bb.predecessors.empty()) {
            header += "  <-";
            for (auto p : bb.predecessors) header += std::format(" bb_{:x}", p);
        }
        s += header + ":\n";

        addr_t last_src = 0;
        for (const auto& inst : bb.insts) {
            if (inst.source_addr != last_src && inst.source_addr != 0) {
                s += std::format("  ; {:#x}\n", inst.source_addr);
                last_src = inst.source_addr;
            }
            s += "  " + format_ir_inst(inst) + "\n";
        }
        s += "\n";
    }
    return s;
}

}  // namespace ember
