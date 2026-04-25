#include <ember/analysis/type_infer_local.hpp>

#include <ember/ir/types.hpp>

namespace ember {

namespace {

// Refine the type of `v` by meeting `t` into the existing entry. Returns
// true if anything changed (drives the fixpoint loop).
[[nodiscard]] bool refine(IrFunction& fn, const IrValue& v, TypeRef t) {
    const u64 k = value_type_key(v);
    if (k == 0) return false;
    auto it = fn.value_types.find(k);
    if (it == fn.value_types.end()) {
        if (t.is_top()) return false;
        fn.value_types.emplace(k, t);
        return true;
    }
    const TypeRef merged = fn.types.meet(it->second, t);
    if (merged == it->second) return false;
    it->second = merged;
    return true;
}

[[nodiscard]] TypeRef int_for(TypeArena& a, IrType t) {
    switch (t) {
        case IrType::I1:  return a.int_t(1);
        case IrType::I8:  return a.int_t(8);
        case IrType::I16: return a.int_t(16);
        case IrType::I32: return a.int_t(32);
        case IrType::I64: return a.int_t(64);
        default:          return a.top();
    }
}

[[nodiscard]] bool is_pointer(const IrFunction& fn, const IrValue& v) {
    return fn.types.kind(fn.type_of(v)) == TypeKind::Ptr;
}

bool sweep(IrFunction& fn) {
    bool changed = false;
    auto& a = fn.types;

    for (auto& bb : fn.blocks) {
        for (auto& inst : bb.insts) {
            switch (inst.op) {
                case IrOp::Load: {
                    if (inst.src_count >= 1) {
                        const TypeRef pointee = int_for(a, inst.dst.type);
                        changed |= refine(fn, inst.srcs[0], a.ptr_t(pointee));
                    }
                    break;
                }

                case IrOp::Store: {
                    if (inst.src_count >= 2) {
                        const TypeRef pointee = int_for(a, inst.srcs[1].type);
                        changed |= refine(fn, inst.srcs[0], a.ptr_t(pointee));
                    }
                    break;
                }

                case IrOp::SExt:
                    changed |= refine(fn, inst.dst,
                                      a.int_t(static_cast<u8>(type_bits(inst.dst.type)),
                                              true, true));
                    break;

                case IrOp::ZExt:
                    changed |= refine(fn, inst.dst,
                                      a.int_t(static_cast<u8>(type_bits(inst.dst.type)),
                                              true, false));
                    break;

                case IrOp::Ashr:
                    if (inst.src_count >= 1) {
                        changed |= refine(fn, inst.srcs[0],
                                          a.int_t(static_cast<u8>(type_bits(inst.srcs[0].type)),
                                                  true, true));
                    }
                    break;

                case IrOp::Lshr:
                    if (inst.src_count >= 1) {
                        changed |= refine(fn, inst.srcs[0],
                                          a.int_t(static_cast<u8>(type_bits(inst.srcs[0].type)),
                                                  true, false));
                    }
                    break;

                case IrOp::CmpSlt:
                case IrOp::CmpSle:
                case IrOp::CmpSgt:
                case IrOp::CmpSge: {
                    for (u8 i = 0; i < inst.src_count && i < 2; ++i) {
                        changed |= refine(fn, inst.srcs[i],
                                          a.int_t(static_cast<u8>(type_bits(inst.srcs[i].type)),
                                                  true, true));
                    }
                    break;
                }

                case IrOp::CmpUlt:
                case IrOp::CmpUle:
                case IrOp::CmpUgt:
                case IrOp::CmpUge: {
                    // Weaker signal — pointer compares often use the
                    // unsigned forms. Only mark when source isn't already
                    // refined to something that would conflict.
                    for (u8 i = 0; i < inst.src_count && i < 2; ++i) {
                        if (is_pointer(fn, inst.srcs[i])) continue;
                        changed |= refine(fn, inst.srcs[i],
                                          a.int_t(static_cast<u8>(type_bits(inst.srcs[i].type)),
                                                  true, false));
                    }
                    break;
                }

                case IrOp::Assign:
                case IrOp::Phi: {
                    // Propagate any concrete operand type onto dst, and
                    // any concrete dst type back onto operands.
                    auto propagate = [&](const IrValue& src) {
                        const TypeRef st = fn.type_of(src);
                        if (!st.is_top()) {
                            changed |= refine(fn, inst.dst, st);
                        }
                    };
                    if (inst.op == IrOp::Phi) {
                        for (const auto& op : inst.phi_operands) propagate(op);
                    } else {
                        for (u8 i = 0; i < inst.src_count; ++i) propagate(inst.srcs[i]);
                    }
                    const TypeRef dt = fn.type_of(inst.dst);
                    if (!dt.is_top()) {
                        if (inst.op == IrOp::Phi) {
                            for (const auto& op : inst.phi_operands) {
                                changed |= refine(fn, op, dt);
                            }
                        } else {
                            for (u8 i = 0; i < inst.src_count; ++i) {
                                changed |= refine(fn, inst.srcs[i], dt);
                            }
                        }
                    }
                    break;
                }

                case IrOp::Add: {
                    // Pointer arithmetic: Ptr + Int → Ptr. We don't try
                    // to refine integer operand widths here — Phase 4
                    // (struct/array recovery) will own that.
                    if (inst.src_count == 2) {
                        const TypeRef a0 = fn.type_of(inst.srcs[0]);
                        const TypeRef a1 = fn.type_of(inst.srcs[1]);
                        if (a.kind(a0) == TypeKind::Ptr) {
                            changed |= refine(fn, inst.dst, a0);
                        } else if (a.kind(a1) == TypeKind::Ptr) {
                            changed |= refine(fn, inst.dst, a1);
                        }
                    }
                    break;
                }

                case IrOp::Sub: {
                    // Ptr - Int → Ptr; Ptr - Ptr → Int (offset).
                    if (inst.src_count == 2) {
                        const TypeRef a0 = fn.type_of(inst.srcs[0]);
                        const TypeRef a1 = fn.type_of(inst.srcs[1]);
                        const bool p0 = a.kind(a0) == TypeKind::Ptr;
                        const bool p1 = a.kind(a1) == TypeKind::Ptr;
                        if (p0 && !p1) {
                            changed |= refine(fn, inst.dst, a0);
                        } else if (p0 && p1) {
                            changed |= refine(fn, inst.dst, int_for(a, inst.dst.type));
                        }
                    }
                    break;
                }

                default:
                    break;
            }
        }
    }
    return changed;
}

}  // namespace

void infer_local_types(IrFunction& fn) {
    constexpr int kMaxSweeps = 10;
    for (int i = 0; i < kMaxSweeps; ++i) {
        if (!sweep(fn)) break;
    }
}

}  // namespace ember
