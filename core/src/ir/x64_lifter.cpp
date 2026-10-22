// Instruction dispatch and the X64Lifter entry point.

#include <spelunk/ir/x64_lifter.hpp>

#include <cstddef>
#include <format>
#include <unordered_map>
#include <utility>
#include <vector>

#include <spelunk/analysis/function.hpp>
#include <spelunk/analysis/x86.hpp>
#include <spelunk/common/error.hpp>
#include <spelunk/disasm/instruction.hpp>
#include <spelunk/disasm/register.hpp>
#include <spelunk/ir/ir.hpp>

#include "x64_lifter_internal.hpp"

namespace spelunk::x64_lift {
namespace {
void lift_instruction_body(LiftCtx& ctx);
}  // namespace

void lift_instruction(LiftCtx& ctx) {
    if (is_x87(ctx.insn->mnemonic) && lift_x86_fp(ctx)) return;
    const FpOutcome before = ctx.fp_outcome;
    lift_instruction_body(ctx);
    if (before.ah) refine_fp_status_use(ctx, before);
}

namespace {
void lift_instruction_body(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    switch (insn.mnemonic) {
        case Mnemonic::Mov:     lift_mov(ctx);     break;
        case Mnemonic::Movzx:   lift_movzx(ctx);   break;
        case Mnemonic::Movsx:   lift_movsx(ctx);   break;
        case Mnemonic::Movsxd:  lift_movsx(ctx);   break;
        case Mnemonic::Lea:     lift_lea(ctx);     break;
        case Mnemonic::Add:     lift_add(ctx);     break;
        case Mnemonic::Sub:     lift_sub(ctx);     break;
        case Mnemonic::Cmp:     lift_cmp(ctx);     break;
        case Mnemonic::And:     lift_and(ctx);     break;
        case Mnemonic::Or:      lift_or(ctx);      break;
        case Mnemonic::Xor:     lift_xor(ctx);     break;
        case Mnemonic::Test:    lift_test(ctx);    break;
        case Mnemonic::Inc:     lift_inc(ctx);     break;
        case Mnemonic::Dec:     lift_dec(ctx);     break;
        case Mnemonic::Neg:     lift_neg(ctx);     break;
        case Mnemonic::Not:     lift_not(ctx);     break;
        case Mnemonic::Shl:     lift_shl(ctx);     break;
        case Mnemonic::Shr:     lift_shr(ctx);     break;
        case Mnemonic::Sar:     lift_sar(ctx);     break;
        case Mnemonic::Rol:     lift_rotate(ctx, /*right=*/false); break;
        case Mnemonic::Ror:     lift_rotate(ctx, /*right=*/true);  break;
        case Mnemonic::Rcl:     lift_rotate_through_carry(ctx, /*right=*/false); break;
        case Mnemonic::Rcr:     lift_rotate_through_carry(ctx, /*right=*/true);  break;
        case Mnemonic::Imul:    lift_imul(ctx);    break;
        case Mnemonic::Mul:     lift_mul(ctx);     break;
        case Mnemonic::Div:     lift_div_one_op(ctx, /*signed_div=*/false); break;
        case Mnemonic::Idiv:    lift_div_one_op(ctx, /*signed_div=*/true);  break;
        case Mnemonic::Adc:     lift_adc_sbb(ctx, /*subtract=*/false); break;
        case Mnemonic::Sbb:     lift_adc_sbb(ctx, /*subtract=*/true);  break;
        case Mnemonic::Xchg:    lift_xchg(ctx);    break;
        case Mnemonic::Xadd:    lift_xadd(ctx);    break;
        case Mnemonic::Cmpxchg: lift_cmpxchg(ctx); break;
        case Mnemonic::Bsf:     lift_bit_scan(ctx, "bsf"); break;
        case Mnemonic::Bsr:     lift_bit_scan(ctx, "bsr"); break;
        case Mnemonic::Popcnt:  lift_popcnt(ctx);  break;
        case Mnemonic::Bt:      lift_bit_test(ctx, 't'); break;
        case Mnemonic::Bts:     lift_bit_test(ctx, 's'); break;
        case Mnemonic::Btr:     lift_bit_test(ctx, 'r'); break;
        case Mnemonic::Btc:     lift_bit_test(ctx, 'c'); break;
        case Mnemonic::Shld:    lift_double_shift(ctx, /*right=*/false); break;
        case Mnemonic::Shrd:    lift_double_shift(ctx, /*right=*/true);  break;
        case Mnemonic::Bswap:   lift_bswap(ctx);   break;
        case Mnemonic::Andn:
        case Mnemonic::Bzhi:
        case Mnemonic::Pext:
        case Mnemonic::Pdep:
        case Mnemonic::Shlx:
        case Mnemonic::Shrx:
        case Mnemonic::Sarx:
            lift_bmi_three_operand(ctx, insn.mnemonic);
            break;
        case Mnemonic::Mulx:    lift_mulx(ctx); break;
        case Mnemonic::Vfmadd132ps: case Mnemonic::Vfmadd132pd:
        case Mnemonic::Vfmadd132ss: case Mnemonic::Vfmadd132sd:
        case Mnemonic::Vfmadd213ps: case Mnemonic::Vfmadd213pd:
        case Mnemonic::Vfmadd213ss: case Mnemonic::Vfmadd213sd:
        case Mnemonic::Vfmadd231ps: case Mnemonic::Vfmadd231pd:
        case Mnemonic::Vfmadd231ss: case Mnemonic::Vfmadd231sd:
            lift_fma(ctx);
            break;
        case Mnemonic::Vzeroupper:
            lift_intrinsic(ctx, "x64.vzeroupper");
            break;

        case Mnemonic::Cmovo: case Mnemonic::Cmovno:
        case Mnemonic::Cmovb: case Mnemonic::Cmovae:
        case Mnemonic::Cmove: case Mnemonic::Cmovne:
        case Mnemonic::Cmovbe: case Mnemonic::Cmova:
        case Mnemonic::Cmovs: case Mnemonic::Cmovns:
        case Mnemonic::Cmovp: case Mnemonic::Cmovnp:
        case Mnemonic::Cmovl: case Mnemonic::Cmovge:
        case Mnemonic::Cmovle: case Mnemonic::Cmovg:
            lift_cmov(ctx, insn.mnemonic);
            break;

        case Mnemonic::Push:    lift_push(ctx);    break;
        case Mnemonic::Pop:     lift_pop(ctx);     break;
        case Mnemonic::Pushf:   lift_pushf(ctx);   break;
        case Mnemonic::Popf:    lift_popf(ctx);    break;
        case Mnemonic::Leave:   lift_leave(ctx);   break;
        case Mnemonic::Call:    lift_call(ctx);    break;
        case Mnemonic::Ret:     lift_ret(ctx);     break;
        case Mnemonic::Jmp:     lift_jmp(ctx);     break;
        case Mnemonic::Nop:     lift_nop(ctx);     break;
        case Mnemonic::Int3:
        case Mnemonic::Hlt:
        case Mnemonic::Ud2:
            lift_unreachable(ctx);
            break;
        case Mnemonic::Syscall:
            lift_intrinsic(ctx, "syscall");
            break;
        case Mnemonic::Lahf:    lift_lahf(ctx); break;
        case Mnemonic::Sahf:    lift_sahf(ctx); break;
        case Mnemonic::Clc:
        case Mnemonic::Stc:
        case Mnemonic::Cmc:
            lift_carry_flag_op(ctx, insn.mnemonic);
            break;
        case Mnemonic::Cld:     lift_intrinsic(ctx, "x64.cld"); break;
        case Mnemonic::StdDir:  lift_intrinsic(ctx, "x64.std"); break;
        case Mnemonic::Cli:     lift_intrinsic(ctx, "x64.cli"); break;
        case Mnemonic::Sti:     lift_intrinsic(ctx, "x64.sti"); break;
        case Mnemonic::Endbr64: lift_intrinsic(ctx, "endbr64"); break;
        case Mnemonic::Endbr32: lift_intrinsic(ctx, "endbr32"); break;
        case Mnemonic::Cpuid:   lift_intrinsic(ctx, "x64.cpuid");  break;
        case Mnemonic::Rdtsc:   lift_intrinsic(ctx, "x64.rdtsc");  break;
        case Mnemonic::Rdtscp:  lift_intrinsic(ctx, "x64.rdtscp"); break;
        case Mnemonic::Rdmsr:   lift_intrinsic(ctx, "x64.rdmsr");  break;
        case Mnemonic::Wrmsr:   lift_intrinsic(ctx, "x64.wrmsr");  break;
        case Mnemonic::Rdpmc:   lift_intrinsic(ctx, "x64.rdpmc");  break;
        case Mnemonic::Pause:   lift_intrinsic(ctx, "x64.pause");  break;
        case Mnemonic::Cdqe: {
            // rax = sext64(eax)
            IrValue eax = ctx.read_reg(Reg::Eax);
            IrValue sx  = ctx.emit_convert(IrOp::SExt, eax, IrType::I64);
            ctx.write_reg(Reg::Rax, sx);
            break;
        }
        case Mnemonic::Cwde: {
            // eax = sext32(ax)   - 32-bit write then zero-extends per x64 rules.
            IrValue ax = ctx.read_reg(Reg::Ax);
            IrValue sx = ctx.emit_convert(IrOp::SExt, ax, IrType::I32);
            ctx.write_reg(Reg::Eax, sx);
            break;
        }
        case Mnemonic::Cdq:
            lift_sign_extend_dividend_high(ctx, IrType::I32);
            break;
        case Mnemonic::Cqo:
            lift_sign_extend_dividend_high(ctx, IrType::I64);
            break;

        // SetCC: nice lift reusing Jcc predicate logic.
        case Mnemonic::Seto: case Mnemonic::Setno:
        case Mnemonic::Setb: case Mnemonic::Setae:
        case Mnemonic::Sete: case Mnemonic::Setne:
        case Mnemonic::Setbe: case Mnemonic::Seta:
        case Mnemonic::Sets: case Mnemonic::Setns:
        case Mnemonic::Setp: case Mnemonic::Setnp:
        case Mnemonic::Setl: case Mnemonic::Setge:
        case Mnemonic::Setle: case Mnemonic::Setg:
            lift_setcc(ctx, insn.mnemonic);
            break;

        // ---- Scalar floating-point ---------------------------------------
        // Arithmetic: Add/Sub/Mul/Div at f32 or f64 type. The emitter
        // renders these as infix operators, so `addsd xmm0, xmm1` decompiles
        // to `xmm0 = (xmm0 + xmm1)`, and with a declared signature that
        // becomes `return (a + b);`.
        case Mnemonic::Addss: lift_fp_binop(ctx, IrOp::Add, IrType::F32); break;
        case Mnemonic::Subss: lift_fp_binop(ctx, IrOp::Sub, IrType::F32); break;
        case Mnemonic::Mulss: lift_fp_binop(ctx, IrOp::Mul, IrType::F32); break;
        case Mnemonic::Divss: lift_fp_binop(ctx, IrOp::Div, IrType::F32); break;
        case Mnemonic::Addsd: lift_fp_binop(ctx, IrOp::Add, IrType::F64); break;
        case Mnemonic::Subsd: lift_fp_binop(ctx, IrOp::Sub, IrType::F64); break;
        case Mnemonic::Mulsd: lift_fp_binop(ctx, IrOp::Mul, IrType::F64); break;
        case Mnemonic::Divsd: lift_fp_binop(ctx, IrOp::Div, IrType::F64); break;
        // Moves: xmm ← xmm/mem and xmm/mem ← xmm at scalar width.
        case Mnemonic::MovssLoad:     lift_fp_mov(ctx, IrType::F32, false); break;
        case Mnemonic::MovssStore:    lift_fp_mov(ctx, IrType::F32, true);  break;
        case Mnemonic::MovsdXmm:      lift_fp_mov(ctx, IrType::F64, false); break;
        case Mnemonic::MovsdXmmStore: lift_fp_mov(ctx, IrType::F64, true);  break;
        // Packed moves: compiler-emitted shortcuts for copying a whole
        // xmm register - we model as scalar F64 copies. This loses the
        // upper 64 bits of SIMD data (which we never reason about anyway)
        // but preserves the scalar dataflow that compiler output relies on.
        // movaps/movups transfer all 128 bits of an XMM register; route
        // through the SIMD-mov path with I128 so the upper 64 bits aren't
        // truncated by lift_fp_mov's scalar F64 path.
        case Mnemonic::Movaps:       lift_simd_mov(ctx, IrType::I128, false); break;
        case Mnemonic::MovapsStore:  lift_simd_mov(ctx, IrType::I128, true);  break;
        case Mnemonic::Movups:       lift_simd_mov(ctx, IrType::I128, false); break;
        case Mnemonic::MovupsStore:  lift_simd_mov(ctx, IrType::I128, true);  break;
        // Scalar-FP unary (intrinsic, libm-style names).
        case Mnemonic::Sqrtss: lift_fp_unop(ctx, "sqrtf", IrType::F32); break;
        case Mnemonic::Sqrtsd: lift_fp_unop(ctx, "sqrt",  IrType::F64); break;

        // Scalar min/max - modeled as named intrinsics (`_mm_min_ss`,
        // `_mm_max_sd`, …). The compiler emits these for `(a < b) ? a : b`
        // patterns; recovering the ternary requires lifting them as
        // IrOp::Select with a proper FP compare, which we don't have a
        // clean way to express yet.
        case Mnemonic::Minss: lift_simd_binop(ctx, "_mm_min_ss", IrType::F32); break;
        case Mnemonic::Maxss: lift_simd_binop(ctx, "_mm_max_ss", IrType::F32); break;
        case Mnemonic::Minsd: lift_simd_binop(ctx, "_mm_min_sd", IrType::F64); break;
        case Mnemonic::Maxsd: lift_simd_binop(ctx, "_mm_max_sd", IrType::F64); break;
        case Mnemonic::Minps: lift_simd_binop(ctx, "_mm_min_ps", IrType::I128); break;
        case Mnemonic::Maxps: lift_simd_binop(ctx, "_mm_max_ps", IrType::I128); break;
        case Mnemonic::Minpd: lift_simd_binop(ctx, "_mm_min_pd", IrType::I128); break;
        case Mnemonic::Maxpd: lift_simd_binop(ctx, "_mm_max_pd", IrType::I128); break;

        // gpr -> xmm conversions (size of the gpr operand drives src width).
        case Mnemonic::Cvtsi2ss: lift_int_to_fp(ctx, "cvtsi2ss", IrType::F32); break;
        case Mnemonic::Cvtsi2sd: lift_int_to_fp(ctx, "cvtsi2sd", IrType::F64); break;

        // xmm -> gpr (truncating). Operand 0 is gpr, operand 1 is xmm/m.
        case Mnemonic::Cvttss2si: lift_fp_to_int(ctx, "cvttss2si", IrType::F32); break;
        case Mnemonic::Cvttsd2si: lift_fp_to_int(ctx, "cvttsd2si", IrType::F64); break;

        // xmm width changes.
        case Mnemonic::Cvtss2sd:
            lift_fp_to_fp(ctx, "cvtss2sd", IrType::F32, IrType::F64); break;
        case Mnemonic::Cvtsd2ss:
            lift_fp_to_fp(ctx, "cvtsd2ss", IrType::F64, IrType::F32); break;

        // Scalar FP compare → ZF/CF/PF. Lets downstream `ja`/`jb`/`je` read
        // out as `if (a > b)` etc. instead of an opaque `ucomiss(...)` plus
        // a stale-flag jcc.
        case Mnemonic::Ucomiss: lift_ucomi(ctx, IrType::F32); break;
        case Mnemonic::Ucomisd: lift_ucomi(ctx, IrType::F64); break;
        // comiss/comisd: same flag effect as ucomiss/ucomisd; the only
        // difference is the QNaN-vs-SNaN exception behaviour, which the
        // emitted code reads identically.
        case Mnemonic::Comiss:  lift_ucomi(ctx, IrType::F32); break;
        case Mnemonic::Cmpss:   lift_cmpss(ctx); break;
        case Mnemonic::Comisd:  lift_ucomi(ctx, IrType::F64); break;

        // ---- Packed SSE: arithmetic / logical / unpack / shuffle / compare.
        // Lifted as named intrinsics carrying both source xmm operands.
        // F32 vs F64 chosen to match the scalar element type the mnemonic
        // implies; for packed-integer ops we still flow through F64 (the
        // dataflow is what matters, the named intrinsic carries the lane
        // semantics).
        case Mnemonic::Andps:  lift_simd_binop(ctx, "_mm_and_ps",    IrType::I128); break;
        case Mnemonic::Andnps: lift_simd_binop(ctx, "_mm_andnot_ps", IrType::I128); break;
        case Mnemonic::Orps:   lift_simd_binop(ctx, "_mm_or_ps",     IrType::I128); break;
        case Mnemonic::Xorps:  lift_simd_binop(ctx, "_mm_xor_ps",    IrType::I128); break;
        case Mnemonic::Addps:  lift_simd_binop(ctx, "_mm_add_ps",    IrType::I128); break;
        case Mnemonic::Mulps:  lift_simd_binop(ctx, "_mm_mul_ps",    IrType::I128); break;
        case Mnemonic::Subps:  lift_simd_binop(ctx, "_mm_sub_ps",    IrType::I128); break;
        case Mnemonic::Divps:  lift_simd_binop(ctx, "_mm_div_ps",    IrType::I128); break;
        case Mnemonic::Andpd:  lift_simd_binop(ctx, "_mm_and_pd",    IrType::I128); break;
        case Mnemonic::Andnpd: lift_simd_binop(ctx, "_mm_andnot_pd", IrType::I128); break;
        case Mnemonic::Orpd:   lift_simd_binop(ctx, "_mm_or_pd",     IrType::I128); break;
        case Mnemonic::Xorpd:  lift_simd_binop(ctx, "_mm_xor_pd",    IrType::I128); break;
        case Mnemonic::Addpd:  lift_simd_binop(ctx, "_mm_add_pd",    IrType::I128); break;
        case Mnemonic::Mulpd:  lift_simd_binop(ctx, "_mm_mul_pd",    IrType::I128); break;
        case Mnemonic::Subpd:  lift_simd_binop(ctx, "_mm_sub_pd",    IrType::I128); break;
        case Mnemonic::Divpd:  lift_simd_binop(ctx, "_mm_div_pd",    IrType::I128); break;

        case Mnemonic::Pxor:    lift_simd_binop(ctx, "_mm_xor_si128",    IrType::I128); break;
        case Mnemonic::Pand:    lift_simd_binop(ctx, "_mm_and_si128",    IrType::I128); break;
        case Mnemonic::Pandn:   lift_simd_binop(ctx, "_mm_andnot_si128", IrType::I128); break;
        case Mnemonic::Por:     lift_simd_binop(ctx, "_mm_or_si128",     IrType::I128); break;
        case Mnemonic::Paddq:   lift_simd_binop(ctx, "_mm_add_epi64",    IrType::I128); break;
        case Mnemonic::Pcmpeqb: lift_simd_binop(ctx, "_mm_cmpeq_epi8",   IrType::I128); break;
        case Mnemonic::Pcmpeqw: lift_simd_binop(ctx, "_mm_cmpeq_epi16",  IrType::I128); break;
        case Mnemonic::Pcmpeqd: lift_simd_binop(ctx, "_mm_cmpeq_epi32",  IrType::I128); break;
        case Mnemonic::Pminub:  lift_simd_binop(ctx, "_mm_min_epu8",     IrType::I128); break;

        case Mnemonic::Punpcklbw:  lift_simd_binop(ctx, "_mm_unpacklo_epi8",  IrType::I128); break;
        case Mnemonic::Punpcklwd:  lift_simd_binop(ctx, "_mm_unpacklo_epi16", IrType::I128); break;
        case Mnemonic::Punpckldq:  lift_simd_binop(ctx, "_mm_unpacklo_epi32", IrType::I128); break;
        case Mnemonic::Punpcklqdq: lift_simd_binop(ctx, "_mm_unpacklo_epi64", IrType::I128); break;
        case Mnemonic::Punpckhqdq: lift_simd_binop(ctx, "_mm_unpackhi_epi64", IrType::I128); break;
        case Mnemonic::Pshufd:     lift_simd_binop(ctx, "_mm_shuffle_epi32",  IrType::I128); break;
        case Mnemonic::Pshuflw:    lift_simd_binop(ctx, "_mm_shufflelo_epi16", IrType::I128); break;
        case Mnemonic::Pshufhw:    lift_simd_binop(ctx, "_mm_shufflehi_epi16", IrType::I128); break;

        // Packed integer arithmetic - same xmm-binop shape as Pxor/Pand.
        case Mnemonic::Paddb:   lift_simd_binop(ctx, "_mm_add_epi8",   IrType::I128); break;
        case Mnemonic::Paddw:   lift_simd_binop(ctx, "_mm_add_epi16",  IrType::I128); break;
        case Mnemonic::Paddd:   lift_simd_binop(ctx, "_mm_add_epi32",  IrType::I128); break;
        case Mnemonic::Psubb:   lift_simd_binop(ctx, "_mm_sub_epi8",   IrType::I128); break;
        case Mnemonic::Psubw:   lift_simd_binop(ctx, "_mm_sub_epi16",  IrType::I128); break;
        case Mnemonic::Psubd:   lift_simd_binop(ctx, "_mm_sub_epi32",  IrType::I128); break;
        case Mnemonic::Psubq:   lift_simd_binop(ctx, "_mm_sub_epi64",  IrType::I128); break;
        case Mnemonic::Pmullw:  lift_simd_binop(ctx, "_mm_mullo_epi16", IrType::I128); break;
        case Mnemonic::Pmulhw:  lift_simd_binop(ctx, "_mm_mulhi_epi16", IrType::I128); break;
        case Mnemonic::Pmulhuw: lift_simd_binop(ctx, "_mm_mulhi_epu16", IrType::I128); break;
        case Mnemonic::Pmuludq: lift_simd_binop(ctx, "_mm_mul_epu32",   IrType::I128); break;
        case Mnemonic::Pmaddwd: lift_simd_binop(ctx, "_mm_madd_epi16",  IrType::I128); break;
        case Mnemonic::Pinsrw:  lift_pinsrw(ctx); break;
        case Mnemonic::Pextrw:  lift_pextrw(ctx); break;

        // Saturating arith.
        case Mnemonic::Psubusb: lift_simd_binop(ctx, "_mm_subs_epu8",  IrType::I128); break;
        case Mnemonic::Psubusw: lift_simd_binop(ctx, "_mm_subs_epu16", IrType::I128); break;
        case Mnemonic::Paddusb: lift_simd_binop(ctx, "_mm_adds_epu8",  IrType::I128); break;
        case Mnemonic::Paddusw: lift_simd_binop(ctx, "_mm_adds_epu16", IrType::I128); break;
        case Mnemonic::Psubsb:  lift_simd_binop(ctx, "_mm_subs_epi8",  IrType::I128); break;
        case Mnemonic::Psubsw:  lift_simd_binop(ctx, "_mm_subs_epi16", IrType::I128); break;
        case Mnemonic::Paddsb:  lift_simd_binop(ctx, "_mm_adds_epi8",  IrType::I128); break;
        case Mnemonic::Paddsw:  lift_simd_binop(ctx, "_mm_adds_epi16", IrType::I128); break;

        // Min / max / averages.
        case Mnemonic::Pmaxub:  lift_simd_binop(ctx, "_mm_max_epu8",  IrType::I128); break;
        case Mnemonic::Pminsw:  lift_simd_binop(ctx, "_mm_min_epi16", IrType::I128); break;
        case Mnemonic::Pmaxsw:  lift_simd_binop(ctx, "_mm_max_epi16", IrType::I128); break;
        case Mnemonic::Pavgb:   lift_simd_binop(ctx, "_mm_avg_epu8",  IrType::I128); break;
        case Mnemonic::Pavgw:   lift_simd_binop(ctx, "_mm_avg_epu16", IrType::I128); break;

        // Greater-than compares.
        case Mnemonic::Pcmpgtb: lift_simd_binop(ctx, "_mm_cmpgt_epi8",  IrType::I128); break;
        case Mnemonic::Pcmpgtw: lift_simd_binop(ctx, "_mm_cmpgt_epi16", IrType::I128); break;
        case Mnemonic::Pcmpgtd: lift_simd_binop(ctx, "_mm_cmpgt_epi32", IrType::I128); break;

        // High-half unpacks.
        case Mnemonic::Punpckhbw: lift_simd_binop(ctx, "_mm_unpackhi_epi8",  IrType::I128); break;
        case Mnemonic::Punpckhwd: lift_simd_binop(ctx, "_mm_unpackhi_epi16", IrType::I128); break;
        case Mnemonic::Punpckhdq: lift_simd_binop(ctx, "_mm_unpackhi_epi32", IrType::I128); break;

        // Float shuffles take an imm8 selector - same 3-operand shape
        // lift_simd_binop already handles for Pshufd.
        case Mnemonic::Shufps:  lift_simd_binop(ctx, "_mm_shuffle_ps", IrType::I128); break;
        case Mnemonic::Shufpd:  lift_simd_binop(ctx, "_mm_shuffle_pd", IrType::I128); break;

        // SSE2 shift family - same mnemonic doubles for the imm8 form
        // (0x66 0F 71/72/73 /N) and the xmm-count form (0x66 0F D1..F3).
        // Branch on operand[1].kind to pick the matching intrinsic.
        case Mnemonic::Psllw:
            if (insn.num_operands >= 2 && insn.operands[1].kind == Operand::Kind::Immediate)
                lift_simd_shift_imm(ctx, "_mm_slli_epi16", IrType::I128);
            else lift_simd_binop(ctx, "_mm_sll_epi16", IrType::I128);
            break;
        case Mnemonic::Pslld:
            if (insn.num_operands >= 2 && insn.operands[1].kind == Operand::Kind::Immediate)
                lift_simd_shift_imm(ctx, "_mm_slli_epi32", IrType::I128);
            else lift_simd_binop(ctx, "_mm_sll_epi32", IrType::I128);
            break;
        case Mnemonic::Psllq:
            if (insn.num_operands >= 2 && insn.operands[1].kind == Operand::Kind::Immediate)
                lift_simd_shift_imm(ctx, "_mm_slli_epi64", IrType::I128);
            else lift_simd_binop(ctx, "_mm_sll_epi64", IrType::I128);
            break;
        case Mnemonic::Pslldq: lift_simd_shift_imm(ctx, "_mm_slli_si128", IrType::I128); break;
        case Mnemonic::Psrlw:
            if (insn.num_operands >= 2 && insn.operands[1].kind == Operand::Kind::Immediate)
                lift_simd_shift_imm(ctx, "_mm_srli_epi16", IrType::I128);
            else lift_simd_binop(ctx, "_mm_srl_epi16", IrType::I128);
            break;
        case Mnemonic::Psrld:
            if (insn.num_operands >= 2 && insn.operands[1].kind == Operand::Kind::Immediate)
                lift_simd_shift_imm(ctx, "_mm_srli_epi32", IrType::I128);
            else lift_simd_binop(ctx, "_mm_srl_epi32", IrType::I128);
            break;
        case Mnemonic::Psrlq:
            if (insn.num_operands >= 2 && insn.operands[1].kind == Operand::Kind::Immediate)
                lift_simd_shift_imm(ctx, "_mm_srli_epi64", IrType::I128);
            else lift_simd_binop(ctx, "_mm_srl_epi64", IrType::I128);
            break;
        case Mnemonic::Psrldq: lift_simd_shift_imm(ctx, "_mm_srli_si128", IrType::I128); break;
        case Mnemonic::Psraw:
            if (insn.num_operands >= 2 && insn.operands[1].kind == Operand::Kind::Immediate)
                lift_simd_shift_imm(ctx, "_mm_srai_epi16", IrType::I128);
            else lift_simd_binop(ctx, "_mm_sra_epi16", IrType::I128);
            break;
        case Mnemonic::Psrad:
            if (insn.num_operands >= 2 && insn.operands[1].kind == Operand::Kind::Immediate)
                lift_simd_shift_imm(ctx, "_mm_srai_epi32", IrType::I128);
            else lift_simd_binop(ctx, "_mm_sra_epi32", IrType::I128);
            break;

        // 128-bit aligned + unaligned moves. Operand 0 may be memory for the
        // *Store variants - lift_simd_mov handles either direction.
        // movdqa/movdqu transfer the entire 128-bit register; pin I128 so the
        // upper 64 bits aren't dropped by the F64 surrogate. movhps/movlps
        // genuinely transfer 64 bits to one half of the register and stay at
        // F64 - the half-merge semantics are still approximate (we don't
        // model the unmodified half of the XMM destination), separate issue.
        case Mnemonic::Movdqa:      lift_simd_mov(ctx, IrType::I128, false); break;
        case Mnemonic::MovdqaStore: lift_simd_mov(ctx, IrType::I128, true);  break;
        case Mnemonic::Movdqu:      lift_simd_mov(ctx, IrType::I128, false); break;
        case Mnemonic::MovdquStore: lift_simd_mov(ctx, IrType::I128, true);  break;
        case Mnemonic::Movhps:      lift_simd_mov(ctx, IrType::F64,  false); break;
        case Mnemonic::Movlps:      lift_simd_mov(ctx, IrType::F64,  false); break;

        // movd / movq: scalar transfer between XMM low lane and gpr-or-mem.
        case Mnemonic::Movd:
        case Mnemonic::MovqGpr:     lift_gpr_scalar_to_xmm(ctx); break;
        case Mnemonic::MovdStore:
        case Mnemonic::MovqGprStore: lift_gpr_scalar_from_xmm(ctx); break;
        case Mnemonic::MovqXmm:     lift_simd_mov(ctx, IrType::I64, false); break;
        case Mnemonic::MovqStore:   lift_simd_mov(ctx, IrType::I64, true);  break;

        // pmovmskb dst, xmm: extract per-byte sign bits to a 16-bit gpr mask.
        // Single-source intrinsic to a gpr destination.
        case Mnemonic::Pmovmskb: {
            if (insn.num_operands == 2) {
                IrValue src = read_xmm(ctx, insn.operands[1], IrType::I128);
                if (src.kind == IrValueKind::None) break;
                IrInst i;
                i.op   = IrOp::Intrinsic;
                i.name = "_mm_movemask_epi8";
                i.dst  = ctx.temp(IrType::I32);
                i.srcs[0]   = src;
                i.src_count = 1;
                IrValue r = i.dst;
                ctx.emit(std::move(i));
                store_lvalue(insn.operands[0], r, ctx);
            }
            break;
        }

        // String ops: intrinsic with explicit rdi/rsi/rcx effect.
        case Mnemonic::Movsb: lift_string_op(ctx, "rep.movsb", true,  false); break;
        case Mnemonic::Movsd: lift_string_op(ctx, "rep.movsd", true,  false); break;
        case Mnemonic::Movsq: lift_string_op(ctx, "rep.movsq", true,  false); break;
        case Mnemonic::Cmpsb: lift_string_op(ctx, "rep.cmpsb", true,  false); break;
        case Mnemonic::Cmpsd: lift_string_op(ctx, "rep.cmpsd", true,  false); break;
        case Mnemonic::Cmpsq: lift_string_op(ctx, "rep.cmpsq", true,  false); break;
        case Mnemonic::Stosb: lift_string_op(ctx, "rep.stosb", false, true);  break;
        case Mnemonic::Stosd: lift_string_op(ctx, "rep.stosd", false, true);  break;
        case Mnemonic::Stosq: lift_string_op(ctx, "rep.stosq", false, true);  break;
        case Mnemonic::Lodsb: lift_string_op(ctx, "rep.lodsb", false, true);  break;
        case Mnemonic::Lodsd: lift_string_op(ctx, "rep.lodsd", false, true);  break;
        case Mnemonic::Lodsq: lift_string_op(ctx, "rep.lodsq", false, true);  break;
        case Mnemonic::Scasb: lift_string_op(ctx, "rep.scasb", false, true);  break;
        case Mnemonic::Scasd: lift_string_op(ctx, "rep.scasd", false, true);  break;
        case Mnemonic::Scasq: lift_string_op(ctx, "rep.scasq", false, true);  break;

        default:
            if (is_conditional_branch(insn.mnemonic)) {
                lift_jcc(ctx, insn.mnemonic);
            } else {
                // Unmodeled mnemonic. Tag with `x64.` so the emitter can
                // render the intrinsic as a `/* ... */` comment rather
                // than `xorps(xmm0, xmm0);` which reads like a real C
                // call. Intrinsics the lifter handles on purpose
                // (sqrtss, ucomiss, …) keep their bare names.
                lift_intrinsic(ctx, std::format("x64.{}",
                                                mnemonic_name(insn.mnemonic)));
            }
            break;
    }
}
}  // namespace

void ensure_terminator(IrBlock& bb) {
    if (!bb.insts.empty() && is_terminator(bb.insts.back().op)) return;

    switch (bb.kind) {
        case BlockKind::Return: {
            IrInst i;
            i.op = IrOp::Return;
            bb.insts.push_back(std::move(i));
            break;
        }
        case BlockKind::Unconditional:
        case BlockKind::Fallthrough:
            if (!bb.successors.empty()) {
                IrInst i;
                i.op      = IrOp::Branch;
                i.target1 = bb.successors[0];
                bb.insts.push_back(std::move(i));
            } else {
                IrInst i;
                i.op = IrOp::Unreachable;
                bb.insts.push_back(std::move(i));
            }
            break;
        case BlockKind::IndirectJmp: {
            IrInst i;
            i.op = IrOp::Unreachable;
            bb.insts.push_back(std::move(i));
            break;
        }
        case BlockKind::Switch:
            // The indirect jmp is the block's natural terminator; it lifts
            // to BranchIndirect so no synthetic instruction is needed.
            break;
        case BlockKind::TailCall:
            // The jmp was lifted as call+return; the Return is the terminator.
            break;
        case BlockKind::Conditional:
            if (!bb.successors.empty()) {
                IrInst i;
                i.op      = IrOp::Branch;
                i.target1 = bb.successors[0];
                bb.insts.push_back(std::move(i));
            }
            break;
    }
}

}  // namespace spelunk::x64_lift

namespace spelunk {

using namespace x64_lift;

Result<IrFunction> X64Lifter::lift(const Function& fn) const {
    const bool x86 = is_x86_32_abi(abi_) && binary_;
    const Abi function_abi = x86 && resolve_function_abi_
        ? analyze_x86_function(*binary_, fn.start).abi : abi_;
    const auto call_pops = x86 ? x86_call_pops(*binary_, fn)
                               : std::unordered_map<addr_t, u16>{};
    const auto call_preserved = x86 && resolve_function_abi_
        ? x86_call_preserved(*binary_, fn)
        : std::unordered_map<addr_t, std::vector<Reg>>{};
    IrFunction ir;
    ir.start = fn.start;
    ir.end   = fn.end;
    ir.name  = fn.name;

    // Compare masks can flow into full-width bitwise selects. Keep scalar
    // writes in their XMM containers throughout these functions, including
    // across basic-block boundaries, rather than inventing upper lanes later.
    bool preserve_scalar_lanes = false;
    for (const auto& block : fn.blocks) for (const auto& insn : block.instructions)
        preserve_scalar_lanes |= insn.mnemonic == Mnemonic::Cmpss;

    ir.blocks.reserve(fn.blocks.size());
    for (const auto& bb : fn.blocks) {
        IrBlock irb;
        irb.start        = bb.start;
        irb.end          = bb.end;
        irb.kind         = bb.kind;
        irb.successors   = bb.successors;
        irb.predecessors = bb.predecessors;
        irb.case_values  = bb.case_values;
        irb.has_default  = bb.has_default;
        irb.switch_index = bb.switch_index;
        ir.block_at[irb.start] = ir.blocks.size();
        ir.blocks.push_back(std::move(irb));
    }

    for (std::size_t i = 0; i < fn.blocks.size(); ++i) {
        const auto& src_bb = fn.blocks[i];
        auto&       dst_bb = ir.blocks[i];

        LiftCtx ctx;
        ctx.fn  = &ir;
        ctx.blk = &dst_bb;
        ctx.abi = function_abi;
        ctx.binary = binary_;
        ctx.call_pops = &call_pops;
        ctx.call_preserved = &call_preserved;
        ctx.preserve_scalar_lanes = preserve_scalar_lanes;

        for (const auto& insn : src_bb.instructions) {
            ctx.insn = &insn;
            lift_instruction(ctx);
        }

        ensure_terminator(dst_bb);
    }

    return ir;
}

}  // namespace spelunk
