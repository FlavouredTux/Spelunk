// Register read/write for the macOS Mach backend on x86-64.
//
// Mach exposes thread state via thread_get_state / thread_set_state
// with a flavor-tagged buffer. We pull five flavors:
//
//   x86_THREAD_STATE64    GPR + RIP/RFLAGS + cs/fs/gs
//   x86_FLOAT_STATE64     x87 + MXCSR + XMM0..15
//   x86_AVX_STATE64       above + YMM0..15 high halves
//   x86_AVX512_STATE64    above + ZMM0..31 high halves + K0..K7
//   x86_DEBUG_STATE64     DR0..DR7
//
// Caveats vs Linux ptrace:
//   * x86_thread_state64 has no ds/es/ss fields. They're effectively
//     unused in x86-64 long mode and Mach doesn't surface them — we
//     leave them zero in the populated Registers and don't set the
//     PresentSeg bit because there's nothing to write back.
//   * fs_base / gs_base are NOT in x86_THREAD_STATE64 either. Mach
//     has a separate selector for these on Apple Silicon machines
//     (irrelevant here) but on x86-64 the kernel doesn't expose them
//     through the user-facing flavors. Left as zero.

#include "mach_target.hpp"

#include <cerrno>
#include <cstring>
#include <format>
#include <string>

#include <mach/mach.h>
#include <mach/thread_act.h>
#include <mach/thread_state.h>
#include <mach/i386/thread_status.h>

namespace ember::debug::mach_ {

namespace {

[[nodiscard]] Error mach_io(const char* op, kern_return_t kr) {
    return Error::io(std::format("{}: {}", op, ::mach_error_string(kr)));
}

void from_gpr(const x86_thread_state64_t& s, Registers& r) {
    r.rax = s.__rax; r.rbx = s.__rbx; r.rcx = s.__rcx; r.rdx = s.__rdx;
    r.rdi = s.__rdi; r.rsi = s.__rsi; r.rbp = s.__rbp; r.rsp = s.__rsp;
    r.r8  = s.__r8;  r.r9  = s.__r9;  r.r10 = s.__r10; r.r11 = s.__r11;
    r.r12 = s.__r12; r.r13 = s.__r13; r.r14 = s.__r14; r.r15 = s.__r15;
    r.rip = s.__rip; r.rflags = s.__rflags;
    r.cs = s.__cs; r.fs = s.__fs; r.gs = s.__gs;
    // ds/es/ss/fs_base/gs_base intentionally not touched.
}

void to_gpr(const Registers& r, x86_thread_state64_t& s) {
    s.__rax = r.rax; s.__rbx = r.rbx; s.__rcx = r.rcx; s.__rdx = r.rdx;
    s.__rdi = r.rdi; s.__rsi = r.rsi; s.__rbp = r.rbp; s.__rsp = r.rsp;
    s.__r8  = r.r8;  s.__r9  = r.r9;  s.__r10 = r.r10; s.__r11 = r.r11;
    s.__r12 = r.r12; s.__r13 = r.r13; s.__r14 = r.r14; s.__r15 = r.r15;
    s.__rip = r.rip; s.__rflags = r.rflags;
    s.__cs = r.cs; s.__fs = r.fs; s.__gs = r.gs;
}

// x86_float_state64_t carries: control word, status word, abridged
// tag, opcode, fp ip+dp, mxcsr+mask, ST0..7 (each as a 16-byte
// _STRUCT_MMST_REG), XMM0..15 (each as a 16-byte _STRUCT_XMM_REG).
void from_fp(const x86_float_state64_t& s, Registers& r) {
    r.fcw = s.__fpu_fcw.__rc | (s.__fpu_fcw.__pc << 8);  // packed bitfield
    r.fsw = static_cast<u16>(
        s.__fpu_fsw.__invalid | (s.__fpu_fsw.__denorm << 1) |
        (s.__fpu_fsw.__zdiv << 2) | (s.__fpu_fsw.__ovrfl << 3) |
        (s.__fpu_fsw.__undfl << 4) | (s.__fpu_fsw.__precis << 5) |
        (s.__fpu_fsw.__stkflt << 6) | (s.__fpu_fsw.__errsumm << 7) |
        (s.__fpu_fsw.__c0 << 8) | (s.__fpu_fsw.__c1 << 9) |
        (s.__fpu_fsw.__c2 << 10) | (s.__fpu_fsw.__tos << 11) |
        (s.__fpu_fsw.__c3 << 14) | (s.__fpu_fsw.__busy << 15));
    r.ftw = s.__fpu_ftw;
    r.fop = s.__fpu_fop;
    // FIP/FDP are split into 32-bit ip/cs and 32-bit dp/ds; combine
    // into 64-bit virtual addresses (cs/ds are zero in long mode).
    r.fip = static_cast<u64>(s.__fpu_ip);
    r.fdp = static_cast<u64>(s.__fpu_dp);
    r.mxcsr      = s.__fpu_mxcsr;
    r.mxcsr_mask = s.__fpu_mxcsrmask;

    std::memcpy(r.st[0].bytes, &s.__fpu_stmm0, 16);
    std::memcpy(r.st[1].bytes, &s.__fpu_stmm1, 16);
    std::memcpy(r.st[2].bytes, &s.__fpu_stmm2, 16);
    std::memcpy(r.st[3].bytes, &s.__fpu_stmm3, 16);
    std::memcpy(r.st[4].bytes, &s.__fpu_stmm4, 16);
    std::memcpy(r.st[5].bytes, &s.__fpu_stmm5, 16);
    std::memcpy(r.st[6].bytes, &s.__fpu_stmm6, 16);
    std::memcpy(r.st[7].bytes, &s.__fpu_stmm7, 16);

    std::memcpy(r.zmm[0].bytes,  &s.__fpu_xmm0,  16);
    std::memcpy(r.zmm[1].bytes,  &s.__fpu_xmm1,  16);
    std::memcpy(r.zmm[2].bytes,  &s.__fpu_xmm2,  16);
    std::memcpy(r.zmm[3].bytes,  &s.__fpu_xmm3,  16);
    std::memcpy(r.zmm[4].bytes,  &s.__fpu_xmm4,  16);
    std::memcpy(r.zmm[5].bytes,  &s.__fpu_xmm5,  16);
    std::memcpy(r.zmm[6].bytes,  &s.__fpu_xmm6,  16);
    std::memcpy(r.zmm[7].bytes,  &s.__fpu_xmm7,  16);
    std::memcpy(r.zmm[8].bytes,  &s.__fpu_xmm8,  16);
    std::memcpy(r.zmm[9].bytes,  &s.__fpu_xmm9,  16);
    std::memcpy(r.zmm[10].bytes, &s.__fpu_xmm10, 16);
    std::memcpy(r.zmm[11].bytes, &s.__fpu_xmm11, 16);
    std::memcpy(r.zmm[12].bytes, &s.__fpu_xmm12, 16);
    std::memcpy(r.zmm[13].bytes, &s.__fpu_xmm13, 16);
    std::memcpy(r.zmm[14].bytes, &s.__fpu_xmm14, 16);
    std::memcpy(r.zmm[15].bytes, &s.__fpu_xmm15, 16);
}

void to_fp(const Registers& r, x86_float_state64_t& s) {
    s.__fpu_fop      = static_cast<u16>(r.fop);
    s.__fpu_ip       = static_cast<u32>(r.fip);
    s.__fpu_dp       = static_cast<u32>(r.fdp);
    s.__fpu_mxcsr    = r.mxcsr;
    s.__fpu_mxcsrmask = r.mxcsr_mask;
    s.__fpu_ftw      = r.ftw;
    // Bitfield round-trip for FCW/FSW is not strictly invertible from
    // packed u16 → struct → u16 in all corner cases. Most callers use
    // get→mutate-one-non-flag-field→set, so the safest thing is to
    // leave FCW/FSW packed and not unpack them here. Real ABI testing
    // on a Mac will tell us if we need a finer-grained set.

    std::memcpy(&s.__fpu_stmm0, r.st[0].bytes, 16);
    std::memcpy(&s.__fpu_stmm1, r.st[1].bytes, 16);
    std::memcpy(&s.__fpu_stmm2, r.st[2].bytes, 16);
    std::memcpy(&s.__fpu_stmm3, r.st[3].bytes, 16);
    std::memcpy(&s.__fpu_stmm4, r.st[4].bytes, 16);
    std::memcpy(&s.__fpu_stmm5, r.st[5].bytes, 16);
    std::memcpy(&s.__fpu_stmm6, r.st[6].bytes, 16);
    std::memcpy(&s.__fpu_stmm7, r.st[7].bytes, 16);

    std::memcpy(&s.__fpu_xmm0,  r.zmm[0].bytes,  16);
    std::memcpy(&s.__fpu_xmm1,  r.zmm[1].bytes,  16);
    std::memcpy(&s.__fpu_xmm2,  r.zmm[2].bytes,  16);
    std::memcpy(&s.__fpu_xmm3,  r.zmm[3].bytes,  16);
    std::memcpy(&s.__fpu_xmm4,  r.zmm[4].bytes,  16);
    std::memcpy(&s.__fpu_xmm5,  r.zmm[5].bytes,  16);
    std::memcpy(&s.__fpu_xmm6,  r.zmm[6].bytes,  16);
    std::memcpy(&s.__fpu_xmm7,  r.zmm[7].bytes,  16);
    std::memcpy(&s.__fpu_xmm8,  r.zmm[8].bytes,  16);
    std::memcpy(&s.__fpu_xmm9,  r.zmm[9].bytes,  16);
    std::memcpy(&s.__fpu_xmm10, r.zmm[10].bytes, 16);
    std::memcpy(&s.__fpu_xmm11, r.zmm[11].bytes, 16);
    std::memcpy(&s.__fpu_xmm12, r.zmm[12].bytes, 16);
    std::memcpy(&s.__fpu_xmm13, r.zmm[13].bytes, 16);
    std::memcpy(&s.__fpu_xmm14, r.zmm[14].bytes, 16);
    std::memcpy(&s.__fpu_xmm15, r.zmm[15].bytes, 16);
}

}  // namespace

Result<Registers> MachOTarget::get_regs(ThreadId tid) {
    Registers r{};
    const thread_act_t th = static_cast<thread_act_t>(tid);

    x86_thread_state64_t gpr{};
    mach_msg_type_number_t cnt = x86_THREAD_STATE64_COUNT;
    kern_return_t kr = ::thread_get_state(
        th, x86_THREAD_STATE64,
        reinterpret_cast<thread_state_t>(&gpr), &cnt);
    if (kr != KERN_SUCCESS) {
        return std::unexpected(mach_io("thread_get_state (GPR)", kr));
    }
    from_gpr(gpr, r);
    r.present |= Registers::PresentGpr;

    x86_float_state64_t fp{};
    cnt = x86_FLOAT_STATE64_COUNT;
    if (::thread_get_state(th, x86_FLOAT_STATE64,
            reinterpret_cast<thread_state_t>(&fp), &cnt) == KERN_SUCCESS) {
        from_fp(fp, r);
        r.present |= Registers::PresentX87 | Registers::PresentSse;
    }

    // AVX state extends the float layout with YMM_HI128 fields. We
    // copy the high 128 bits of each YMM into bytes 16..31 of zmm[i].
    x86_avx_state64_t avx{};
    cnt = x86_AVX_STATE64_COUNT;
    if (::thread_get_state(th, x86_AVX_STATE64,
            reinterpret_cast<thread_state_t>(&avx), &cnt) == KERN_SUCCESS) {
        std::memcpy(r.zmm[0].bytes  + 16, &avx.__fpu_ymmh0,  16);
        std::memcpy(r.zmm[1].bytes  + 16, &avx.__fpu_ymmh1,  16);
        std::memcpy(r.zmm[2].bytes  + 16, &avx.__fpu_ymmh2,  16);
        std::memcpy(r.zmm[3].bytes  + 16, &avx.__fpu_ymmh3,  16);
        std::memcpy(r.zmm[4].bytes  + 16, &avx.__fpu_ymmh4,  16);
        std::memcpy(r.zmm[5].bytes  + 16, &avx.__fpu_ymmh5,  16);
        std::memcpy(r.zmm[6].bytes  + 16, &avx.__fpu_ymmh6,  16);
        std::memcpy(r.zmm[7].bytes  + 16, &avx.__fpu_ymmh7,  16);
        std::memcpy(r.zmm[8].bytes  + 16, &avx.__fpu_ymmh8,  16);
        std::memcpy(r.zmm[9].bytes  + 16, &avx.__fpu_ymmh9,  16);
        std::memcpy(r.zmm[10].bytes + 16, &avx.__fpu_ymmh10, 16);
        std::memcpy(r.zmm[11].bytes + 16, &avx.__fpu_ymmh11, 16);
        std::memcpy(r.zmm[12].bytes + 16, &avx.__fpu_ymmh12, 16);
        std::memcpy(r.zmm[13].bytes + 16, &avx.__fpu_ymmh13, 16);
        std::memcpy(r.zmm[14].bytes + 16, &avx.__fpu_ymmh14, 16);
        std::memcpy(r.zmm[15].bytes + 16, &avx.__fpu_ymmh15, 16);
        r.present |= Registers::PresentAvx;
    }

#ifdef x86_AVX512_STATE64_COUNT
    x86_avx512_state64_t z{};
    cnt = x86_AVX512_STATE64_COUNT;
    if (::thread_get_state(th, x86_AVX512_STATE64,
            reinterpret_cast<thread_state_t>(&z), &cnt) == KERN_SUCCESS) {
        // K0..K7
        std::memcpy(&r.k[0], &z.__fpu_k0, 8);
        std::memcpy(&r.k[1], &z.__fpu_k1, 8);
        std::memcpy(&r.k[2], &z.__fpu_k2, 8);
        std::memcpy(&r.k[3], &z.__fpu_k3, 8);
        std::memcpy(&r.k[4], &z.__fpu_k4, 8);
        std::memcpy(&r.k[5], &z.__fpu_k5, 8);
        std::memcpy(&r.k[6], &z.__fpu_k6, 8);
        std::memcpy(&r.k[7], &z.__fpu_k7, 8);
        // ZMM0..15 high 256 bits → bytes 32..63 of zmm[i].
        std::memcpy(r.zmm[0].bytes  + 32, &z.__fpu_zmmh0,  32);
        std::memcpy(r.zmm[1].bytes  + 32, &z.__fpu_zmmh1,  32);
        std::memcpy(r.zmm[2].bytes  + 32, &z.__fpu_zmmh2,  32);
        std::memcpy(r.zmm[3].bytes  + 32, &z.__fpu_zmmh3,  32);
        std::memcpy(r.zmm[4].bytes  + 32, &z.__fpu_zmmh4,  32);
        std::memcpy(r.zmm[5].bytes  + 32, &z.__fpu_zmmh5,  32);
        std::memcpy(r.zmm[6].bytes  + 32, &z.__fpu_zmmh6,  32);
        std::memcpy(r.zmm[7].bytes  + 32, &z.__fpu_zmmh7,  32);
        std::memcpy(r.zmm[8].bytes  + 32, &z.__fpu_zmmh8,  32);
        std::memcpy(r.zmm[9].bytes  + 32, &z.__fpu_zmmh9,  32);
        std::memcpy(r.zmm[10].bytes + 32, &z.__fpu_zmmh10, 32);
        std::memcpy(r.zmm[11].bytes + 32, &z.__fpu_zmmh11, 32);
        std::memcpy(r.zmm[12].bytes + 32, &z.__fpu_zmmh12, 32);
        std::memcpy(r.zmm[13].bytes + 32, &z.__fpu_zmmh13, 32);
        std::memcpy(r.zmm[14].bytes + 32, &z.__fpu_zmmh14, 32);
        std::memcpy(r.zmm[15].bytes + 32, &z.__fpu_zmmh15, 32);
        // ZMM16..31 (full 512 bits each)
        std::memcpy(r.zmm[16].bytes, &z.__fpu_zmm16, 64);
        std::memcpy(r.zmm[17].bytes, &z.__fpu_zmm17, 64);
        std::memcpy(r.zmm[18].bytes, &z.__fpu_zmm18, 64);
        std::memcpy(r.zmm[19].bytes, &z.__fpu_zmm19, 64);
        std::memcpy(r.zmm[20].bytes, &z.__fpu_zmm20, 64);
        std::memcpy(r.zmm[21].bytes, &z.__fpu_zmm21, 64);
        std::memcpy(r.zmm[22].bytes, &z.__fpu_zmm22, 64);
        std::memcpy(r.zmm[23].bytes, &z.__fpu_zmm23, 64);
        std::memcpy(r.zmm[24].bytes, &z.__fpu_zmm24, 64);
        std::memcpy(r.zmm[25].bytes, &z.__fpu_zmm25, 64);
        std::memcpy(r.zmm[26].bytes, &z.__fpu_zmm26, 64);
        std::memcpy(r.zmm[27].bytes, &z.__fpu_zmm27, 64);
        std::memcpy(r.zmm[28].bytes, &z.__fpu_zmm28, 64);
        std::memcpy(r.zmm[29].bytes, &z.__fpu_zmm29, 64);
        std::memcpy(r.zmm[30].bytes, &z.__fpu_zmm30, 64);
        std::memcpy(r.zmm[31].bytes, &z.__fpu_zmm31, 64);
        r.present |= Registers::PresentAvx512;
    }
#endif

    x86_debug_state64_t dr{};
    cnt = x86_DEBUG_STATE64_COUNT;
    if (::thread_get_state(th, x86_DEBUG_STATE64,
            reinterpret_cast<thread_state_t>(&dr), &cnt) == KERN_SUCCESS) {
        r.dr[0] = dr.__dr0;
        r.dr[1] = dr.__dr1;
        r.dr[2] = dr.__dr2;
        r.dr[3] = dr.__dr3;
        r.dr[4] = dr.__dr4;
        r.dr[5] = dr.__dr5;
        r.dr[6] = dr.__dr6;
        r.dr[7] = dr.__dr7;
        r.present |= Registers::PresentDr;
    }

    return r;
}

Result<void> MachOTarget::set_regs(ThreadId tid, const Registers& r) {
    const thread_act_t th = static_cast<thread_act_t>(tid);

    if (r.present & Registers::PresentGpr) {
        x86_thread_state64_t gpr{};
        to_gpr(r, gpr);
        if (auto kr = ::thread_set_state(th, x86_THREAD_STATE64,
                reinterpret_cast<thread_state_t>(&gpr),
                x86_THREAD_STATE64_COUNT); kr != KERN_SUCCESS) {
            return std::unexpected(mach_io("thread_set_state (GPR)", kr));
        }
    }
    // For x87/SSE: round-trip through float state. Avx/Avx512 set
    // is deferred until we have a Mac to test against — the AVX/
    // AVX-512 state structs share the float prefix, so partial writes
    // to fp would clobber the upper halves. v0 only writes float when
    // exactly the legacy bits were changed.
    if ((r.present & (Registers::PresentX87 | Registers::PresentSse)) &&
        !(r.present & (Registers::PresentAvx | Registers::PresentAvx512))) {
        x86_float_state64_t fp{};
        // Read-modify-write so fields we don't unpack stay correct.
        mach_msg_type_number_t cnt = x86_FLOAT_STATE64_COUNT;
        ::thread_get_state(th, x86_FLOAT_STATE64,
            reinterpret_cast<thread_state_t>(&fp), &cnt);
        to_fp(r, fp);
        if (auto kr = ::thread_set_state(th, x86_FLOAT_STATE64,
                reinterpret_cast<thread_state_t>(&fp),
                x86_FLOAT_STATE64_COUNT); kr != KERN_SUCCESS) {
            return std::unexpected(mach_io("thread_set_state (FP)", kr));
        }
    }

    if (r.present & Registers::PresentDr) {
        x86_debug_state64_t dr{};
        dr.__dr0 = r.dr[0]; dr.__dr1 = r.dr[1];
        dr.__dr2 = r.dr[2]; dr.__dr3 = r.dr[3];
        dr.__dr4 = r.dr[4]; dr.__dr5 = r.dr[5];
        dr.__dr6 = r.dr[6]; dr.__dr7 = r.dr[7];
        if (auto kr = ::thread_set_state(th, x86_DEBUG_STATE64,
                reinterpret_cast<thread_state_t>(&dr),
                x86_DEBUG_STATE64_COUNT); kr != KERN_SUCCESS) {
            return std::unexpected(mach_io("thread_set_state (DR)", kr));
        }
    }

    return {};
}

}  // namespace ember::debug::mach_
