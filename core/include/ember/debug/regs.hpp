#pragma once

#include <ember/common/types.hpp>

namespace ember::debug {

// Full x86-64 architectural register snapshot. Holds GPRs, segments,
// x87, SSE/AVX/AVX-512 SIMD state, mask registers, and debug
// registers in a single struct so callers can `get_regs → mutate one
// field → set_regs` without losing the rest of the state.
//
// Subsets the host CPU/kernel doesn't expose are zeroed and have
// their `Present*` bit clear in `present`. On `set_regs` only
// subsets whose bit is set are written back to the tracee — the
// round-trip pattern just works because get_regs sets every bit it
// populated.
//
// SIMD layout: XMM[i] = low 16 bytes of zmm[i]; YMM[i] = low 32
// bytes; ZMM[i] = full 64 bytes. zmm[16..31] are AVX-512-only.
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4324)  // structure padded due to alignas(64) — intentional
#endif
struct alignas(64) Registers {
    // ---- General-purpose + RIP + RFLAGS + segments ----
    u64 rax = 0, rbx = 0, rcx = 0, rdx = 0;
    u64 rsi = 0, rdi = 0, rbp = 0, rsp = 0;
    u64 r8  = 0, r9  = 0, r10 = 0, r11 = 0;
    u64 r12 = 0, r13 = 0, r14 = 0, r15 = 0;
    u64 rip = 0, rflags = 0;
    u64 cs = 0, ds = 0, es = 0, fs = 0, gs = 0, ss = 0;
    u64 fs_base = 0, gs_base = 0;

    // ---- x87 FPU control + data pointers ----
    u16 fcw    = 0;       // control word
    u16 fsw    = 0;       // status word
    u8  ftw    = 0;       // tag word (FXSAVE abridged form, 1 bit per slot)
    u8  _x87_reserved = 0;
    u16 fop    = 0;       // last x87 opcode
    u64 fip    = 0;       // last x87 instruction pointer
    u64 fdp    = 0;       // last x87 data pointer

    // ST(0)..ST(7): 80-bit extended-precision values stored in 16-byte
    // slots (low 10 bytes are the value; high 6 are reserved). Layout
    // matches the FXSAVE / XSAVE legacy region exactly.
    struct X87Reg { u8 bytes[16] = {}; };
    X87Reg st[8] = {};

    // ---- SSE / AVX / AVX-512 SIMD state ----
    u32 mxcsr      = 0;
    u32 mxcsr_mask = 0;

    // zmm[0..15] alias XMM/YMM/ZMM low halves; zmm[16..31] only
    // populated when AVX-512 is present. Endianness is little-endian
    // byte order matching FXSAVE/XSAVE on disk.
    struct ZmmReg { u8 bytes[64] = {}; };
    ZmmReg zmm[32] = {};

    // K0..K7 mask registers (AVX-512). K0 is the implicit "all-ones"
    // mask in some encodings but we still store its raw value.
    u64 k[8] = {};

    // ---- Debug registers ----
    // DR0..DR3 = breakpoint linear addresses
    // DR4/DR5  = reserved (CPU aliases to DR6/DR7 if CR4.DE=0); we
    //            still keep their slots so indexing matches the manual.
    // DR6      = status (which DR fired, single-step, task-switch, …)
    // DR7      = control (enable bits + length/type per slot)
    u64 dr[8] = {};

    // ---- Validity bitmap ----
    u32 present = 0;

    static constexpr u32 PresentGpr     = 1u << 0;  // GPRs + RIP/RFLAGS + segs + FS/GS_BASE
    static constexpr u32 PresentX87     = 1u << 1;  // FCW/FSW/FTW/FOP/FIP/FDP + ST0..7
    static constexpr u32 PresentSse     = 1u << 2;  // MXCSR + XMM0..15 (low 16B of zmm[0..15])
    static constexpr u32 PresentAvx     = 1u << 3;  // YMM0..15 high 128 (bytes 16..31 of zmm[0..15])
    static constexpr u32 PresentAvx512  = 1u << 4;  // ZMM0..15 high 256 + ZMM16..31 + K0..7
    static constexpr u32 PresentDr      = 1u << 5;  // DR0..DR7
};
#ifdef _MSC_VER
#pragma warning(pop)
#endif

}  // namespace ember::debug
