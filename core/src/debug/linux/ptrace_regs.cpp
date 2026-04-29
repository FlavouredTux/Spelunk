// Register read/write for the Linux ptrace backend on x86-64.
//
// Three sources combine into a single Registers snapshot:
//   GPR + RIP/RFLAGS + segs   ← PTRACE_GETREGS    (user_regs_struct)
//   x87 + MXCSR + XMM0..15    ← PTRACE_GETFPREGS  (FXSAVE legacy region)
//   YMM/ZMM/K mask registers  ← PTRACE_GETREGSET(NT_X86_XSTATE)
//   DR0..DR7                  ← PTRACE_PEEKUSER per slot
//
// XSAVE component offsets within the area come from CPUID leaf 0xD.
// The kernel returns the standard (non-compacted) XSAVE layout for
// PTRACE_GETREGSET so EBX from CPUID(0xD, n) is the right offset.

#include "ptrace_target.hpp"

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <unistd.h>

#include <cpuid.h>
#include <elf.h>

namespace ember::debug::linux_ {

namespace {

[[nodiscard]] Error errno_io(const char* op) {
    return Error::io(std::string(op) + ": " + std::strerror(errno));
}

// Cached XSAVE area layout for the host CPU. CPUID(0xD, 0) gives the
// total area size and the user-state XCR0 bitmap; CPUID(0xD, n) for
// n >= 2 gives per-component offset/size within the area.
struct XSaveLayout {
    u64  xcr0    = 0;     // bits set = user-state components supported
    u32  size    = 0;     // total XSAVE area bytes for current XCR0
    u32  off[64] = {};    // byte offset within area, per component
    u32  sz[64]  = {};    // component size in bytes
    bool valid   = false;
};

XSaveLayout query_xsave_layout_once() {
    XSaveLayout l{};
    unsigned a = 0, b = 0, c = 0, d = 0;
    if (!__get_cpuid_count(0xD, 0, &a, &b, &c, &d)) return l;
    l.xcr0 = (static_cast<u64>(d) << 32) | a;
    l.size = b;
    for (unsigned i = 2; i < 64; ++i) {
        if (!(l.xcr0 & (1ULL << i))) continue;
        if (!__get_cpuid_count(0xD, i, &a, &b, &c, &d)) continue;
        l.sz[i]  = a;
        l.off[i] = b;
    }
    l.valid = true;
    return l;
}

const XSaveLayout& xsave_layout() {
    static const XSaveLayout layout = query_xsave_layout_once();
    return layout;
}

// ---- Conversion: kernel structs ↔ Registers ------------------------

void from_user_regs(const user_regs_struct& u, Registers& r) {
    r.rax = u.rax; r.rbx = u.rbx; r.rcx = u.rcx; r.rdx = u.rdx;
    r.rsi = u.rsi; r.rdi = u.rdi; r.rbp = u.rbp; r.rsp = u.rsp;
    r.r8  = u.r8;  r.r9  = u.r9;  r.r10 = u.r10; r.r11 = u.r11;
    r.r12 = u.r12; r.r13 = u.r13; r.r14 = u.r14; r.r15 = u.r15;
    r.rip = u.rip; r.rflags = u.eflags;
    r.cs = u.cs; r.ds = u.ds; r.es = u.es;
    r.fs = u.fs; r.gs = u.gs; r.ss = u.ss;
    r.fs_base = u.fs_base; r.gs_base = u.gs_base;
}

void to_user_regs(const Registers& r, user_regs_struct& u) {
    u.rax = r.rax; u.rbx = r.rbx; u.rcx = r.rcx; u.rdx = r.rdx;
    u.rsi = r.rsi; u.rdi = r.rdi; u.rbp = r.rbp; u.rsp = r.rsp;
    u.r8  = r.r8;  u.r9  = r.r9;  u.r10 = r.r10; u.r11 = r.r11;
    u.r12 = r.r12; u.r13 = r.r13; u.r14 = r.r14; u.r15 = r.r15;
    u.rip = r.rip; u.eflags = r.rflags;
    u.cs = r.cs; u.ds = r.ds; u.es = r.es;
    u.fs = r.fs; u.gs = r.gs; u.ss = r.ss;
    u.fs_base = r.fs_base; u.gs_base = r.gs_base;
}

void from_user_fp(const user_fpregs_struct& fp, Registers& r) {
    r.fcw = fp.cwd;
    r.fsw = fp.swd;
    r.ftw = static_cast<u8>(fp.ftw);
    r.fop = fp.fop;
    r.fip = fp.rip;
    r.fdp = fp.rdp;
    r.mxcsr      = fp.mxcsr;
    r.mxcsr_mask = fp.mxcr_mask;
    std::memcpy(r.st, fp.st_space, sizeof(r.st));
    for (int i = 0; i < 16; ++i) {
        std::memcpy(r.zmm[i].bytes, &fp.xmm_space[i * 4], 16);
    }
}

void to_user_fp(const Registers& r, user_fpregs_struct& fp) {
    fp.cwd = r.fcw;
    fp.swd = r.fsw;
    fp.ftw = r.ftw;
    fp.fop = r.fop;
    fp.rip = r.fip;
    fp.rdp = r.fdp;
    fp.mxcsr     = r.mxcsr;
    fp.mxcr_mask = r.mxcsr_mask;
    std::memcpy(fp.st_space, r.st, sizeof(r.st));
    for (int i = 0; i < 16; ++i) {
        std::memcpy(&fp.xmm_space[i * 4], r.zmm[i].bytes, 16);
    }
}

// ---- XSAVE area unpack/pack ---------------------------------------

constexpr unsigned kStateAvxYmmHi    = 2;  // YMM0..15 high 128 bits
constexpr unsigned kStateAvx512Opmask = 5; // K0..K7
constexpr unsigned kStateAvx512ZmmHi  = 6; // ZMM0..15 high 256 bits
constexpr unsigned kStateAvx512Hi16   = 7; // ZMM16..31 (full 512)

void unpack_xsave(const std::byte* buf, std::size_t len, Registers& r) {
    const auto& L = xsave_layout();
    if (!L.valid || len < 520) return;

    u64 xstate_bv = 0;
    std::memcpy(&xstate_bv, buf + 512, 8);

    // ---- AVX YMM_Hi128 ----
    if ((L.xcr0 & (1ULL << kStateAvxYmmHi)) && L.off[kStateAvxYmmHi] != 0) {
        const std::size_t off = L.off[kStateAvxYmmHi];
        if (xstate_bv & (1ULL << kStateAvxYmmHi)) {
            if (len >= off + 16 * 16) {
                for (int i = 0; i < 16; ++i) {
                    std::memcpy(r.zmm[i].bytes + 16, buf + off + i * 16, 16);
                }
            }
        }
        // Init state for YMM_Hi128 is zero — Registers default already is.
        r.present |= Registers::PresentAvx;
    }

    const bool avx512_supported =
        (L.xcr0 & (1ULL << kStateAvx512Opmask)) &&
        (L.xcr0 & (1ULL << kStateAvx512ZmmHi))  &&
        (L.xcr0 & (1ULL << kStateAvx512Hi16));
    if (!avx512_supported) return;

    if (xstate_bv & (1ULL << kStateAvx512Opmask)) {
        const std::size_t off = L.off[kStateAvx512Opmask];
        if (off != 0 && len >= off + 8 * 8) {
            for (int i = 0; i < 8; ++i) {
                std::memcpy(&r.k[i], buf + off + i * 8, 8);
            }
        }
    }
    if (xstate_bv & (1ULL << kStateAvx512ZmmHi)) {
        const std::size_t off = L.off[kStateAvx512ZmmHi];
        if (off != 0 && len >= off + 16 * 32) {
            for (int i = 0; i < 16; ++i) {
                std::memcpy(r.zmm[i].bytes + 32, buf + off + i * 32, 32);
            }
        }
    }
    if (xstate_bv & (1ULL << kStateAvx512Hi16)) {
        const std::size_t off = L.off[kStateAvx512Hi16];
        if (off != 0 && len >= off + 16 * 64) {
            for (int i = 0; i < 16; ++i) {
                std::memcpy(r.zmm[16 + i].bytes, buf + off + i * 64, 64);
            }
        }
    }
    r.present |= Registers::PresentAvx512;
}

void pack_xsave(const Registers& r, std::byte* buf, std::size_t len) {
    const auto& L = xsave_layout();
    if (!L.valid || len < 520) return;

    u64 xstate_bv = 0;
    std::memcpy(&xstate_bv, buf + 512, 8);

    if ((r.present & Registers::PresentAvx) &&
        (L.xcr0 & (1ULL << kStateAvxYmmHi)) && L.off[kStateAvxYmmHi] != 0) {
        const std::size_t off = L.off[kStateAvxYmmHi];
        if (len >= off + 16 * 16) {
            for (int i = 0; i < 16; ++i) {
                std::memcpy(buf + off + i * 16, r.zmm[i].bytes + 16, 16);
            }
            xstate_bv |= 1ULL << kStateAvxYmmHi;
        }
    }
    if ((r.present & Registers::PresentAvx512) &&
        (L.xcr0 & (1ULL << kStateAvx512Opmask))) {
        const std::size_t off = L.off[kStateAvx512Opmask];
        if (off != 0 && len >= off + 8 * 8) {
            for (int i = 0; i < 8; ++i) {
                std::memcpy(buf + off + i * 8, &r.k[i], 8);
            }
            xstate_bv |= 1ULL << kStateAvx512Opmask;
        }
    }
    if ((r.present & Registers::PresentAvx512) &&
        (L.xcr0 & (1ULL << kStateAvx512ZmmHi))) {
        const std::size_t off = L.off[kStateAvx512ZmmHi];
        if (off != 0 && len >= off + 16 * 32) {
            for (int i = 0; i < 16; ++i) {
                std::memcpy(buf + off + i * 32, r.zmm[i].bytes + 32, 32);
            }
            xstate_bv |= 1ULL << kStateAvx512ZmmHi;
        }
    }
    if ((r.present & Registers::PresentAvx512) &&
        (L.xcr0 & (1ULL << kStateAvx512Hi16))) {
        const std::size_t off = L.off[kStateAvx512Hi16];
        if (off != 0 && len >= off + 16 * 64) {
            for (int i = 0; i < 16; ++i) {
                std::memcpy(buf + off + i * 64, r.zmm[16 + i].bytes, 64);
            }
            xstate_bv |= 1ULL << kStateAvx512Hi16;
        }
    }

    std::memcpy(buf + 512, &xstate_bv, 8);
}

}  // namespace

Result<Registers> LinuxTarget::get_regs(ThreadId tid) {
    Registers r{};
    const pid_t kt = static_cast<pid_t>(tid);

    user_regs_struct ur{};
    if (::ptrace(PTRACE_GETREGS, kt, nullptr, &ur) < 0) {
        return std::unexpected(errno_io("getregs"));
    }
    from_user_regs(ur, r);
    r.present |= Registers::PresentGpr;

    user_fpregs_struct fp{};
    if (::ptrace(PTRACE_GETFPREGS, kt, nullptr, &fp) >= 0) {
        from_user_fp(fp, r);
        r.present |= Registers::PresentX87 | Registers::PresentSse;
    }

    const auto& L = xsave_layout();
    if (L.valid && L.size >= 576) {
        std::vector<std::byte> buf(L.size);
        ::iovec iov{buf.data(), buf.size()};
        if (::ptrace(PTRACE_GETREGSET, kt,
                     reinterpret_cast<void*>(static_cast<std::uintptr_t>(NT_X86_XSTATE)),
                     &iov) >= 0) {
            unpack_xsave(buf.data(), iov.iov_len, r);
        }
    }

    constexpr std::size_t kDrBase = offsetof(struct user, u_debugreg[0]);
    constexpr std::size_t kDrStride = sizeof(reinterpret_cast<struct user*>(0)->u_debugreg[0]);
    bool dr_ok = true;
    for (int i = 0; i < 8; ++i) {
        const std::size_t off = kDrBase + static_cast<std::size_t>(i) * kDrStride;
        errno = 0;
        const long v = ::ptrace(PTRACE_PEEKUSER, kt,
                                reinterpret_cast<void*>(off), nullptr);
        if (v == -1 && errno != 0) { dr_ok = false; break; }
        r.dr[i] = static_cast<u64>(v);
    }
    if (dr_ok) r.present |= Registers::PresentDr;

    return r;
}

Result<void> LinuxTarget::set_regs(ThreadId tid, const Registers& r) {
    const pid_t kt = static_cast<pid_t>(tid);

    if (r.present & Registers::PresentGpr) {
        user_regs_struct ur{};
        to_user_regs(r, ur);
        if (::ptrace(PTRACE_SETREGS, kt, nullptr, &ur) < 0) {
            return std::unexpected(errno_io("setregs"));
        }
    }

    // For x87/SSE/AVX/AVX-512 we round-trip through the XSAVE area
    // when any extended component is requested, so we don't trash
    // unrelated state. Pure-x87/SSE writes can shortcut to SETFPREGS.
    const u32 ext = Registers::PresentAvx | Registers::PresentAvx512;
    const u32 leg = Registers::PresentX87 | Registers::PresentSse;

    if (r.present & ext) {
        const auto& L = xsave_layout();
        if (L.valid && L.size >= 576) {
            std::vector<std::byte> buf(L.size);
            ::iovec iov{buf.data(), buf.size()};
            if (::ptrace(PTRACE_GETREGSET, kt,
                         reinterpret_cast<void*>(static_cast<std::uintptr_t>(NT_X86_XSTATE)),
                         &iov) < 0) {
                return std::unexpected(errno_io("getregset (read-modify-write)"));
            }
            // Overlay legacy region from r if requested.
            if (r.present & leg) {
                user_fpregs_struct fp{};
                std::memcpy(&fp, buf.data(), sizeof(fp));
                to_user_fp(r, fp);
                std::memcpy(buf.data(), &fp, sizeof(fp));
                u64 xstate_bv = 0;
                std::memcpy(&xstate_bv, buf.data() + 512, 8);
                if (r.present & Registers::PresentX87) xstate_bv |= 1ULL << 0;
                if (r.present & Registers::PresentSse) xstate_bv |= 1ULL << 1;
                std::memcpy(buf.data() + 512, &xstate_bv, 8);
            }
            pack_xsave(r, buf.data(), iov.iov_len);
            iov.iov_len = buf.size();
            if (::ptrace(PTRACE_SETREGSET, kt,
                         reinterpret_cast<void*>(static_cast<std::uintptr_t>(NT_X86_XSTATE)),
                         &iov) < 0) {
                return std::unexpected(errno_io("setregset"));
            }
        }
    } else if (r.present & leg) {
        user_fpregs_struct fp{};
        to_user_fp(r, fp);
        if (::ptrace(PTRACE_SETFPREGS, kt, nullptr, &fp) < 0) {
            return std::unexpected(errno_io("setfpregs"));
        }
    }

    if (r.present & Registers::PresentDr) {
        constexpr std::size_t kDrBase = offsetof(struct user, u_debugreg[0]);
        constexpr std::size_t kDrStride = sizeof(reinterpret_cast<struct user*>(0)->u_debugreg[0]);
        for (int i = 0; i < 8; ++i) {
            const std::size_t off = kDrBase + static_cast<std::size_t>(i) * kDrStride;
            if (::ptrace(PTRACE_POKEUSER, kt,
                         reinterpret_cast<void*>(off),
                         reinterpret_cast<void*>(static_cast<std::uintptr_t>(r.dr[i]))) < 0) {
                return std::unexpected(errno_io("pokeuser (dr)"));
            }
        }
    }

    return {};
}

}  // namespace ember::debug::linux_
