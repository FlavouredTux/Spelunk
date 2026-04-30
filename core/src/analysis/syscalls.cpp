#include <ember/analysis/syscalls.hpp>

#include <array>
#include <optional>
#include <string_view>

#include <ember/analysis/cfg_builder.hpp>
#include <ember/analysis/function.hpp>
#include <ember/binary/binary.hpp>
#include <ember/binary/section.hpp>
#include <ember/disasm/decoder.hpp>
#include <ember/disasm/x64_decoder.hpp>
#include <ember/ir/ssa.hpp>

namespace ember {

namespace {

// Linux x86-64 syscall name table. Subset that covers ~99% of real
// userspace usage; gaps in the range render as the raw integer with
// no name. Indexed directly by syscall number — sparse entries are
// nullptr.
//
// Sourced from arch/x86/entry/syscalls/syscall_64.tbl. Numbers above
// the end of this table (newer syscalls) just go nameless rather
// than mis-tagged.
constexpr const char* kLinuxX64Syscalls[] = {
    "read",                    // 0
    "write",                   // 1
    "open",                    // 2
    "close",                   // 3
    "stat",                    // 4
    "fstat",                   // 5
    "lstat",                   // 6
    "poll",                    // 7
    "lseek",                   // 8
    "mmap",                    // 9
    "mprotect",                // 10
    "munmap",                  // 11
    "brk",                     // 12
    "rt_sigaction",            // 13
    "rt_sigprocmask",          // 14
    "rt_sigreturn",            // 15
    "ioctl",                   // 16
    "pread64",                 // 17
    "pwrite64",                // 18
    "readv",                   // 19
    "writev",                  // 20
    "access",                  // 21
    "pipe",                    // 22
    "select",                  // 23
    "sched_yield",             // 24
    "mremap",                  // 25
    "msync",                   // 26
    "mincore",                 // 27
    "madvise",                 // 28
    "shmget",                  // 29
    "shmat",                   // 30
    "shmctl",                  // 31
    "dup",                     // 32
    "dup2",                    // 33
    "pause",                   // 34
    "nanosleep",               // 35
    "getitimer",               // 36
    "alarm",                   // 37
    "setitimer",               // 38
    "getpid",                  // 39
    "sendfile",                // 40
    "socket",                  // 41
    "connect",                 // 42
    "accept",                  // 43
    "sendto",                  // 44
    "recvfrom",                // 45
    "sendmsg",                 // 46
    "recvmsg",                 // 47
    "shutdown",                // 48
    "bind",                    // 49
    "listen",                  // 50
    "getsockname",             // 51
    "getpeername",             // 52
    "socketpair",              // 53
    "setsockopt",              // 54
    "getsockopt",              // 55
    "clone",                   // 56
    "fork",                    // 57
    "vfork",                   // 58
    "execve",                  // 59
    "exit",                    // 60
    "wait4",                   // 61
    "kill",                    // 62
    "uname",                   // 63
    "semget",                  // 64
    "semop",                   // 65
    "semctl",                  // 66
    "shmdt",                   // 67
    "msgget",                  // 68
    "msgsnd",                  // 69
    "msgrcv",                  // 70
    "msgctl",                  // 71
    "fcntl",                   // 72
    "flock",                   // 73
    "fsync",                   // 74
    "fdatasync",               // 75
    "truncate",                // 76
    "ftruncate",               // 77
    "getdents",                // 78
    "getcwd",                  // 79
    "chdir",                   // 80
    "fchdir",                  // 81
    "rename",                  // 82
    "mkdir",                   // 83
    "rmdir",                   // 84
    "creat",                   // 85
    "link",                    // 86
    "unlink",                  // 87
    "symlink",                 // 88
    "readlink",                // 89
    "chmod",                   // 90
    "fchmod",                  // 91
    "chown",                   // 92
    "fchown",                  // 93
    "lchown",                  // 94
    "umask",                   // 95
    "gettimeofday",            // 96
    "getrlimit",               // 97
    "getrusage",               // 98
    "sysinfo",                 // 99
    "times",                   // 100
    "ptrace",                  // 101
    "getuid",                  // 102
    "syslog",                  // 103
    "getgid",                  // 104
    "setuid",                  // 105
    "setgid",                  // 106
    "geteuid",                 // 107
    "getegid",                 // 108
    "setpgid",                 // 109
    "getppid",                 // 110
    "getpgrp",                 // 111
    "setsid",                  // 112
    "setreuid",                // 113
    "setregid",                // 114
    "getgroups",               // 115
    "setgroups",               // 116
    "setresuid",               // 117
    "getresuid",               // 118
    "setresgid",               // 119
    "getresgid",               // 120
    "getpgid",                 // 121
    "setfsuid",                // 122
    "setfsgid",                // 123
    "getsid",                  // 124
    "capget",                  // 125
    "capset",                  // 126
    "rt_sigpending",           // 127
    "rt_sigtimedwait",         // 128
    "rt_sigqueueinfo",         // 129
    "rt_sigsuspend",           // 130
    "sigaltstack",             // 131
    "utime",                   // 132
    "mknod",                   // 133
    "uselib",                  // 134
    "personality",             // 135
    "ustat",                   // 136
    "statfs",                  // 137
    "fstatfs",                 // 138
    "sysfs",                   // 139
    "getpriority",             // 140
    "setpriority",             // 141
    "sched_setparam",          // 142
    "sched_getparam",          // 143
    "sched_setscheduler",      // 144
    "sched_getscheduler",      // 145
    "sched_get_priority_max",  // 146
    "sched_get_priority_min",  // 147
    "sched_rr_get_interval",   // 148
    "mlock",                   // 149
    "munlock",                 // 150
    "mlockall",                // 151
    "munlockall",              // 152
    "vhangup",                 // 153
    "modify_ldt",              // 154
    "pivot_root",              // 155
    "_sysctl",                 // 156
    "prctl",                   // 157
    "arch_prctl",              // 158
    "adjtimex",                // 159
    "setrlimit",               // 160
    "chroot",                  // 161
    "sync",                    // 162
    "acct",                    // 163
    "settimeofday",            // 164
    "mount",                   // 165
    "umount2",                 // 166
    "swapon",                  // 167
    "swapoff",                 // 168
    "reboot",                  // 169
    "sethostname",             // 170
    "setdomainname",           // 171
    "iopl",                    // 172
    "ioperm",                  // 173
    "create_module",           // 174
    "init_module",             // 175
    "delete_module",           // 176
    "get_kernel_syms",         // 177
    "query_module",            // 178
    "quotactl",                // 179
    "nfsservctl",              // 180
    "getpmsg",                 // 181
    "putpmsg",                 // 182
    "afs_syscall",             // 183
    "tuxcall",                 // 184
    "security",                // 185
    "gettid",                  // 186
    "readahead",               // 187
    "setxattr",                // 188
    "lsetxattr",               // 189
    "fsetxattr",               // 190
    "getxattr",                // 191
    "lgetxattr",               // 192
    "fgetxattr",               // 193
    "listxattr",               // 194
    "llistxattr",              // 195
    "flistxattr",              // 196
    "removexattr",             // 197
    "lremovexattr",            // 198
    "fremovexattr",            // 199
    "tkill",                   // 200
    "time",                    // 201
    "futex",                   // 202
    "sched_setaffinity",       // 203
    "sched_getaffinity",       // 204
    "set_thread_area",         // 205
    "io_setup",                // 206
    "io_destroy",              // 207
    "io_getevents",            // 208
    "io_submit",               // 209
    "io_cancel",               // 210
    "get_thread_area",         // 211
    "lookup_dcookie",          // 212
    "epoll_create",            // 213
    "epoll_ctl_old",           // 214
    "epoll_wait_old",          // 215
    "remap_file_pages",        // 216
    "getdents64",              // 217
    "set_tid_address",         // 218
    "restart_syscall",         // 219
    "semtimedop",              // 220
    "fadvise64",               // 221
    "timer_create",            // 222
    "timer_settime",           // 223
    "timer_gettime",           // 224
    "timer_getoverrun",        // 225
    "timer_delete",            // 226
    "clock_settime",           // 227
    "clock_gettime",           // 228
    "clock_getres",            // 229
    "clock_nanosleep",         // 230
    "exit_group",              // 231
    "epoll_wait",              // 232
    "epoll_ctl",               // 233
    "tgkill",                  // 234
    "utimes",                  // 235
    "vserver",                 // 236
    "mbind",                   // 237
    "set_mempolicy",           // 238
    "get_mempolicy",           // 239
    "mq_open",                 // 240
    "mq_unlink",               // 241
    "mq_timedsend",            // 242
    "mq_timedreceive",         // 243
    "mq_notify",               // 244
    "mq_getsetattr",           // 245
    "kexec_load",              // 246
    "waitid",                  // 247
    "add_key",                 // 248
    "request_key",             // 249
    "keyctl",                  // 250
    "ioprio_set",              // 251
    "ioprio_get",              // 252
    "inotify_init",            // 253
    "inotify_add_watch",       // 254
    "inotify_rm_watch",        // 255
    "migrate_pages",           // 256
    "openat",                  // 257
    "mkdirat",                 // 258
    "mknodat",                 // 259
    "fchownat",                // 260
    "futimesat",               // 261
    "newfstatat",              // 262
    "unlinkat",                // 263
    "renameat",                // 264
    "linkat",                  // 265
    "symlinkat",               // 266
    "readlinkat",              // 267
    "fchmodat",                // 268
    "faccessat",               // 269
    "pselect6",                // 270
    "ppoll",                   // 271
    "unshare",                 // 272
    "set_robust_list",         // 273
    "get_robust_list",         // 274
    "splice",                  // 275
    "tee",                     // 276
    "sync_file_range",         // 277
    "vmsplice",                // 278
    "move_pages",              // 279
    "utimensat",               // 280
    "epoll_pwait",             // 281
    "signalfd",                // 282
    "timerfd_create",          // 283
    "eventfd",                 // 284
    "fallocate",               // 285
    "timerfd_settime",         // 286
    "timerfd_gettime",         // 287
    "accept4",                 // 288
    "signalfd4",               // 289
    "eventfd2",                // 290
    "epoll_create1",           // 291
    "dup3",                    // 292
    "pipe2",                   // 293
    "inotify_init1",           // 294
    "preadv",                  // 295
    "pwritev",                 // 296
    "rt_tgsigqueueinfo",       // 297
    "perf_event_open",         // 298
    "recvmmsg",                // 299
    "fanotify_init",           // 300
    "fanotify_mark",           // 301
    "prlimit64",               // 302
    "name_to_handle_at",       // 303
    "open_by_handle_at",       // 304
    "clock_adjtime",           // 305
    "syncfs",                  // 306
    "sendmmsg",                // 307
    "setns",                   // 308
    "getcpu",                  // 309
    "process_vm_readv",        // 310
    "process_vm_writev",       // 311
    "kcmp",                    // 312
    "finit_module",            // 313
    "sched_setattr",           // 314
    "sched_getattr",           // 315
    "renameat2",               // 316
    "seccomp",                 // 317
    "getrandom",               // 318
    "memfd_create",            // 319
    "kexec_file_load",         // 320
    "bpf",                     // 321
    "execveat",                // 322
    "userfaultfd",             // 323
    "membarrier",              // 324
    "mlock2",                  // 325
    "copy_file_range",         // 326
    "preadv2",                 // 327
    "pwritev2",                // 328
    "pkey_mprotect",           // 329
    "pkey_alloc",              // 330
    "pkey_free",               // 331
    "statx",                   // 332
    "io_pgetevents",           // 333
    "rseq",                    // 334
};

constexpr u32 kSyscallTableSize =
    sizeof(kLinuxX64Syscalls) / sizeof(kLinuxX64Syscalls[0]);

// True when `r` is rax / eax / ax / al — the architectural register
// the syscall ABI uses to pass the syscall number. We treat all four
// width views as the same write target, since `mov eax, N` clears the
// high 32 bits of rax (per x86-64 zero-extend rule) and is the
// canonical way compilers emit small syscall numbers.
[[nodiscard]] bool is_rax_family(Reg r) noexcept {
    return canonical_reg(r) == Reg::Rax;
}

// Walk the function's blocks. For each `syscall`, scan back through
// preceding instructions in the same block for a `mov rax/eax/ax/al,
// imm` write. If none found, follow a single CFG predecessor (one
// hop) since `mov eax, N; jmp; …; syscall` is the common shape under
// minor obfuscation. More than one predecessor → ambiguous, leave
// unresolved.
[[nodiscard]] std::optional<u64>
trace_rax_const(const Function& fn, std::size_t block_idx,
                std::size_t inst_idx_excl) {
    const auto& bb = fn.blocks[block_idx];
    auto scan_block = [&](const BasicBlock& b, std::size_t end) -> std::optional<u64> {
        for (std::size_t k = end; k-- > 0;) {
            const auto& ins = b.instructions[k];
            if (ins.num_operands < 1) continue;
            const auto& dst = ins.operands[0];
            if (dst.kind != Operand::Kind::Register) continue;
            if (!is_rax_family(dst.reg)) continue;
            // `mov rax/eax, imm`: tracked. Other writes (xor eax,eax;
            // pop rax; arithmetic) are not constant-resolvable here
            // and abort the trace — including xor-self, which DOES
            // produce zero but isn't always the syscall number the
            // caller intended (zero is `read`, the most common false
            // positive in pre-syscall ABI shuffling).
            if (ins.mnemonic == Mnemonic::Mov && ins.num_operands >= 2 &&
                ins.operands[1].kind == Operand::Kind::Immediate) {
                return static_cast<u64>(ins.operands[1].imm.value);
            }
            // Any other rax write clobbers our trace.
            return std::nullopt;
        }
        return std::nullopt;
    };
    if (auto v = scan_block(bb, inst_idx_excl); v) return v;
    if (bb.predecessors.size() != 1) return std::nullopt;
    auto pit = fn.block_at.find(bb.predecessors.front());
    if (pit == fn.block_at.end()) return std::nullopt;
    const auto& pbb = fn.blocks[pit->second];
    return scan_block(pbb, pbb.instructions.size());
}

}  // namespace

std::string_view linux_x64_syscall_name(u32 nr) noexcept {
    if (nr >= kSyscallTableSize) return {};
    const char* p = kLinuxX64Syscalls[nr];
    return p ? std::string_view{p} : std::string_view{};
}

std::vector<SyscallSite>
analyze_syscalls(const Binary& b, addr_t fn_va) {
    auto dec_r = make_decoder(b);
    if (!dec_r) return {};
    const Decoder& dec = **dec_r;
    const CfgBuilder builder(b, dec);
    auto fn_r = builder.build(fn_va);
    if (!fn_r) return {};
    const Function& fn = *fn_r;

    std::vector<SyscallSite> out;
    for (std::size_t bi = 0; bi < fn.blocks.size(); ++bi) {
        const auto& bb = fn.blocks[bi];
        for (std::size_t ii = 0; ii < bb.instructions.size(); ++ii) {
            const auto& ins = bb.instructions[ii];
            if (ins.mnemonic != Mnemonic::Syscall) continue;
            SyscallSite s;
            s.va = ins.address;
            // file_offset: convert the VA to its on-disk byte offset
            // by walking the binary's sections. The Section ABI gives
            // us file_offset directly when the address is mapped.
            for (const auto& sec : b.sections()) {
                if (ins.address >= sec.vaddr &&
                    ins.address <  sec.vaddr + sec.size &&
                    sec.file_offset > 0) {
                    s.file_offset = sec.file_offset +
                                    (ins.address - sec.vaddr);
                    break;
                }
            }
            if (auto v = trace_rax_const(fn, bi, ii); v) {
                if (*v <= 0xFFFFFFFFull) {
                    s.syscall_nr = static_cast<u32>(*v);
                    auto nm = linux_x64_syscall_name(*s.syscall_nr);
                    if (!nm.empty()) s.name = std::string{nm};
                }
            }
            out.push_back(std::move(s));
        }
    }
    return out;
}

}  // namespace ember
