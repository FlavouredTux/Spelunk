# Debugger

`ember --debug PATH` (Linux ptrace, macOS Mach) launches a REPL-driven
debugger with the same view you decompile against — pseudo-C lines as
the source view, ember's symbol resolution for breakpoints, and the
same `Annotations` pulled in for naming. The point is not to replace
gdb; it's to debug the binary you've been reading without leaving
ember's namespace.

## Launch / attach

```sh
ember --debug ./target -- arg1 arg2     # launch under the debugger
ember --debug --attach-pid 1234         # attach to a running process
```

`--attach-pid` doesn't need a binary path; the REPL resolves symbols
through whichever `--aux-binary` oracles you load (or none, falling
back to raw addresses).

`--ignore-fault-at <hex>` (repeatable) and `--ignore-fault-file <path>`
seed the [ignored-fault filter](#ignored-faults) so a binary that
catches and recovers from `SIGSEGV` / `SIGILL` internally doesn't stop
the debugger on every recoverable hit.

## REPL surface

```
run                     launch the binary (uses --debug PATH and -- args)
attach <pid>            attach to a running process
detach                  detach from the tracee (it keeps running)
kill                    SIGKILL the tracee

b <addr|sym|sym:line>   set a software breakpoint
                        - sym:line resolves a pseudo-C line for the
                          named function (see `code` for numbered lines)
                        - <bin>:<sym> picks one Binary when primary
                          and aux both define the symbol
bp                      list breakpoints
d <id>                  delete a breakpoint

watch <addr> [r|w|rw] [N]
                        hardware data watchpoint at <addr>; N = 1, 2, 4,
                        or 8 (default 8) sets the byte window; default
                        mode is read+write. `r` is accepted but armed
                        as rw — x86 has no read-only mode at the
                        architectural level. Up to 4 active watches
                        (DR0..DR3); cloned threads inherit the set.
wp                      list watchpoints
dwp <id>                delete a watchpoint

catch syscall [<nr|name>...]
                        stop on every `syscall` instruction (entry+exit).
                        With no args, catches every syscall; otherwise only
                        the listed numbers / Linux x86-64 names. Pairs with
                        `--list-syscalls` (static analysis) — this catch
                        covers CFF-buried sites the walker can't resolve.
dcatch                  clear the syscall catchpoint

c                       continue all paused threads
s                       single-step the current thread
regs [all]              print registers ('all' for x87/SSE/AVX/AVX-512/DR)
set <reg> <value>       write rax/.../rip/rflags/cs/.../gs_base.
                        <value> = hex (0x…), decimal, or any address-spec
                        `b` accepts (sym, sym+ofs, bin:sym).

x <addr> [n]            read n bytes (default 16) and hex-dump
poke <addr> <hex>...    write hex bytes — `poke 0x401234 c3` writes a
                        RET, `poke <a> 90 90 90` nops out three bytes

bt | where              backtrace (.eh_frame; RBP-walk fallback)
code | list | l         pseudo-C of the function containing the current PC

aux                     list loaded aux symbol oracles
aux <path>[@hex]        load a Binary as an aux oracle; auto-detect slide
                        (or pin it with @hex). Used for non-ELF code in
                        the tracee — Mach-O / PE blobs an in-process
                        loader mmap'd into anon-rwx memory.

ignored                 list known-recovered fault PCs
ignore <addr>           add a static (un-slid) PC to the ignored set
unignore <addr>         remove a PC
ignore-file <path>      load addrs from a file (hex per line, '#' comments)

threads                 list threads (* marks current)
thread <tid>            switch current thread
help                    this message
q | quit | exit         leave the REPL
```

## Skip-past-trap workflow

The reason `set` and `poke` exist: a breakpoint or fault lands you at
`syscall` or `int3` you want to skip — without detaching to gdb just
to nudge state.

```
(ember) bt
#0  0x401234 sub_401234+0x0
#1  ...
(ember) regs
rax=0x000000000000003c  rbx=0x...  rcx=0x...  rdx=0x...
rip=0x0000000000401234  rflags=0x0000000000000346
(ember) set rip 0x401236      # skip the 2-byte instruction
(ember) c

# Or NOP-out a check before continuing:
(ember) poke 0x401234 90 90 90 90 90
wrote 5 byte(s) at 0x0000000000401234
(ember) c
```

`set rip <value>` accepts any address spec `b` does, so
`set rip target_function+0x40` works.

## Pseudo-C-line breakpoints

```
(ember) code
... (ember prints the pseudo-C with line numbers)
(ember) b sub_4000b0:42        # break at the asm address that maps to line 42
(ember) c
```

The mapping comes from the same `LineMap` the emitter records when it
generates the function's pseudo-C. There's no DWARF requirement —
ember derives line numbers from its own decompile output, not from
the binary's debug info.

## Aux symbol oracles

Binaries that mmap a foreign-format payload into anon memory at runtime
won't show up in `/proc/<pid>/maps` with a useful path. Load them as
aux oracles:

```
(ember) aux /path/to/payload.dylib
(ember) bp
# breakpoints set against `payload:foo` resolve via the aux oracle's symbol
```

Slide is auto-detected by size-matching the binary's mapped extent
against an anon RWX region whose first 4 bytes match the expected
format magic. If detection misfires, pin it: `aux /path@0x7fff80000000`.

## Ignored faults

Some binaries — anti-tamper, JITs, exception-handling tests — catch
and recover from `SIGSEGV` / `SIGILL` / `SIGBUS` / `SIGFPE` internally.
Without help, the debugger stops on every recoverable hit and ruins
the trace. The `ignored` set names PCs whose fault should be silently
forwarded to the tracee's own handler:

```
(ember) ignore 0x401234
(ember) ignored
0x0000000000401234
(ember) c        # SEGV at 0x401234 now passes through; no stop
```

Static (un-slid) addresses; ember slide-corrects at match time using
whichever Binary owns the live PC.

## Stack unwinder

`bt` uses `.eh_frame` / `.debug_frame` CFI when the primary binary has
it (which is essentially always on Linux, even with debug symbols
stripped). Without CFI ember falls back to RBP walking, which is
correct for `-fno-omit-frame-pointer` code and degrades gracefully on
the rest. The choice is automatic per-call.

When CFI + RBP-walk together produce fewer than three frames (Rust
abort-shim chains, control-flow-flattened code, hand-rolled assembler
that doesn't carry CFI), `bt` falls through to a **scavenged unwinder**:
it reads up to 256 qwords from RSP and surfaces every value that
satisfies *both* checks —

1. The address falls inside a known function in one of the loaded
   Binaries (primary or aux).
2. The byte immediately before that address decodes as a `call`
   instruction.

Together those filters kill the bulk of false positives a naïve scan
would surface; what's left is the names you couldn't see otherwise.
The scavenged frames render with a `*scavenged*` suffix so it's
obvious they're best-effort, and the order isn't necessarily
caller→callee:

```
(ember) bt
#0  0x000055...  <fn_a+0x40>
#1  0x000055...  <__rust_start_panic+0x18>
#2  0x000055...  <fn_b+0x80>            *scavenged*
#3  0x000055...  <abort_internal+0x12>  *scavenged*
  (via .eh_frame; *scavenged* frames are best-effort)
```

All `bt` frames now render as `func+0xOFFSET` rather than naked hex
when the PC is inside a known function but not at the entry — true
for return addresses, mid-body breakpoints, and every scavenged
candidate. Pure unknown PCs stay bare so the user can see them.

## Threads

Multi-threaded targets get one event per thread on stops. `threads`
lists them, `thread <tid>` switches the current focus (which `regs`,
`s`, `code`, `bt` operate on). `c` resumes all of them; ember tracks
each thread's signal state independently.

## Ctrl+C

Interrupts the tracee back to the prompt instead of killing the REPL.
Internally ember installs a `SIGINT` handler that calls
`Target::interrupt()` on the active session — without it, the
`PTRACE_O_EXITKILL` linkage we install for safety would take the
tracee down on the first Ctrl+C.

## Hardware watchpoints

`watch <addr> [r|w|rw] [N]` arms a CPU debug-register slot to trap on
data access. The trap fires after a write completes, so the PC at stop
is the *next* instruction; the watched VA comes from the slot itself
(reported in the `Watchpoint #N (DR0) hit: data 0x... touched at PC ...`
event). Use this for the cases breakpoints can't reach:

```
(ember) watch 0x600820 w 8        # DT_INIT_ARRAY[0]: who zeroes it?
(ember) c
Watchpoint #1 (DR0) hit: data 0x0000000000600820 touched at PC ...
                        in thread ...
(ember) bt
#0  0x...   sub_b7410+0x44   <-- the zero-er
#1  ...
```

Same trick for the GOT slot of `environ` (catches the env-check),
the `getenv` PLT thunk (catches first call), or the syscall-instruction
byte once `rax` reaches the value you care about (`watch <syscall_va>`
on the literal `0F 05` byte after a `mov rax, 0x3b`).

Limits worth knowing:

- Only **4 active** watches (DR0..DR3).
- **No read-only mode** on x86 — the CPU's "data read/write" type
  fires on both reads and writes. `watch <a> r` is accepted; it's
  armed as rw and prints a one-line note.
- Sizes are 1, 2, 4, or 8 bytes; the address must be aligned to the
  size. To cover a wider field, set multiple slots.
- New threads spawned via `clone(2)` after the watch is armed get
  the same DR set re-applied — no per-thread re-arming needed.

## Syscall catchpoints

`catch syscall [<nr|name>...]` is the dynamic complement to
`--list-syscalls`. The static walker maps every `mov rax, N; syscall`
shape it can resolve; the catchpoint covers the rest — CFF-buried
sites, indirect rax aliases, JIT-emitted code that the walker never
sees in the static binary.

```
(ember) catch syscall execve exit_group
Catching syscalls: execve(59) exit_group(231)
(ember) c
Syscall ENTRY execve(59) at PC 0x... in thread ...
(ember) bt          # the actual call site, regardless of how
                    # rax got loaded
(ember) c
Syscall EXIT  execve(59) at PC 0x... in thread ...
(ember) dcatch      # clear when done
```

Behind the scenes ember sets `PTRACE_O_TRACESYSGOOD` so syscall-stops
arrive as `SIGTRAP | 0x80` and never collide with int3 hits or DR
watchpoints. With a non-empty filter, sites whose `orig_rax` doesn't
match the user's set are silently re-issued as `PTRACE_SYSCALL` —
the user only sees the syscalls they asked for.

## Limits

- macOS backend works for process control, memory, registers,
  breakpoints, and events; aux-binary slide detection, hardware
  watchpoints, and syscall catchpoints are Linux-only for now (no
  `/proc/<pid>/maps` equivalent we lean on; macOS would route
  watchpoints through `thread_set_state` with `x86_DEBUG_STATE64`,
  and Mach has no clean syscall-trap analogue without per-syscall
  exception ports).
- No remote target mode; everything is in-process ptrace / Mach.
