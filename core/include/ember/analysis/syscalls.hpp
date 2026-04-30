#pragma once

#include <optional>
#include <string>
#include <vector>

#include <ember/binary/binary.hpp>
#include <ember/common/types.hpp>

namespace ember {

// One `syscall` instruction inside a function, paired with whatever
// we could recover about which syscall it is. `syscall_nr` is set
// when we found a constant write to rax/eax dominating the syscall
// site within the function — the typical `mov eax, N; syscall`
// shape. `name` is non-empty when `syscall_nr` matched a known
// Linux x86-64 syscall number.
//
// Misses: an indirect rax (e.g. CFF state-machine that buries the
// number through a register-aliased copy) shows as `syscall_nr =
// nullopt`. The site is still surfaced so callers see *where* the
// syscall is, even when *which* one stays opaque.
struct SyscallSite {
    addr_t              va           = 0;
    u64                 file_offset  = 0;
    std::optional<u32>  syscall_nr;
    std::string         name;
};

// Walk the function at `fn_va`, decode every `syscall` instruction
// reachable from it, and return one entry per site. Trace rax back
// through Assign / Trunc / ZExt chains to find the most recent
// constant write; a non-Imm result leaves the site unresolved.
//
// The walk is per-function (no inlining across calls), so a syscall
// number set in a different function and only carried in via a reg
// argument shows as unresolved. That's fine — for CFF and obfuscated
// code the user mostly wants "where are the syscalls" + "the obvious
// ones" first, and follows up with the unresolved sites by hand.
[[nodiscard]] std::vector<SyscallSite>
analyze_syscalls(const Binary& b, addr_t fn_va);

// Linux x86-64 syscall name lookup. Returns empty for unknown
// numbers; the caller can render `?` or the raw integer.
[[nodiscard]] std::string_view linux_x64_syscall_name(u32 nr) noexcept;

}  // namespace ember
