#pragma once

#include <optional>
#include <unordered_map>
#include <vector>

#include <spelunk/analysis/arity.hpp>

namespace spelunk {

struct Function;

// x86 Windows conventions are per-function, rather than per-image. Keep
// stack cleanup separate from arity: RET n includes unused stack arguments.
struct X86FunctionInfo {
    Abi abi = Abi::Win32Cdecl;
    u16 callee_pop = 0;
    std::vector<InferredArgument> arguments;
    // Caller-saved registers the function never writes, directly or through
    // its own calls. gcc's -fipa-ra keeps values live in them across calls.
    std::vector<Reg> preserved;
};

// Convention, stack cleanup and arguments of the function or import at
// `entry`. Memoized per binary.
[[nodiscard]] X86FunctionInfo
analyze_x86_function(const Binary& binary, addr_t entry);

// Bytes a call to `target` removes from the stack on return: RET n for code
// in the image, the declared convention for imports. Nullopt when the image
// says nothing, as for an undecorated system-DLL import with no known
// prototype. Never lifts, so lifters can ask it per call site.
[[nodiscard]] std::optional<u16>
x86_callee_pop(const Binary& binary, addr_t target);

// Stack bytes popped by each call in `fn`, keyed by call address. When the
// callee is silent the caller's code answers: `sub esp, n` straight after
// the call re-reserves what the callee popped, and a stdcall import pops
// the arguments pushed for it.
[[nodiscard]] std::unordered_map<addr_t, u16>
x86_call_pops(const Binary& binary, const Function& fn);

// A value one of those helpers leaves in esp or ebp: an offset from the
// caller's esp just before the call or from its ebp, or the word stored there.
struct X86FrameValue {
    enum class Base : u8 { CallSp, CallerFp };
    Base base = Base::CallSp;
    i32  offset = 0;
    bool load = false;
};

// MSVC builds and tears down frames in shared helpers - __SEH_prolog4,
// __EH_prolog3, __SEH_epilog4 and their kin - called as
// `push size; push scope_table; call __SEH_prolog4`. Such a call sets the
// caller's ebp and esp rather than returning balanced.
struct X86FrameHelper {
    X86FrameValue sp;
    X86FrameValue fp;
    std::vector<Reg> clobbers;       // registers it leaves changed (eax..edx)
    bool links_seh = false;          // links an exception registration into fs:[0]
    std::optional<u32> handler;      // that registration's handler
};

// Calls in `fn` into frame helpers, keyed by call address. Found by
// simulating each straight-line callee from the constants its call site
// pushes, so stripped images need no names.
[[nodiscard]] std::unordered_map<addr_t, X86FrameHelper>
x86_frame_helpers(const Binary& binary, const Function& fn);

// Caller-saved registers each call in `fn` leaves untouched, keyed by call
// address. Only direct calls into the image qualify.
[[nodiscard]] std::unordered_map<addr_t, std::vector<Reg>>
x86_call_preserved(const Binary& binary, const Function& fn);

}  // namespace spelunk
