#pragma once

#include <vector>

#include <ember/binary/binary.hpp>
#include <ember/common/types.hpp>
#include <ember/disasm/register.hpp>

namespace ember {

// One detected interpreter-style "VM dispatcher" inside a binary,
// reported with enough anatomy to drive bytecode lifting (phase 1b/1c).
// Canonical shape:
//
//   movzx <idx>, byte ptr [<pc> + disp]    ; load opcode byte
//   add   <pc>, <pc_advance>                ; advance the PC (optional;
//                                            ;   may live inside handlers)
//   jmp   qword ptr [<table> + idx*8]
//
// Both `call`-then-fallthrough and tail-`jmp` variants of the dispatch
// are accepted. The detector is conservative — only emits a match when
// ≥ 8 valid code-pointer handlers are found, so a stray indirect jump
// through some constant table won't false-positive.
struct VmDispatcher {
    // Site coordinates.
    addr_t              function_addr        = 0;   // function whose CFG holds the dispatch
    addr_t              dispatch_addr        = 0;   // VA of the indirect jmp/call
    addr_t              opcode_load_addr     = 0;   // VA of the byte-load that feeds the table

    // Handler table.
    addr_t              table_addr           = 0;
    std::size_t         table_entries        = 0;   // total entries walked before invalid
    std::vector<addr_t> handlers;                   // unique entries from the table

    // Opcode shape.
    Reg                 opcode_index_reg     = Reg::None;   // dst of the byte-load
    u8                  opcode_size_bytes    = 1;           // 1 (movzx byte) or 2 (movzx word)

    // Program counter (bytecode pointer).
    Reg                 pc_register          = Reg::None;
    i32                 pc_disp              = 0;
    // Observed advance to the PC per dispatch (`add pc, N` or `inc pc`
    // between the byte-load and the dispatch). Zero when the increment
    // happens elsewhere (e.g. inside each handler — threaded dispatch).
    i32                 pc_advance           = 0;
    // VA of the bytecode stream when the PC was loaded via a constant
    // `lea pc, [rip+disp]` ahead of the dispatch loop. Zero means the
    // PC came from a function parameter (caller supplies the bytecode)
    // or via a load whose address we don't resolve.
    addr_t              bytecode_addr        = 0;
};

// Scan every defined function in the binary for a dispatch shape. Empty
// for arches the x64 decoder doesn't handle.
[[nodiscard]] std::vector<VmDispatcher>
detect_vm_dispatchers(const Binary& b);

// Phase 1b coarse classification of one VM handler. The body — insns
// from the handler's entry up to its trailing dispatch (threaded) or
// terminator (central) — is walked and tallied across insn families;
// the dominant family wins via the precedence
//   Return > Call > Branch > Store > Load > Arith > Null.
// Phase 1c will refine these to specific opcodes (vm_add, vm_jmp_if_
// zero, vm_call_native, …) once we've grown a per-VM dictionary.
enum class HandlerKind : u8 {
    Unknown,
    Null,        // body has no recognised work — pure passthrough
    Arith,       // add / sub / and / or / xor / shl / shr / mul / etc.
    Load,        // mov / movzx / movsx of (mem → reg)
    Store,       // mov of (reg/imm → mem)
    Branch,      // conditional jump or cmov
    Call,        // direct `call imm` (calls into a native helper)
    Return,      // ret (handler exits the VM run loop)
};

[[nodiscard]] std::string_view handler_kind_name(HandlerKind k) noexcept;

struct HandlerClassification {
    addr_t      entry      = 0;     // handler entry
    addr_t      body_end   = 0;     // first byte past the classified body
    HandlerKind kind       = HandlerKind::Unknown;
    std::size_t insn_count = 0;     // body insns (excludes trailing dispatch)
    // Kind-specific short detail. Populated for Arith / Load / Store /
    // Branch / Call:
    //   Arith  → mnemonic name ("add", "sub", "xor", …)
    //   Load   → memory operand summary ("[rip+0x40]", "[rcx]")
    //   Store  → memory operand summary
    //   Branch → conditional mnemonic ("je", "jne", …)
    //   Call   → target VA when the call is direct, empty otherwise
    // Empty for Return / Null / Unknown.
    std::string summary;
};

// Classify a single handler. When `dispatch_addr` is non-zero, the
// walk stops at that address — used for threaded handlers, where
// the trailing dispatch shape (lea/movzx/inc/jmp) shouldn't be
// counted as part of the body.
[[nodiscard]] HandlerClassification
classify_vm_handler(const Binary& b, addr_t handler_entry,
                    addr_t dispatch_addr = 0);

// One VM, after dispatcher-level results are clustered by handler-
// table address. Multiple dispatchers sharing a table are *the same
// VM*: a tail-dispatch at the end of every handler (threaded VM)
// produces one VmDispatcher per handler, all pointing at the same
// table; clustering exposes that they're the same machine.
//
// `entry_sites` are dispatchers whose function_addr is NOT in
// `handlers` — i.e. the central dispatch loop's outer function(s).
// `threaded_sites` are dispatchers whose function_addr IS in
// `handlers` — the handler itself ends with a fresh opcode-fetch +
// dispatch instead of returning to a central loop.
//
// A pure central VM has 1 entry site and 0 threaded sites; a pure
// threaded VM has 0 entry sites and N threaded sites; mixed VMs
// (some handlers fall through to a central re-dispatch, others
// tail-dispatch directly) have both.
struct VmInstance {
    addr_t              table_addr           = 0;
    std::size_t         table_entries        = 0;
    std::vector<addr_t> handlers;

    // Anatomy taken from the first dispatcher in the cluster — VMs
    // with multiple sites running through different opcode/pc shapes
    // are pathological and don't show up in real binaries.
    Reg                 opcode_index_reg     = Reg::None;
    u8                  opcode_size_bytes    = 1;
    Reg                 pc_register          = Reg::None;
    i32                 pc_disp              = 0;
    i32                 pc_advance           = 0;
    addr_t              bytecode_addr        = 0;

    std::vector<VmDispatcher> entry_sites;
    std::vector<VmDispatcher> threaded_sites;

    // Parallel to `handlers` — per-slot classification. Empty until
    // analyze_vms() (or an explicit classify call) populates it.
    std::vector<HandlerClassification> handler_classes;
};

// Cluster dispatchers by handler-table address and classify each as
// an entry site or a threaded slot. Does NOT classify handler bodies;
// callers wanting that should use `analyze_vms` or call
// `classify_vm_handler` directly.
[[nodiscard]] std::vector<VmInstance>
group_vm_dispatchers(const std::vector<VmDispatcher>& dispatchers);

// Top-level convenience: detect → group → per-handler classify, with
// VmInstance.handler_classes populated.
[[nodiscard]] std::vector<VmInstance> analyze_vms(const Binary& b);

}  // namespace ember
