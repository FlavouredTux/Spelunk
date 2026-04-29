#pragma once

#include <optional>

#include <ember/binary/binary.hpp>
#include <ember/common/types.hpp>

namespace ember::cfi {

// How a register's value is recovered from the parent frame.
enum class RuleKind : u8 {
    Undefined,    // no recoverable value (caller's value is gone)
    SameValue,    // register holds its caller's value (callee-saved untouched)
    Offset,       // [CFA + offset]
    ValOffset,    // CFA + offset (the value, not stored at that addr)
    Register,     // value of another DWARF register
    // DWARF expressions (DW_CFA_expression / val_expression) are
    // intentionally absent — recover() returns nullopt when it
    // encounters them, and the caller falls back to RBP-walk.
};

struct Rule {
    RuleKind kind   = RuleKind::SameValue;
    i64      offset = 0;   // for Offset / ValOffset
    u32      reg    = 0;   // for Register
};

// Where the CFA itself lives at a given PC.
struct CfaDef {
    enum class Kind : u8 { Register, Unknown };
    Kind kind   = Kind::Unknown;
    u32  reg    = 0;
    i64  offset = 0;
};

struct State {
    // 0..16 covers x86-64 GPRs (rax..r15) + RIP per System V's DWARF
    // mapping. Higher-numbered DWARF regs (XMM, FP) aren't used by
    // the unwinder so we don't allocate slots for them.
    static constexpr unsigned kNumRegs = 17;
    CfaDef cfa;
    Rule   regs[kNumRegs];
    u32    return_address_register = 16;  // RIP for x86-64
};

// Walk the binary's .eh_frame, find the FDE covering `target_pc`,
// run CIE initial-instructions + FDE instructions up to (but not
// including) `target_pc`, and return the resulting State.
//
// nullopt is returned when:
//   - no .eh_frame section is present
//   - no FDE covers target_pc
//   - a DW_CFA_*expression opcode is encountered (caller falls back)
//   - the CFI stream is malformed
[[nodiscard]] std::optional<State>
recover(const Binary& b, addr_t target_pc);

}  // namespace ember::cfi
