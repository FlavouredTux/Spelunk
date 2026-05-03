#pragma once

#include <optional>
#include <string>
#include <vector>

#include <ember/common/types.hpp>
#include <ember/disasm/instruction.hpp>

namespace ember {

class Binary;

// Classification of an int3 (0xCC) found inside a known function's
// decoded instruction stream. The resolver does NOT blindly scan
// executable sections — it walks the disassembled instruction stream
// so encrypted/packed sections are never touched. Each int3 is
// classified by its structural role in the surrounding code.
enum class Int3Kind : u8 {
    // Inter-function padding / alignment filler. MSVC linkers fill
    // padding between functions with 0xCC ("int3 hot-patch bytes").
    // Identified by: the byte lies outside any known function's
    // decoded instruction stream, or sits in a run of consecutive
    // 0xCC bytes between function boundaries.
    Padding,

    // A conditional branch (Jcc) that was stubbed out — replaced
    // with int3 by an obfuscator or optimizer. The `predicate`
    // field records the flag condition the original branch would
    // have tested. This is the most valuable classification: it
    // lets the decompiler recover the branch semantics even when
    // the original instruction bytes are gone.
    StubbedBranch,

    // Deliberate anti-debug trap. The program placed int3 to detect
    // whether a debugger is present. Heuristic: the containing
    // function imports IsDebuggerPresent, NtQueryInformationProcess,
    // or CheckRemoteDebuggerPresent.
    AntiDebug,

    // Programmatic breakpoint — __debugbreak() (MSVC) or
    // DebugBreak() (Win32). Identified by: the containing function's
    // symbol name matches known debug-break wrappers.
    DebugBreak,

    // The target program placed its own software breakpoint at
    // runtime (e.g. a JIT or instrumentation layer). Cannot be
    // detected from static analysis alone — requires comparing live
    // memory against the on-disk image. Always classified as Unknown
    // by the static pass.
    RuntimeBp,

    // Cannot classify with available information.
    Unknown,
};

[[nodiscard]] constexpr std::string_view int3_kind_name(Int3Kind k) noexcept {
    switch (k) {
        case Int3Kind::StubbedBranch: return "stubbed-branch";
        case Int3Kind::Padding:       return "padding";
        case Int3Kind::AntiDebug:     return "anti-debug";
        case Int3Kind::DebugBreak:    return "debugbreak";
        case Int3Kind::RuntimeBp:     return "runtime-bp";
        case Int3Kind::Unknown:       return "unknown";
    }
    return "?";
}

// The flag predicate that a stubbed conditional branch would have
// tested. Maps 1:1 to the Jcc family — each entry names the
// condition and the flags it depends on.
enum class BranchPredicate : u8 {
    Overflow,      // JO   — OF==1
    NotOverflow,   // JNO  — OF==0
    Below,         // JB   — CF==1          (unsigned <)
    AboveEq,       // JAE  — CF==0          (unsigned >=)
    Equal,         // JE   — ZF==1
    NotEqual,      // JNE  — ZF==0
    BelowEq,       // JBE  — CF==1 || ZF==1  (unsigned <=)
    Above,         // JA   — CF==0 && ZF==0  (unsigned >)
    Sign,          // JS   — SF==1
    NotSign,       // JNS  — SF==0
    Parity,        // JP   — PF==1
    NotParity,     // JNP  — PF==0
    Less,          // JL   — SF!=OF          (signed <)
    GreaterEq,     // JGE  — SF==OF          (signed >=)
    LessEq,        // JLE  — ZF==1 || SF!=OF (signed <=)
    Greater,       // JG   — ZF==0 && SF==OF (signed >)
};

[[nodiscard]] constexpr std::string_view branch_predicate_name(BranchPredicate p) noexcept {
    switch (p) {
        case BranchPredicate::Overflow:    return "overflow";
        case BranchPredicate::NotOverflow: return "!overflow";
        case BranchPredicate::Below:       return "below";
        case BranchPredicate::AboveEq:     return "above_eq";
        case BranchPredicate::Equal:        return "equal";
        case BranchPredicate::NotEqual:     return "not_equal";
        case BranchPredicate::BelowEq:      return "below_eq";
        case BranchPredicate::Above:        return "above";
        case BranchPredicate::Sign:         return "sign";
        case BranchPredicate::NotSign:      return "!sign";
        case BranchPredicate::Parity:       return "parity";
        case BranchPredicate::NotParity:    return "!parity";
        case BranchPredicate::Less:         return "less";
        case BranchPredicate::GreaterEq:    return "greater_eq";
        case BranchPredicate::LessEq:       return "less_eq";
        case BranchPredicate::Greater:      return "greater";
    }
    return "?";
}

// Map a Jcc mnemonic to its BranchPredicate. Returns nullopt for
// non-conditional-branch mnemonics.
[[nodiscard]] constexpr std::optional<BranchPredicate>
mnemonic_to_predicate(Mnemonic mn) noexcept {
    switch (mn) {
        case Mnemonic::Jo:  return BranchPredicate::Overflow;
        case Mnemonic::Jno: return BranchPredicate::NotOverflow;
        case Mnemonic::Jb:  return BranchPredicate::Below;
        case Mnemonic::Jae: return BranchPredicate::AboveEq;
        case Mnemonic::Je:  return BranchPredicate::Equal;
        case Mnemonic::Jne: return BranchPredicate::NotEqual;
        case Mnemonic::Jbe: return BranchPredicate::BelowEq;
        case Mnemonic::Ja:  return BranchPredicate::Above;
        case Mnemonic::Js:  return BranchPredicate::Sign;
        case Mnemonic::Jns: return BranchPredicate::NotSign;
        case Mnemonic::Jp:  return BranchPredicate::Parity;
        case Mnemonic::Jnp: return BranchPredicate::NotParity;
        case Mnemonic::Jl:  return BranchPredicate::Less;
        case Mnemonic::Jge: return BranchPredicate::GreaterEq;
        case Mnemonic::Jle: return BranchPredicate::LessEq;
        case Mnemonic::Jg:  return BranchPredicate::Greater;
        default: return std::nullopt;
    }
}

struct Int3Resolution {
    Int3Kind kind       = Int3Kind::Unknown;
    addr_t   addr       = 0;              // VA of the 0xCC byte
    addr_t   containing_fn = 0;           // entry VA of the enclosing function, 0 if none
    u64      fn_offset  = 0;              // offset within that function

    // ---- StubbedBranch fields -------------------------------------------
    // When kind == StubbedBranch, these fields describe the branch
    // that was replaced. `predicate` is the flag condition the
    // original Jcc would have tested. `original_mnemonic` is the
    // Jcc mnemonic that was stubbed. `branch_target` is the
    // fall-through or taken target, when recoverable from the
    // surrounding instruction stream.
    std::optional<BranchPredicate> predicate;
    Mnemonic original_mnemonic = Mnemonic::Invalid;
    std::optional<addr_t> branch_target;

    // Brief human-readable note explaining the classification.
    std::string note;
};

// Walk the decoded instruction stream of every discovered function,
// find int3 instructions, and classify each one. Analyzes ALL
// executable sections unconditionally — no opt-out. Returns results
// sorted by address. Only fires on X86_64/X86 binaries.
[[nodiscard]] std::vector<Int3Resolution>
resolve_embedded_int3s(const Binary& b);

// Classify a single int3 at a known address. Used at runtime when
// the debug event loop encounters an unexpected SIGTRAP that doesn't
// match a debugger-placed breakpoint. Returns Unknown when the
// address has no classification.
[[nodiscard]] Int3Resolution
resolve_int3_at(const Binary& b, addr_t va);

}  // namespace ember
