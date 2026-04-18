#include <ember/disasm/register.hpp>

#include <array>
#include <cstddef>

namespace ember {

namespace {

constexpr std::array<std::string_view, 92> kRegNames = {
    "",
    "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh",
    "spl", "bpl", "sil", "dil",
    "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
    "ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
    "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
    "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
    "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "es", "cs", "ss", "ds", "fs", "gs",
    "rip",
    "xmm0",  "xmm1",  "xmm2",  "xmm3",  "xmm4",  "xmm5",  "xmm6",  "xmm7",
    "xmm8",  "xmm9",  "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
};

}  // namespace

std::string_view reg_name(Reg r) noexcept {
    const auto idx = static_cast<std::size_t>(r);
    if (idx >= kRegNames.size()) return "?";
    return kRegNames[idx];
}

}  // namespace ember
