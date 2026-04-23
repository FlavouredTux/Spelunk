#pragma once

#include <map>
#include <string_view>
#include <vector>

#include <ember/binary/binary.hpp>
#include <ember/common/types.hpp>

namespace ember {

// How the referencing instruction interacts with the target address.
//   Read  — the memory operand is a source (e.g. `mov reg, [rip+disp]`,
//           `call qword [rip+imp_slot]`, `cmp [rip+flag], 0`).
//   Write — the memory operand is a destination on a writing mnemonic
//           (e.g. `mov [rip+disp], reg`, `add [rip+ctr], 1`).
//   Lea   — `lea reg, [rip+disp]`. Address-taken; the bytes at the
//           target are not accessed by this instruction.
enum class DataXrefKind : u8 { Read, Write, Lea };

[[nodiscard]] constexpr std::string_view
data_xref_kind_name(DataXrefKind k) noexcept {
    switch (k) {
        case DataXrefKind::Read:  return "read";
        case DataXrefKind::Write: return "write";
        case DataXrefKind::Lea:   return "lea";
    }
    return "?";
}

struct DataXref {
    addr_t        from_pc = 0;  // VA of the referencing instruction
    addr_t        to_addr = 0;  // VA the operand resolves to
    DataXrefKind  kind    = DataXrefKind::Read;
};

// Scan every defined function for memory operands that resolve to a
// non-executable loaded section and emit one DataXref per such operand.
// Handles rip-relative (`[rip+disp]`), absolute (`[disp]`), and scalar
// immediate operands (for architectures where address-size immediates
// are common). Excludes targets in executable sections — those are
// call/jmp edges and live on the call graph, not the data xref map.
//
// Results are grouped by target VA (map key) and each bucket is sorted
// by `from_pc` with duplicates collapsed when the same instruction
// references the target through multiple operand slots.
[[nodiscard]] std::map<addr_t, std::vector<DataXref>>
compute_data_xrefs(const Binary& b);

}  // namespace ember
