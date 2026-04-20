#pragma once

#include <map>
#include <string>
#include <vector>

#include <ember/binary/binary.hpp>
#include <ember/common/types.hpp>

namespace ember {

// One C++ class recovered from Itanium-ABI RTTI in the binary's data
// sections. Typeinfo address points at the `__class_type_info` (or
// `__si_class_type_info` / `__vmi_class_type_info`) struct; `vtable_addr`
// is the class's primary vtable base (where `offset_to_top = 0` and the
// following u64 is the typeinfo pointer). `methods` lists the vtable's
// per-slot IMPs in order; entries outside `__TEXT` become zero (for pure
// virtual / deleted slots).
struct RttiClass {
    std::string          mangled_name;   // e.g. "N3RBX6LoggerE"
    std::string          demangled_name; // e.g. "RBX::Logger"
    addr_t               typeinfo = 0;
    addr_t               vtable   = 0;   // 0 when we only found the typeinfo
    std::vector<addr_t>  methods;        // vtable slots pointing into __TEXT
};

// Walks `__DATA_CONST,__const` and `__DATA,__const` for typeinfo structs
// (two-pointer records where the second pointer's target demangles as an
// Itanium mangled name) and their associated vtables (16-byte records
// starting with `offset_to_top=0` + a known typeinfo pointer).
[[nodiscard]] std::vector<RttiClass> parse_itanium_rtti(const Binary& b);

// Convenience: flatten `parse_itanium_rtti` into a (imp_addr → label) map
// for the emitter. Each virtual-method IMP is tagged `<Class>::vfn_<N>`.
[[nodiscard]] std::map<addr_t, std::string>
rtti_method_names(const std::vector<RttiClass>& classes);

}  // namespace ember
