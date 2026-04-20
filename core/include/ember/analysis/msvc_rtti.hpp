#pragma once

#include <map>
#include <string>
#include <vector>

#include <ember/binary/binary.hpp>
#include <ember/common/types.hpp>

namespace ember {

// One C++ class recovered from Microsoft Visual C++ RTTI in a PE binary.
// Parallels `RttiClass` for Itanium but carries MSVC-specific pointers:
// `col` is the RTTICompleteObjectLocator VA, `type_descriptor` is the
// MSVC TypeDescriptor. `vtable` is the primary vtable base (the slot
// immediately *after* the COL pointer); `methods` lists per-slot IMPs.
struct MsvcRttiClass {
    std::string          decorated_name;  // e.g. ".?AVMyClass@@"
    std::string          pretty_name;     // e.g. "MyClass"
    addr_t               col             = 0;
    addr_t               type_descriptor = 0;
    addr_t               vtable          = 0;
    std::vector<addr_t>  methods;
};

// Walks PE `.rdata`-like sections looking for vtable + COL pairs. Returns
// empty for non-PE binaries (MSVC RTTI is Windows-only). v1 strips the
// decorated-name prefix/suffix; it does not run a full MSVC demangler, so
// nested / templated names come back partially-cleaned.
[[nodiscard]] std::vector<MsvcRttiClass> parse_msvc_rtti(const Binary& b);

// Convenience: flatten `parse_msvc_rtti` into a (imp_addr → label) map
// for the emitter, matching the signature of `rtti_method_names` so the
// consumer at `emitter.cpp:2669` is format-agnostic.
[[nodiscard]] std::map<addr_t, std::string>
rtti_method_names(const std::vector<MsvcRttiClass>& classes);

}  // namespace ember
