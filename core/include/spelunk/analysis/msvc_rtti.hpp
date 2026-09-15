#pragma once

#include <map>
#include <span>
#include <string>
#include <vector>

#include <spelunk/binary/binary.hpp>
#include <spelunk/common/types.hpp>

namespace spelunk {

struct MsvcRttiBaseClass {
    std::string decorated_name;
    std::string pretty_name;
    addr_t      descriptor      = 0;
    addr_t      type_descriptor = 0;
    i32         mdisp           = 0;
    i32         pdisp           = 0;
    i32         vdisp           = 0;
    u32         attributes      = 0;
};

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
    addr_t               class_hierarchy = 0;
    addr_t               vtable          = 0;
    std::vector<addr_t>  methods;
    std::vector<MsvcRttiBaseClass> bases;
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
rtti_method_names(std::span<const MsvcRttiClass> classes);

}  // namespace spelunk
