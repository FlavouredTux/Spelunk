#pragma once

#include <map>
#include <string>
#include <vector>

#include <ember/binary/binary.hpp>
#include <ember/common/types.hpp>

namespace ember {

// One entry per recovered Objective-C method: class name, selector, and the
// function-pointer IMP that runtime_msgSend resolves to. Instance methods
// use `-[Class sel]`, class methods use `+[Class sel]`.
struct ObjcMethod {
    std::string cls;           // class or protocol name, e.g. "NSApplication"
    std::string selector;      // raw selector, e.g. "setDelegate:"
    std::string type_encoding; // ObjC type encoding, e.g. "v16@0:8"
    bool        is_class = false;   // true for +class methods
    addr_t      imp = 0;       // IMP for class methods; 0 for protocol signatures
};

// A formal protocol with its required + optional method signatures. Method
// IMPs are always zero here — protocols only carry signatures, not bodies.
struct ObjcProtocol {
    std::string name;                         // e.g. "NSTextInputClient"
    std::vector<std::string> conforms_to;     // parent protocol names
    std::vector<ObjcMethod>  required_instance;
    std::vector<ObjcMethod>  required_class;
    std::vector<ObjcMethod>  optional_instance;
    std::vector<ObjcMethod>  optional_class;
};

// Decode an ObjC type encoding into a C-shaped signature. Input looks like
// "v16@0:8" (void, self:id@0, _cmd:SEL@8) or
// "@32@0:8@16@24" (id, self, _cmd, id, id). Output is the same shape a C
// header declares, with the implicit self/_cmd args hidden:
//   "v16@0:8"                         → "void ()"
//   "@32@0:8@16@24"                   → "id (id, id)"
//   "v40@0:8@\"NSString\"16i32"       → "void (NSString*, int)"
// Returns an empty string on malformed input.
[[nodiscard]] std::string decode_objc_type(std::string_view encoding);

// Structured variant of decode_objc_type: returns the separated
// [return_type, arg0_type, arg1_type, ...] list. self and _cmd are kept
// as the first two args (consumers that want them hidden slice [2..]).
// Empty vector on malformed input.
[[nodiscard]] std::vector<std::string>
decode_objc_type_parts(std::string_view encoding);

// Walks __objc_classlist (+ protocols/categories) and returns every
// method's (class, selector, IMP) triple. Empty on non-Mach-O binaries or
// when the expected __objc_* sections are absent.
[[nodiscard]] std::vector<ObjcMethod> parse_objc_methods(const Binary& b);

// Walks __objc_protolist and returns every declared protocol with its
// required + optional method signatures. Empty when the binary has no
// ObjC protocol metadata.
[[nodiscard]] std::vector<ObjcProtocol> parse_objc_protocols(const Binary& b);

// Walks __objc_selrefs to find selector-reference pointers at specific
// addresses, so the emitter can resolve `mov rsi, [rip + selref_offset]`
// instructions to actual selector names at call sites. Returned map is
// (selref_addr → selector_string).
[[nodiscard]] std::map<addr_t, std::string> parse_objc_selrefs(const Binary& b);

// Walks __objc_classrefs — an array of pointers into __objc_classlist
// entries — so a RIP-relative `mov rdi, [rip + classref]` can render as
// `[ClassName class]` instead of a raw address load. Map is
// (classref_slot_addr → class_name).
[[nodiscard]] std::map<addr_t, std::string> parse_objc_classrefs(const Binary& b);

}  // namespace ember
