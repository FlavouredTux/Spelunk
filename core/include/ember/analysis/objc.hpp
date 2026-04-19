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
    std::string cls;         // class name, e.g. "NSApplication"
    std::string selector;    // raw selector, e.g. "setDelegate:"
    bool        is_class = false;  // true for +class methods
    addr_t      imp = 0;     // function address this selector maps to
};

// Walks __objc_classlist (+ protocols/categories) and returns every
// method's (class, selector, IMP) triple. Empty on non-Mach-O binaries or
// when the expected __objc_* sections are absent.
[[nodiscard]] std::vector<ObjcMethod> parse_objc_methods(const Binary& b);

// Walks __objc_selrefs to find selector-reference pointers at specific
// addresses, so the emitter can resolve `mov rsi, [rip + selref_offset]`
// instructions to actual selector names at call sites. Returned map is
// (selref_addr → selector_string).
[[nodiscard]] std::map<addr_t, std::string> parse_objc_selrefs(const Binary& b);

}  // namespace ember
