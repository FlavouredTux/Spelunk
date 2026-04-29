#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace ember {

// Itanium C++ ABI name demangler. Supports the subset of the ABI that
// covers 95%+ of real-world C++ symbols:
//
//   - nested names (N...E)
//   - source-name components (<len><chars>)
//   - ctors/dtors (C1/C2/C3/D0/D1/D2)
//   - common operator names (eq, ne, pl, ls, rs, aS, ix, cl, ...)
//   - builtin types (v, b, c, i, j, l, m, x, y, f, d, ...)
//   - pointer / lvalue ref / rvalue ref / const / volatile / array modifiers
//   - template parameters (T_, T0_, ...) and template argument lists
//   - substitutions (S_, S0_, ...) + St/Sa/Ss/Si/So/Sd pre-defined abbrevs
//   - CV-qualified member function suffixes
//
// Returns the demangled string on success. Unrecognized / unsupported
// constructs make the parser bail out (returns nullopt); callers should
// fall back to the mangled name unchanged.
//
// Intentionally NOT supported: __cxa_demangle-specific extensions, GCC
// vendor extensions (Ua9enable_if..., Dv, etc.), and C++20 constraint
// expressions inside mangled templates. Those land us back in nullopt.
[[nodiscard]] std::optional<std::string>
demangle_itanium(std::string_view mangled);

// Convenience: demangle if the input looks mangled (starts with _Z or __Z),
// otherwise return the input as-is. Useful wherever we display symbol names.
[[nodiscard]] std::string pretty_symbol(std::string_view name);

// Strip the trailing (arg-list) and CV/ref suffix from a demangled name,
// leaving just the qualified identifier. `foo::bar(int) const` → `foo::bar`.
// No-op on anything that doesn't look like a demangled signature.
[[nodiscard]] std::string strip_signature_suffix(std::string_view demangled);

// Convenience: like pretty_symbol but for function-header use — demangles
// and strips the arg list, so the name can go in a declaration where the
// header builder will attach its own argument list.
[[nodiscard]] std::string pretty_symbol_base(std::string_view name);

// Arity inference from a mangled name. Demangles, parses the trailing
// `(args)`, counts comma-separated entries (depth-aware so template-args
// nested inside don't get split), and adds 1 for `this` when the name is
// a non-static member function. Returns nullopt for non-Itanium names,
// for free functions whose decl can't be parsed, or for any signature the
// demangler bailed on. Used to size C++-stdlib calls correctly without
// needing a hand-maintained table for every member function ember sees.
[[nodiscard]] std::optional<unsigned char>
arity_from_mangled(std::string_view mangled);

}  // namespace ember
