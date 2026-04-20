#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace ember {

// MSVC C++ name demangler. Covers the subset of the spec that produces
// readable names on real-world Windows binaries:
//
//   - qualified names (`?name@scope1@scope2@@...`)
//   - constructors / destructors (`??0`, `??1`)
//   - common operator names (`??2` new, `??3` delete, `??4` =, `??_G` /
//     `??_E` deleting destructors, `??_7` vftable, `??_8` vbtable)
//   - templates (`?$name@<args>@@`) with recursive type rendering
//   - name backreferences (digits 0-9 within a qualified name)
//   - type backreferences (digits 0-9 inside a template arg list)
//   - builtin types (H, D, M, N, X, _N, _J, _K, _W, ...)
//   - pointer / reference / const / volatile decorations
//   - RTTI type descriptors (`.?AV...@@`, `.?AU...@@`)
//
// The output is *names only* — function signatures (parameter types,
// calling conventions, CV qualifiers, return type) are not rendered. The
// emitter wants pretty class names for vtable labelling; full sig
// rendering belongs in a heavier downstream layer.
//
// Returns nullopt when the parser hits an unsupported construct or the
// input doesn't look mangled. Callers should treat that as "use the raw
// name unchanged" rather than as an error.
[[nodiscard]] std::optional<std::string>
demangle_msvc(std::string_view mangled);

}  // namespace ember
