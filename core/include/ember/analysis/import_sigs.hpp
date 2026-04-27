#pragma once

#include <optional>
#include <string_view>
#include <vector>

#include <ember/ir/types.hpp>

namespace ember {

// Known signature for a libc / POSIX / pthread / Win32 import. Used by
// IPA and the emitter's local pass to type call arguments and call
// return values without touching the IR-level lattice (`infer_local_types`
// then propagates the seeded types through the rest of the function).
//
// All TypeRefs index into the arena passed to `lookup_import_sig`. The
// arena is content-interned, so repeated lookups for the same name into
// the same arena are cheap and produce identical TypeRefs.
//
// `variadic` is informational: callers should iterate `params.size()`
// fixed args and rely on the format-string parser (in the emitter) for
// downstream variadic slots.
struct ImportSigSpec {
    TypeRef                ret;
    std::vector<TypeRef>   params;
    bool                   variadic = false;
};

// Look up a known import. `name` is the bare symbol name as returned by
// `clean_import_name` (already stripped of `@GLIBC_*` suffix and
// `__imp_` prefix). Returns nullopt for any unknown name.
[[nodiscard]] std::optional<ImportSigSpec>
lookup_import_sig(std::string_view name, TypeArena& arena);

class Binary;     // <ember/binary/binary.hpp>
struct IrFunction;  // <ember/ir/ir.hpp>

// Pre-seed the function's `value_types` from each Call to a known import:
//
//   - The post-call value of RAX (the next Clobber's dst, after SSA) is
//     refined to the import's return type — `infer_local_types` then
//     propagates that forward through the body. So `void* p = fopen(...)`
//     keeps its `void*` typing through every subsequent fread/fclose.
//
//   - For each call argument that traces back to one of the caller's own
//     int-arg registers (a version-0 read), the corresponding caller-arg
//     slot is refined to the import's expected param type. So a function
//     that ends up calling `fopen(arg0, arg1)` gets `arg0: char*` /
//     `arg1: char*` even without the full IPA pass.
//
// Idempotent (`meet`s into any existing entry), so safe to call more
// than once.
void seed_call_return_types(const Binary& b, IrFunction& fn);

}  // namespace ember
