#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

#include <ember/analysis/symtable.hpp>
#include <ember/binary/binary.hpp>
#include <ember/common/error.hpp>
#include <ember/common/types.hpp>

namespace ember::analysis {

// One detected resolver: a function whose body writes to a stride-8
// run of slots in a writable section. Multiple resolvers may
// independently populate disjoint runs of the same fnptr table; the
// detector iterates, claiming each longest unclaimed run until
// nothing remains above the noise floor.
struct ResolverCandidate {
    addr_t       fn_addr    = 0;
    std::string  fn_name;
    addr_t       base_va    = 0;   // VA of the first slot this resolver wrote
    std::size_t  slots      = 0;   // consecutive stride-8 slots covered
};

// One row of the unified mapping. `fnptr_va` is unset when the slot
// for this string's index falls outside any detected resolver's
// claimed range. `resolver_fn` names the resolver that claimed the
// slot (when one did).
struct ResolvedSymbol {
    std::size_t            index      = 0;
    addr_t                 string_va  = 0;
    std::string            name;
    std::optional<addr_t>  fnptr_va;
    std::optional<addr_t>  resolver_fn;
    std::vector<addr_t>    callsites;
};

struct SymResolution {
    SymtableWalk                    walk;
    std::vector<ResolvedSymbol>     rows;
    // Resolvers sorted by ascending base_va so resolvers[0].base_va
    // is the merged "table base" against which row indices map back
    // to slot VAs.
    std::vector<ResolverCandidate>  resolvers;
    std::size_t                     non_empty_count   = 0;
    std::size_t                     resolved_count    = 0;   // strings with a fnptr_va
};

// Walk the string table at `table_va`, locate every resolver function
// that writes to a stride-8 run in a writable section, and pair every
// non-empty string with whichever resolver claimed its slot. Errors
// only on an unmapped `table_va` - a missing resolver is reported via
// an empty `resolvers` vector and zero `resolved_count`.
[[nodiscard]] Result<SymResolution>
resolve_symtable(const Binary& b, addr_t table_va);

}  // namespace ember::analysis
