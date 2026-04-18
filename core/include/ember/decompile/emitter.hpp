#pragma once

#include <string>

#include <ember/binary/binary.hpp>
#include <ember/common/annotations.hpp>
#include <ember/common/error.hpp>
#include <ember/structure/region.hpp>

namespace ember {

class PseudoCEmitter {
public:
    PseudoCEmitter() = default;

    // `binary`      — used for string/import/global resolution (optional).
    // `annotations` — per-binary user edits (renames, declared signatures).
    //                 When set, function headers and callsites use the user's
    //                 name + typed params in place of the fallback `sub_XXXX`.
    [[nodiscard]] Result<std::string>
    emit(const StructuredFunction& sf,
         const Binary* binary = nullptr,
         const Annotations* annotations = nullptr) const;
};

}  // namespace ember
