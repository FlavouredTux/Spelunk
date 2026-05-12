#pragma once

// Extension hook for adding IR lifters out-of-tree. Mirror of
// decoder_registry - see that header for the contract. Builtins win;
// the registry only fires for arches core has no lifter for.
//
// The factory receives the resolved ABI (`abi_for(format, arch, endian)`)
// alongside the Binary so out-of-tree lifters don't have to redo the
// format/arch/endian → ABI mapping themselves.

#include <memory>

#include <ember/binary/arch.hpp>
#include <ember/ir/abi.hpp>

namespace ember {

class Binary;
class Lifter;

namespace ext {

using LifterFactory = std::unique_ptr<Lifter>(*)(const Binary& b, Abi abi);

LifterFactory register_lifter(Arch arch, LifterFactory factory) noexcept;

[[nodiscard]] LifterFactory get_lifter_factory(Arch arch) noexcept;

}  // namespace ext
}  // namespace ember
