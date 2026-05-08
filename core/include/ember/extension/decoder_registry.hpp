#pragma once

// Extension hook for adding architecture decoders out-of-tree.
//
// Builtin arches (x86_64, ARM64, PPC32/64) are dispatched directly in
// make_decoder() — registering a factory for one of those arches has no
// effect; the builtin path always wins. Arches that core doesn't ship a
// decoder for fall through to this registry, so an out-of-tree extension
// (ember-pro, a research fork) can plug in RISC-V / MIPS / etc. without
// editing core's switch statement.
//
// Registration is not thread-safe: call from main() before any decoder
// is requested. Registrations are global and last for the process.

#include <memory>

#include <ember/binary/arch.hpp>

namespace ember {

class Binary;
class Decoder;

namespace ext {

using DecoderFactory = std::unique_ptr<Decoder>(*)(const Binary& b);

// Register a factory for `arch`. Replaces any prior registration for the
// same arch. Returns the previously-registered factory (or nullptr).
DecoderFactory register_decoder(Arch arch, DecoderFactory factory) noexcept;

// Look up the factory registered for `arch`. Returns nullptr when no
// extension factory is registered.
[[nodiscard]] DecoderFactory get_decoder_factory(Arch arch) noexcept;

}  // namespace ext
}  // namespace ember
