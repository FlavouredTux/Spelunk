#pragma once

// Extension hook for adding binary-format loaders out-of-tree.
//
// Builtin formats (ELF, Mach-O, PE, minidump) are sniffed and dispatched
// directly in load_binary(). Buffers that no builtin recognises are
// offered to each registered extension loader in registration order;
// the first loader whose `sniff` accepts the buffer takes the load.
//
// `sniff` MUST be a cheap magic-byte check (a few bytes at fixed
// offsets) - it runs on every load, including those that ultimately
// land in a builtin loader, so a slow sniff makes every load slow.
// `load` consumes the buffer (by move) and returns a fully-constructed
// Binary instance; the LoadOptions are forwarded so format-specific
// knobs (e.g. a Pro analogue of PE's PDB sidecar discovery) can ride
// on the same surface the builtin loaders use.
//
// Registration is not thread-safe: call from main() before the first
// load_binary() invocation. Registrations last for the process and are
// global.
//
// Raw-region binaries (ember/binary/raw_regions.hpp) deliberately do
// not flow through this registry - they have no magic bytes and are
// only constructed via explicit CLI flags, not auto-detection.

#include <cstddef>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

#include <ember/common/error.hpp>

namespace ember {

class Binary;
struct LoadOptions;

namespace ext {

using LoaderSniff = bool (*)(std::span<const std::byte> buffer) noexcept;
using LoaderLoad  = Result<std::unique_ptr<Binary>> (*)(std::vector<std::byte> buffer,
                                                        const LoadOptions& opts);

struct LoaderEntry {
    // Stable identifier for diagnostics - `ember --list-loaders` etc.
    // Convention: lowercase, no spaces ("nso", "xex2", "wasm").
    std::string_view name;
    LoaderSniff      sniff;
    LoaderLoad       load;
};

// Append `entry` to the extension loader list. Sniffs run in registration
// order; the first match wins. Re-registering a previously-registered
// `name` replaces the old entry (in place - order is preserved).
void register_loader(LoaderEntry entry);

// Snapshot of currently-registered loader entries. Used by load_binary()
// to dispatch and by `ember --list-loaders` to enumerate.
[[nodiscard]] std::span<const LoaderEntry> registered_loaders() noexcept;

}  // namespace ext
}  // namespace ember
