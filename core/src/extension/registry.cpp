#include <ember/extension/decoder_registry.hpp>
#include <ember/extension/lifter_registry.hpp>
#include <ember/extension/loader_registry.hpp>

#include <algorithm>
#include <unordered_map>
#include <vector>

namespace ember::ext {

namespace {

// Global tables. Hidden inside this TU so no header pulls in <unordered_map>
// transitively. Lookup is rare (once per make_decoder/make_lifter call), so
// the cost of hashing an Arch is irrelevant compared to lifting itself.

std::unordered_map<Arch, DecoderFactory>&
decoder_table() noexcept {
    static std::unordered_map<Arch, DecoderFactory> t;
    return t;
}

std::unordered_map<Arch, LifterFactory>&
lifter_table() noexcept {
    static std::unordered_map<Arch, LifterFactory> t;
    return t;
}

std::vector<LoaderEntry>&
loader_list() noexcept {
    static std::vector<LoaderEntry> v;
    return v;
}

}  // namespace

DecoderFactory
register_decoder(Arch arch, DecoderFactory factory) noexcept {
    auto& t = decoder_table();
    DecoderFactory prev = nullptr;
    if (auto it = t.find(arch); it != t.end()) prev = it->second;
    if (factory) t[arch] = factory;
    else         t.erase(arch);
    return prev;
}

DecoderFactory
get_decoder_factory(Arch arch) noexcept {
    const auto& t = decoder_table();
    auto it = t.find(arch);
    return it == t.end() ? nullptr : it->second;
}

LifterFactory
register_lifter(Arch arch, LifterFactory factory) noexcept {
    auto& t = lifter_table();
    LifterFactory prev = nullptr;
    if (auto it = t.find(arch); it != t.end()) prev = it->second;
    if (factory) t[arch] = factory;
    else         t.erase(arch);
    return prev;
}

LifterFactory
get_lifter_factory(Arch arch) noexcept {
    const auto& t = lifter_table();
    auto it = t.find(arch);
    return it == t.end() ? nullptr : it->second;
}

void
register_loader(LoaderEntry entry) {
    auto& v = loader_list();
    auto it = std::find_if(v.begin(), v.end(),
        [&](const LoaderEntry& e) { return e.name == entry.name; });
    if (it != v.end()) *it = entry;
    else               v.push_back(entry);
}

std::span<const LoaderEntry>
registered_loaders() noexcept {
    return loader_list();
}

}  // namespace ember::ext
