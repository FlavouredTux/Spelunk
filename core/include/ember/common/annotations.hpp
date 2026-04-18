#pragma once

#include <filesystem>
#include <map>
#include <string>
#include <vector>

#include <ember/common/error.hpp>
#include <ember/common/types.hpp>

namespace ember {

struct ParamSig {
    std::string type;
    std::string name;
};

struct FunctionSig {
    std::string           return_type;
    std::vector<ParamSig> params;
};

// On-disk format, one record per line:
//
//   rename <hex-addr> <new-name>
//   sig    <hex-addr> <return-type>|<param-type>|<param-name>|...
//   note   <hex-addr> <text>
//
// Addresses are hex without a 0x prefix. Blank lines and lines starting
// with `#` are ignored. Unknown record kinds are skipped.
struct Annotations {
    std::map<addr_t, std::string>  renames;
    std::map<addr_t, FunctionSig>  signatures;
    std::map<addr_t, std::string>  notes;

    static Result<Annotations>
    load(const std::filesystem::path& path);

    Result<void>
    save(const std::filesystem::path& path) const;

    const std::string* name_for(addr_t a) const noexcept {
        auto it = renames.find(a);
        return it == renames.end() ? nullptr : &it->second;
    }

    const FunctionSig* signature_for(addr_t a) const noexcept {
        auto it = signatures.find(a);
        return it == signatures.end() ? nullptr : &it->second;
    }

    const std::string* note_for(addr_t a) const noexcept {
        auto it = notes.find(a);
        return it == notes.end() ? nullptr : &it->second;
    }
};

}  // namespace ember
