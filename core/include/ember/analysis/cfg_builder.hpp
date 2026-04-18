#pragma once

#include <string>

#include <ember/analysis/function.hpp>
#include <ember/binary/binary.hpp>
#include <ember/common/error.hpp>
#include <ember/common/types.hpp>
#include <ember/disasm/x64_decoder.hpp>

namespace ember {

class CfgBuilder {
public:
    CfgBuilder(const Binary& binary, const X64Decoder& decoder) noexcept
        : binary_(binary), decoder_(decoder) {}

    [[nodiscard]] Result<Function>
    build(addr_t entry, std::string name = {}) const;

private:
    const Binary&      binary_;
    const X64Decoder&  decoder_;
};

}  // namespace ember
