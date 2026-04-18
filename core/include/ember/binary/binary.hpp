#pragma once

#include <cstddef>
#include <filesystem>
#include <memory>
#include <span>

#include <ember/binary/arch.hpp>
#include <ember/binary/format.hpp>
#include <ember/binary/section.hpp>
#include <ember/binary/symbol.hpp>
#include <ember/common/error.hpp>
#include <ember/common/types.hpp>

namespace ember {

class Binary {
public:
    Binary() = default;
    virtual ~Binary() = default;

    Binary(const Binary&)            = delete;
    Binary& operator=(const Binary&) = delete;
    Binary(Binary&&)                 = delete;
    Binary& operator=(Binary&&)      = delete;

    [[nodiscard]] virtual Format format() const noexcept      = 0;
    [[nodiscard]] virtual Arch   arch() const noexcept        = 0;
    [[nodiscard]] virtual addr_t entry_point() const noexcept = 0;

    [[nodiscard]] virtual std::span<const Section> sections() const noexcept = 0;
    [[nodiscard]] virtual std::span<const Symbol>  symbols() const noexcept  = 0;

    [[nodiscard]] virtual std::span<const std::byte> image() const noexcept = 0;

    // Default: walk `sections()` to resolve a virtual address to file bytes.
    // Format-specific loaders (e.g. ElfBinary with PT_LOAD) should override
    // this to use their authoritative mapping table; for binaries that
    // carry only section headers (relocatable .o files) the default is
    // still correct.
    [[nodiscard]] virtual std::span<const std::byte>
    bytes_at(addr_t vaddr) const noexcept {
        for (const auto& s : sections()) {
            if (s.data.empty()) continue;
            if (vaddr < s.vaddr) continue;
            const auto offset = vaddr - s.vaddr;
            if (offset >= s.data.size()) continue;
            return s.data.subspan(static_cast<std::size_t>(offset));
        }
        return {};
    }

    // Look up the import whose PLT stub covers `plt_addr`. Accepts any
    // address within the stub's slot — typically 16 bytes on x86-64 — so
    // that callers targeting the middle of a slot (e.g. skipping a leading
    // endbr64 prefix) still resolve to the right import.
    [[nodiscard]] const Symbol*
    import_at_plt(addr_t plt_addr, unsigned slot_size = 16) const noexcept {
        if (plt_addr == 0) return nullptr;
        for (const auto& s : symbols()) {
            if (!s.is_import) continue;
            if (s.addr == 0) continue;
            if (plt_addr >= s.addr && plt_addr < s.addr + slot_size) return &s;
        }
        return nullptr;
    }

    // Look up the import whose GOT slot is at `got_addr` (the address the
    // dynamic linker fills with the resolved function pointer).
    [[nodiscard]] const Symbol* import_at_got(addr_t got_addr) const noexcept {
        if (got_addr == 0) return nullptr;
        for (const auto& s : symbols()) {
            if (!s.is_import) continue;
            if (s.got_addr == got_addr) return &s;
        }
        return nullptr;
    }

    // Find a named defined symbol (Object or Function) that contains the
    // given virtual address. Used by the emitter to render `*(u64*)(0x404020)`
    // as `g_name` where a matching global exists.
    [[nodiscard]] const Symbol* defined_object_at(addr_t vaddr) const noexcept {
        for (const auto& s : symbols()) {
            if (s.is_import) continue;
            if (s.kind != SymbolKind::Object && s.kind != SymbolKind::Function) continue;
            if (s.addr == 0 || s.size == 0) continue;
            if (vaddr >= s.addr && vaddr < s.addr + s.size) return &s;
        }
        return nullptr;
    }
};

[[nodiscard]] Result<std::unique_ptr<Binary>>
load_binary(const std::filesystem::path& path);

}  // namespace ember
