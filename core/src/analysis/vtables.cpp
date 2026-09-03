#include <ember/analysis/vtables.hpp>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <span>
#include <utility>
#include <vector>

#include <ember/analysis/discovery.hpp>
#include <ember/binary/arch.hpp>
#include <ember/binary/binary.hpp>
#include <ember/common/types.hpp>

namespace ember {

namespace {

[[nodiscard]] bool read_slot(std::span<const std::byte> data, std::size_t off,
                             std::size_t width, addr_t& out) noexcept {
    if (off + width > data.size()) return false;
    if (width == 8) {
        u64 v = 0;
        std::memcpy(&v, data.data() + off, sizeof(v));
        out = static_cast<addr_t>(v);
        return true;
    }
    if (width == 4) {
        u32 v = 0;
        std::memcpy(&v, data.data() + off, sizeof(v));
        out = static_cast<addr_t>(v);
        return true;
    }
    return false;
}

}  // namespace

std::vector<RuntimeVtable>
discover_runtime_vtables(const Binary& b) {
    const unsigned bits = arch_pointer_bits(b.arch());
    if (bits != 32 && bits != 64) return {};
    const std::size_t width = bits / 8;

    std::vector<RuntimeVtable> out;
    for (const auto& s : b.sections()) {
        if (!s.flags.readable || addr_in_code_section(b, s.vaddr) ||
            s.data.size() < width * 2) {
            continue;
        }
        const std::size_t first_aligned =
            (width - (static_cast<std::size_t>(s.vaddr) % width)) % width;
        std::size_t i = first_aligned;
        while (i + width <= s.data.size()) {
            addr_t target = 0;
            if (!read_slot(s.data, i, width, target) ||
                !addr_in_code_section(b, target)) {
                i += width;
                continue;
            }

            RuntimeVtable vt;
            vt.vaddr = s.vaddr + static_cast<addr_t>(i);
            while (i + width <= s.data.size()) {
                if (!read_slot(s.data, i, width, target) ||
                    !addr_in_code_section(b, target)) {
                    break;
                }
                vt.methods.push_back(target);
                i += width;
            }
            if (vt.methods.size() >= 2) out.push_back(std::move(vt));
        }
    }
    std::ranges::sort(out, [](const RuntimeVtable& lhs, const RuntimeVtable& rhs) {
        return lhs.vaddr < rhs.vaddr;
    });
    return out;
}

}  // namespace ember
