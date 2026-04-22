#include <ember/analysis/pe_unwind.hpp>

#include <algorithm>

#include <ember/binary/pe.hpp>
#include <ember/common/bytes.hpp>

namespace ember {

namespace {

constexpr std::size_t kDdException    = 3;
constexpr std::size_t kRuntimeFuncSize = 12;  // x86-64 RUNTIME_FUNCTION

}  // namespace

std::vector<PeUnwindEntry> parse_pe_pdata(const Binary& b) {
    const auto* pe = dynamic_cast<const PeBinary*>(&b);
    if (!pe) return {};
    // ARM64 uses a separate packed format; refuse to interpret x64-shaped
    // entries on other architectures rather than emit bogus function
    // boundaries.
    if (pe->arch() != Arch::X86_64) return {};

    const auto dds = pe->data_directories();
    if (dds.size() <= kDdException) return {};
    const auto& dd = dds[kDdException];
    if (dd.size == 0 || dd.virtual_address == 0) return {};

    const addr_t image_base = pe->image_base();
    std::vector<PeUnwindEntry> out;
    out.reserve(dd.size / kRuntimeFuncSize);

    for (u32 off = 0; off + kRuntimeFuncSize <= dd.size; off += kRuntimeFuncSize) {
        const auto span = b.bytes_at(image_base + dd.virtual_address + off);
        if (span.size() < kRuntimeFuncSize) break;
        const u32 begin_rva  = read_le_at<u32>(span.data() + 0);
        const u32 end_rva    = read_le_at<u32>(span.data() + 4);
        const u32 unwind_rva = read_le_at<u32>(span.data() + 8);
        // Sparse tail entries are all-zero; treat as end-of-array.
        if ((begin_rva | end_rva | unwind_rva) == 0) break;
        // Reject malformed entries where end <= begin rather than
        // silently emitting a zero-size function.
        if (end_rva <= begin_rva) continue;
        if (b.bytes_at(image_base + begin_rva).empty()) continue;
        if (b.bytes_at(image_base + unwind_rva).empty()) continue;

        out.push_back({
            .begin       = image_base + begin_rva,
            .end         = image_base + end_rva,
            .unwind_info = image_base + unwind_rva,
        });
    }

    std::ranges::sort(out, [](const PeUnwindEntry& x, const PeUnwindEntry& y) noexcept {
        return x.begin < y.begin;
    });
    out.erase(std::ranges::unique(out, [](const PeUnwindEntry& x, const PeUnwindEntry& y) noexcept {
        return x.begin == y.begin;
    }).begin(), out.end());
    return out;
}

}  // namespace ember
