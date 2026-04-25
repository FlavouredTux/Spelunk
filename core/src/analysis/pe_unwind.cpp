#include <ember/analysis/pe_unwind.hpp>

#include <algorithm>

#include <ember/binary/pe.hpp>
#include <ember/common/bytes.hpp>

namespace ember {

namespace {

constexpr std::size_t kDdException     = 3;
constexpr std::size_t kRuntimeFuncSize = 12;  // x86-64 RUNTIME_FUNCTION

// UWOP_* opcodes — see Microsoft's "x64 exception handling".
constexpr u8 UWOP_PUSH_NONVOL     = 0;
constexpr u8 UWOP_ALLOC_LARGE     = 1;
constexpr u8 UWOP_ALLOC_SMALL     = 2;
constexpr u8 UWOP_SET_FPREG       = 3;
constexpr u8 UWOP_SAVE_NONVOL     = 4;
constexpr u8 UWOP_SAVE_NONVOL_FAR = 5;
constexpr u8 UWOP_SAVE_XMM128     = 8;
constexpr u8 UWOP_SAVE_XMM128_FAR = 9;
constexpr u8 UWOP_PUSH_MACHFRAME  = 10;

constexpr u8 UNW_FLAG_EHANDLER  = 0x1;
constexpr u8 UNW_FLAG_UHANDLER  = 0x2;
constexpr u8 UNW_FLAG_CHAININFO = 0x4;

}  // namespace

std::vector<PeUnwindEntry> parse_pe_pdata(const Binary& b) {
    const auto* pe = dynamic_cast<const PeBinary*>(&b);
    if (!pe) return {};
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
        if ((begin_rva | end_rva | unwind_rva) == 0) break;
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

std::optional<ParsedUnwindInfo>
parse_unwind_info(const Binary& b, addr_t unwind_info_va) {
    if (unwind_info_va == 0) return std::nullopt;
    auto span = b.bytes_at(unwind_info_va);
    if (span.size() < 4) return std::nullopt;

    ParsedUnwindInfo info{};
    const u8 ver_flags = read_le_at<u8>(span.data() + 0);
    info.version       = static_cast<u8>(ver_flags & 0x07);
    info.flags         = static_cast<u8>((ver_flags >> 3) & 0x1F);
    // MS only ever defined versions 1 and 2 for UNWIND_INFO. Anything
    // else means the entry's UnwindInfo RVA is bogus (stub fixtures,
    // packed images, garbage) — refusing to parse here keeps a wild
    // size_of_prolog from accidentally hiding the entire function body.
    if (info.version != 1 && info.version != 2) return std::nullopt;
    info.size_of_prolog = read_le_at<u8>(span.data() + 1);
    const u8 count_of_codes = read_le_at<u8>(span.data() + 2);
    const u8 frame_byte = read_le_at<u8>(span.data() + 3);
    info.frame_register        = static_cast<u8>(frame_byte & 0x0F);
    info.frame_register_offset = static_cast<u8>((frame_byte >> 4) & 0x0F);

    // Bounds-check the code array. Each code is 2 bytes; following the array
    // are optional alignment padding + handler/chained data.
    const std::size_t codes_bytes = static_cast<std::size_t>(count_of_codes) * 2u;
    if (span.size() < 4u + codes_bytes) return std::nullopt;

    info.codes.reserve(count_of_codes);
    std::size_t i = 0;
    while (i < count_of_codes) {
        const std::byte* p = span.data() + 4u + (i * 2u);
        const u8 code_offset = read_le_at<u8>(p + 0);
        const u8 op_byte     = read_le_at<u8>(p + 1);
        const u8 op          = static_cast<u8>(op_byte & 0x0F);
        const u8 op_info     = static_cast<u8>((op_byte >> 4) & 0x0F);

        UnwindCode code{code_offset, op, op_info, 0u};
        std::size_t slots = 1;

        switch (op) {
            case UWOP_PUSH_NONVOL:
                slots = 1;
                break;
            case UWOP_ALLOC_LARGE:
                if (op_info == 0) {
                    slots = 2;
                    if (i + 1 >= count_of_codes) return std::nullopt;
                    code.operand = static_cast<u32>(read_le_at<u16>(p + 2)) * 8u;
                } else if (op_info == 1) {
                    slots = 3;
                    if (i + 2 >= count_of_codes) return std::nullopt;
                    code.operand = read_le_at<u32>(p + 2);
                } else {
                    return std::nullopt;
                }
                break;
            case UWOP_ALLOC_SMALL:
                slots = 1;
                code.operand = static_cast<u32>(op_info) * 8u + 8u;
                break;
            case UWOP_SET_FPREG:
                slots = 1;
                break;
            case UWOP_SAVE_NONVOL:
                slots = 2;
                if (i + 1 >= count_of_codes) return std::nullopt;
                code.operand = static_cast<u32>(read_le_at<u16>(p + 2)) * 8u;
                break;
            case UWOP_SAVE_NONVOL_FAR:
                slots = 3;
                if (i + 2 >= count_of_codes) return std::nullopt;
                code.operand = read_le_at<u32>(p + 2);
                break;
            case UWOP_SAVE_XMM128:
                slots = 2;
                if (i + 1 >= count_of_codes) return std::nullopt;
                code.operand = static_cast<u32>(read_le_at<u16>(p + 2)) * 16u;
                break;
            case UWOP_SAVE_XMM128_FAR:
                slots = 3;
                if (i + 2 >= count_of_codes) return std::nullopt;
                code.operand = read_le_at<u32>(p + 2);
                break;
            case UWOP_PUSH_MACHFRAME:
                slots = 1;
                break;
            default:
                return std::nullopt;
        }

        info.codes.push_back(code);
        i += slots;
    }

    // Past the codes (with 1 padding slot when count is odd) sits either a
    // chained RUNTIME_FUNCTION or an exception-handler RVA. Ignore handler
    // payload bytes — only the RVA itself is captured here.
    const std::size_t aligned_codes_bytes = (codes_bytes + 3u) & ~std::size_t{3u};
    const std::size_t tail = 4u + aligned_codes_bytes;

    if (info.flags & UNW_FLAG_CHAININFO) {
        if (span.size() < tail + kRuntimeFuncSize) return info;  // truncated chain; keep header
        const std::byte* p = span.data() + tail;
        const u32 begin_rva = read_le_at<u32>(p + 0);
        // Chained RUNTIME_FUNCTION's begin_rva pointer to the parent's
        // RUNTIME_FUNCTION; we expose it as the absolute VA of the parent's
        // function start so callers can navigate.
        const auto* pe = dynamic_cast<const PeBinary*>(&b);
        if (pe) info.chained_va = pe->image_base() + begin_rva;
    } else if (info.flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) {
        if (span.size() < tail + 4u) return info;
        const std::byte* p = span.data() + tail;
        const u32 handler_rva = read_le_at<u32>(p);
        const auto* pe = dynamic_cast<const PeBinary*>(&b);
        if (pe) info.handler_rva = pe->image_base() + handler_rva;
    }

    return info;
}

std::map<addr_t, addr_t> build_prologue_ranges(const Binary& b) {
    std::map<addr_t, addr_t> out;
    const auto entries = parse_pe_pdata(b);
    for (const auto& e : entries) {
        auto info = parse_unwind_info(b, e.unwind_info);
        if (!info) continue;
        // Chained entries describe a continuation of the parent function;
        // the prologue belongs to the parent, not here.
        if (info->flags & UNW_FLAG_CHAININFO) continue;
        if (info->size_of_prolog == 0) continue;
        const addr_t prologue_end = e.begin + info->size_of_prolog;
        // Defensive: don't run the prologue past the function end.
        out[e.begin] = std::min(prologue_end, e.end);
    }
    return out;
}

}  // namespace ember
