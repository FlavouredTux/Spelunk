#include "eh_frame_internal.hpp"

#include <spelunk/binary/binary.hpp>

#include <cstddef>
#include <cstdio>
#include <limits>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace {

using spelunk::u8;
using spelunk::u32;
using spelunk::u64;

int failures = 0;

void check(bool condition, const char* context) {
    if (condition) return;
    std::fprintf(stderr, "FAIL: %s\n", context);
    ++failures;
}

void append_u8(std::vector<std::byte>& out, u8 value) {
    out.push_back(static_cast<std::byte>(value));
}

void append_u32(std::vector<std::byte>& out, u32 value) {
    for (unsigned shift = 0; shift < 32; shift += 8) {
        append_u8(out, static_cast<u8>(value >> shift));
    }
}

void append_u64(std::vector<std::byte>& out, u64 value) {
    for (unsigned shift = 0; shift < 64; shift += 8) {
        append_u8(out, static_cast<u8>(value >> shift));
    }
}

void append_record(std::vector<std::byte>& section,
                   const std::vector<std::byte>& payload) {
    append_u32(section, static_cast<u32>(payload.size()));
    section.insert(section.end(), payload.begin(), payload.end());
}

std::size_t append_plain_cie(std::vector<std::byte>& section) {
    const std::size_t offset = section.size();
    std::vector<std::byte> payload;
    append_u32(payload, 0);  // CIE id
    append_u8(payload, 1);   // version
    append_u8(payload, 0);   // empty augmentation string
    append_u8(payload, 1);   // code alignment
    append_u8(payload, 0x78);  // data alignment: -8 (SLEB128)
    append_u8(payload, 16);  // return-address register
    append_record(section, payload);
    return offset;
}

std::size_t append_lsda_cie(std::vector<std::byte>& section) {
    const std::size_t offset = section.size();
    std::vector<std::byte> payload;
    append_u32(payload, 0);  // CIE id
    append_u8(payload, 1);   // version
    append_u8(payload, 'z');
    append_u8(payload, 'L');
    append_u8(payload, 'R');
    append_u8(payload, 0);
    append_u8(payload, 1);   // code alignment
    append_u8(payload, 0x78);  // data alignment: -8 (SLEB128)
    append_u8(payload, 16);  // return-address register
    append_u8(payload, 2);   // CIE augmentation length
    append_u8(payload, spelunk::ehfi::DW_EH_PE_udata8);
    append_u8(payload, spelunk::ehfi::DW_EH_PE_udata4);
    append_record(section, payload);
    return offset;
}

std::size_t append_undersized_lsda_cie(std::vector<std::byte>& section) {
    const std::size_t offset = section.size();
    std::vector<std::byte> payload;
    append_u32(payload, 0);  // CIE id
    append_u8(payload, 1);   // version
    append_u8(payload, 'z');
    append_u8(payload, 'L');
    append_u8(payload, 'R');
    append_u8(payload, 0);
    append_u8(payload, 1);   // code alignment
    append_u8(payload, 0x78);  // data alignment: -8 (SLEB128)
    append_u8(payload, 16);  // return-address register
    append_u8(payload, 1);   // Too short for both L and R fields.
    append_u8(payload, spelunk::ehfi::DW_EH_PE_udata8);
    // This is the first CFI instruction, not part of the augmentation.
    append_u8(payload, spelunk::ehfi::DW_EH_PE_udata4);
    append_record(section, payload);
    return offset;
}

std::size_t append_aarch64_marker_cie(std::vector<std::byte>& section) {
    const std::size_t offset = section.size();
    std::vector<std::byte> payload;
    append_u32(payload, 0);  // CIE id
    append_u8(payload, 1);   // version
    append_u8(payload, 'z');
    append_u8(payload, 'R');
    append_u8(payload, 'B');
    append_u8(payload, 0);
    append_u8(payload, 1);   // code alignment
    append_u8(payload, 0x78);  // data alignment: -8 (SLEB128)
    append_u8(payload, 16);  // return-address register
    append_u8(payload, 1);   // Only R contributes augmentation data.
    append_u8(payload, spelunk::ehfi::DW_EH_PE_udata4);
    append_record(section, payload);
    return offset;
}

void append_abs_fde(std::vector<std::byte>& section,
                    std::size_t cie_offset,
                    u64 pc_begin,
                    u64 pc_range,
                    u32 cie_pointer_override = 0) {
    const std::size_t cie_pointer_pos = section.size() + sizeof(u32);
    std::vector<std::byte> payload;
    const auto cie_pointer = cie_pointer_override != 0
        ? cie_pointer_override
        : static_cast<u32>(cie_pointer_pos - cie_offset);
    append_u32(payload, cie_pointer);
    append_u64(payload, pc_begin);
    append_u64(payload, pc_range);
    append_record(section, payload);
}

class MockBinary final : public spelunk::Binary {
public:
    explicit MockBinary(std::vector<std::byte> eh_frame)
        : bytes_(std::move(eh_frame)) {
        section_.name = ".eh_frame";
        section_.vaddr = 0x1000;
        section_.size = bytes_.size();
        section_.flags.readable = true;
        section_.data = bytes_;
    }

    [[nodiscard]] spelunk::Format format() const noexcept override {
        return spelunk::Format::Elf;
    }
    [[nodiscard]] spelunk::Arch arch() const noexcept override {
        return spelunk::Arch::X86_64;
    }
    [[nodiscard]] spelunk::Endian endian() const noexcept override {
        return spelunk::Endian::Little;
    }
    [[nodiscard]] spelunk::addr_t entry_point() const noexcept override {
        return 0;
    }
    [[nodiscard]] std::span<const spelunk::Section>
    sections() const noexcept override {
        return std::span<const spelunk::Section>(&section_, 1);
    }
    [[nodiscard]] std::span<const spelunk::Symbol>
    symbols() const noexcept override {
        return symbols_;
    }
    [[nodiscard]] std::span<const std::byte>
    image() const noexcept override {
        return bytes_;
    }

protected:
    [[nodiscard]] std::vector<spelunk::Symbol>&
    mutable_symbols() noexcept override {
        return symbols_;
    }

private:
    std::vector<std::byte> bytes_;
    spelunk::Section section_;
    std::vector<spelunk::Symbol> symbols_;
};

std::size_t visit_count(const MockBinary& binary) {
    std::size_t count = 0;
    spelunk::ehfi::for_each_decoded_fde(
        binary, [&](const spelunk::ehfi::DecodedFde&) {
            ++count;
            return spelunk::ehfi::FdeVisit::Continue;
        });
    return count;
}

void test_short_record_is_rejected() {
    std::vector<std::byte> section;
    append_u32(section, 3);
    append_u32(section, 1);  // Physical bytes exist, declared payload is short.
    MockBinary binary(std::move(section));
    check(visit_count(binary) == 0,
          "record shorter than its CIE id is rejected");
}

void test_forward_cie_reference_is_rejected() {
    std::vector<std::byte> section;
    append_plain_cie(section);
    const auto cie_pointer_pos = section.size() + sizeof(u32);
    append_abs_fde(section, 0, 0x2000, 0x40,
                   static_cast<u32>(cie_pointer_pos + 1));
    MockBinary binary(std::move(section));
    check(visit_count(binary) == 0,
          "impossible backward CIE reference does not alias offset zero");
}

void test_lsda_decode_stays_inside_augmentation() {
    std::vector<std::byte> section;
    const auto cie_offset = append_lsda_cie(section);
    const std::size_t cie_pointer_pos = section.size() + sizeof(u32);

    std::vector<std::byte> fde;
    append_u32(fde, static_cast<u32>(cie_pointer_pos - cie_offset));
    append_u32(fde, 0x2000);
    append_u32(fde, 0x40);
    append_u8(fde, 1);     // FDE augmentation length
    append_u8(fde, 0xaa);  // Too short for the advertised udata8 LSDA.
    for (u8 byte = 1; byte <= 8; ++byte) append_u8(fde, byte);
    append_record(section, fde);

    MockBinary binary(std::move(section));
    std::size_t count = 0;
    spelunk::ehfi::for_each_decoded_fde(
        binary, [&](const spelunk::ehfi::DecodedFde& decoded) {
            ++count;
            check(decoded.augmentation_valid,
                  "bounded but undersized LSDA augmentation keeps CFI boundary");
            check(!decoded.lsda_address,
                  "LSDA decoder cannot consume following CFI instructions");
            check(decoded.instructions.size() == 8,
                  "CFI instructions start after the declared augmentation");
            return spelunk::ehfi::FdeVisit::Continue;
        });
    check(count == 1, "bounded LSDA test visits its FDE");
}

void test_cie_decode_stays_inside_augmentation() {
    std::vector<std::byte> section;
    const auto cie_offset = append_undersized_lsda_cie(section);
    const std::size_t cie_pointer_pos = section.size() + sizeof(u32);

    std::vector<std::byte> fde;
    append_u32(fde, static_cast<u32>(cie_pointer_pos - cie_offset));
    append_u32(fde, 0x2000);
    append_u32(fde, 0x40);
    append_u8(fde, 0);  // Empty FDE augmentation.
    append_record(section, fde);

    MockBinary binary(std::move(section));
    check(visit_count(binary) == 0,
          "CIE fields cannot consume its initial CFI instructions");
}

void test_cie_marker_has_no_payload_byte() {
    std::vector<std::byte> section;
    const auto cie_offset = append_aarch64_marker_cie(section);
    const std::size_t cie_pointer_pos = section.size() + sizeof(u32);

    std::vector<std::byte> fde;
    append_u32(fde, static_cast<u32>(cie_pointer_pos - cie_offset));
    append_u32(fde, 0x2000);
    append_u32(fde, 0x40);
    append_u8(fde, 0);  // Empty FDE augmentation.
    append_record(section, fde);

    MockBinary binary(std::move(section));
    std::size_t count = 0;
    spelunk::ehfi::for_each_decoded_fde(
        binary, [&](const spelunk::ehfi::DecodedFde& decoded) {
            ++count;
            check(decoded.pc_begin == 0x2000 && decoded.pc_range == 0x40,
                  "marker-only CIE preserves FDE pointer encoding");
            return spelunk::ehfi::FdeVisit::Continue;
        });
    check(count == 1, "AArch64 B marker consumes no augmentation byte");
}

void test_truncated_augmentation_is_marked_invalid() {
    std::vector<std::byte> section;
    const auto cie_offset = append_lsda_cie(section);
    const std::size_t cie_pointer_pos = section.size() + sizeof(u32);

    std::vector<std::byte> fde;
    append_u32(fde, static_cast<u32>(cie_pointer_pos - cie_offset));
    append_u32(fde, 0x2000);
    append_u32(fde, 0x40);
    append_u8(fde, 8);  // Only the next two bytes exist.
    append_u8(fde, 0xaa);
    append_u8(fde, 0xbb);
    append_record(section, fde);

    MockBinary binary(std::move(section));
    std::size_t count = 0;
    spelunk::ehfi::for_each_decoded_fde(
        binary, [&](const spelunk::ehfi::DecodedFde& decoded) {
            ++count;
            check(!decoded.augmentation_valid,
                  "truncated augmentation is invalid");
            check(!decoded.lsda_address,
                  "truncated augmentation cannot produce an LSDA address");
            check(decoded.instructions.empty(),
                  "invalid augmentation has no instruction boundary");
            return spelunk::ehfi::FdeVisit::Continue;
        });
    check(count == 1, "extent-tolerant walk still reports malformed FDE");
}

void test_overflowing_pc_range_is_rejected() {
    std::vector<std::byte> section;
    const auto cie_offset = append_plain_cie(section);
    append_abs_fde(section, cie_offset,
                   std::numeric_limits<u64>::max() - 3, 8);
    MockBinary binary(std::move(section));
    check(visit_count(binary) == 0,
          "FDE whose address range wraps is rejected");
}

}  // namespace

int main() {
    test_short_record_is_rejected();
    test_forward_cie_reference_is_rejected();
    test_lsda_decode_stays_inside_augmentation();
    test_cie_decode_stays_inside_augmentation();
    test_cie_marker_has_no_payload_byte();
    test_truncated_augmentation_is_marked_invalid();
    test_overflowing_pc_range_is_rejected();

    if (failures != 0) {
        std::fprintf(stderr, "%d EH-frame test(s) failed\n", failures);
        return 1;
    }
    return 0;
}
