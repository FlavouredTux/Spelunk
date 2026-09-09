// Cafe RPX/RPL sections use a big-endian size followed by a zlib stream.
#include <ember/binary/elf.hpp>

#include <format>
#include <utility>

#include "elf_internal.hpp"

#ifdef EMBER_HAS_ZLIB
#include <zlib.h>
#endif

namespace ember {

Result<void> ElfBinary::decompress_cafe_sections(const ParsedEhdr& h) {
    // The processor-specific flag must not be interpreted on ordinary ELF.
    if (h.is_64bit || endian_ != Endian::Big || h.e_machine != 20 ||
        buffer_[7] != std::byte{0xca}) return {};
    if (h.e_shnum == 0) return {};
    if (h.e_shentsize != elf::kShdr32Size) {
        return std::unexpected(Error::invalid_format("cafe: invalid section header size"));
    }
    const ByteReader reader(buffer_);
    auto table = reader.slice(h.e_shoff, static_cast<u64>(h.e_shnum) * h.e_shentsize);
    if (!table) return std::unexpected(table.error());
    constexpr u64 deflated = 0x08000000;
    // Snapshot headers before any buffer growth or header rewriting.
    std::vector<elf::Shdr> headers;
    headers.reserve(h.e_shnum);
    for (u32 i = 0; i < h.e_shnum; ++i)
        headers.push_back(elf::shdr_at(endian_, table->data(), i, false));

#ifdef EMBER_HAS_ZLIB
    constexpr std::size_t section_limit = 256u * 1024u * 1024u;
    constexpr std::size_t total_limit = 512u * 1024u * 1024u;
    std::size_t expanded_total = 0;
    struct Expanded { u32 index; std::vector<std::byte> bytes; };
    std::vector<Expanded> expanded;
#endif
    for (u32 i = 0; i < h.e_shnum; ++i) {
        const auto& sh = headers[i];
        if ((sh.flags & deflated) == 0) continue;
        if (sh.type == elf::sht::NOBITS || sh.type == elf::sht::NULL_ || sh.size < 4) {
            return std::unexpected(Error::invalid_format(std::format(
                "cafe: invalid compressed section {}", i)));
        }
        auto input = reader.slice(sh.offset, sh.size);
        if (!input) return std::unexpected(input.error());
#ifndef EMBER_HAS_ZLIB
        return std::unexpected(Error::unsupported(
            "cafe: compressed RPX/RPL sections require a build with zlib"));
#else
        const u32 size = read_be_at<u32>(input->data());
        if (size > section_limit || size > total_limit - expanded_total) {
            return std::unexpected(Error::invalid_format(
                "cafe: decompressed sections exceed the 256 MiB section / 512 MiB total limit"));
        }
        // One spare byte also allows a valid empty stream and detects output
        // exceeding the declared size without trusting the length prefix.
        std::vector<std::byte> output(static_cast<std::size_t>(size) + 1);
        z_stream stream{};
        stream.next_in = reinterpret_cast<Bytef*>(const_cast<std::byte*>(input->data() + 4));
        stream.avail_in = static_cast<uInt>(sh.size - 4);
        stream.next_out = reinterpret_cast<Bytef*>(output.data());
        stream.avail_out = static_cast<uInt>(output.size());
        if (inflateInit(&stream) != Z_OK) {
            return std::unexpected(Error::invalid_format("cafe: cannot initialize zlib"));
        }
        const int status = inflate(&stream, Z_FINISH);
        const bool valid = status == Z_STREAM_END && stream.total_out == size && stream.avail_in == 0;
        inflateEnd(&stream);
        if (!valid) {
            return std::unexpected(Error::invalid_format(std::format(
                "cafe: section {} has an invalid zlib stream or decompressed size", i)));
        }
        output.resize(size);
        expanded_total += size;
        expanded.push_back({i, std::move(output)});
#endif
    }
#ifdef EMBER_HAS_ZLIB
    if (expanded.empty()) return {};
    if (buffer_.size() > 0xffffffffULL - expanded_total) {
        return std::unexpected(Error::invalid_format("cafe: expanded image exceeds ELF32 offsets"));
    }
    buffer_.reserve(buffer_.size() + expanded_total);
    auto write32 = [this](std::size_t offset, u32 value) {
        for (unsigned j = 0; j < 4; ++j)
            buffer_[offset + j] = static_cast<std::byte>((value >> ((3 - j) * 8)) & 0xffu);
    };
    // Normalize only the owned in-memory image, before any Section/Segment
    // spans exist. Every later parser sees the same expanded section offsets.
    for (const auto& section : expanded) {
        const u32 offset = static_cast<u32>(buffer_.size());
        buffer_.insert(buffer_.end(), section.bytes.begin(), section.bytes.end());
        const auto at = static_cast<std::size_t>(h.e_shoff) + section.index * elf::kShdr32Size;
        write32(at + 8, static_cast<u32>(headers[section.index].flags & ~deflated));
        write32(at + 16, offset);
        write32(at + 20, static_cast<u32>(section.bytes.size()));
    }
#endif
    return {};
}

} // namespace ember
