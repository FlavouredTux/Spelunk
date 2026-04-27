// Unit tests for the PDB v7 (MSF) reader.
//
// We synthesize a minimal but well-formed MSF in memory and parse it,
// rather than committing a binary fixture. The synthesized container has:
//   - 1024-byte blocks
//   - 5 streams: 0 (old dir), 1 (PDB info), 2 (TPI), 3 (DBI header),
//                4 (symbol records, holding two S_PUB32 records)
// The parser must walk the directory, find the DBI's sym_record_stream
// pointer (= 4), read stream 4, and turn the S_PUB32 records into
// PublicSymbols.
#include <ember/binary/pdb.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string_view>
#include <vector>

namespace {

int fails = 0;

template <typename A, typename B>
void check_eq(const A& got, const B& want, const char* ctx) {
    if (!(got == want)) {
        std::fprintf(stderr, "FAIL: %s\n", ctx);
        ++fails;
    }
}

void check_eq_sz(std::size_t got, std::size_t want, const char* ctx) {
    if (got != want) {
        std::fprintf(stderr, "FAIL: %s (got %zu, want %zu)\n", ctx, got, want);
        ++fails;
    }
}

// ---- Tiny in-memory writer ----------------------------------------------

struct W {
    std::vector<std::byte> buf;

    void put_u8(std::uint8_t v) { buf.push_back(static_cast<std::byte>(v)); }
    void put_u16(std::uint16_t v) {
        put_u8(static_cast<std::uint8_t>(v & 0xff));
        put_u8(static_cast<std::uint8_t>((v >> 8) & 0xff));
    }
    void put_u32(std::uint32_t v) {
        put_u16(static_cast<std::uint16_t>(v & 0xffff));
        put_u16(static_cast<std::uint16_t>((v >> 16) & 0xffff));
    }
    void put_i32(std::int32_t v) { put_u32(static_cast<std::uint32_t>(v)); }
    void put_bytes(const void* p, std::size_t n) {
        const auto* b = static_cast<const std::byte*>(p);
        buf.insert(buf.end(), b, b + n);
    }
    void put_cstr(std::string_view s) {
        put_bytes(s.data(), s.size());
        put_u8(0);
    }
    void pad_to_block(std::size_t block_size) {
        const std::size_t r = buf.size() % block_size;
        if (r != 0) buf.resize(buf.size() + (block_size - r));
    }
    void pad_to_align(std::size_t align) {
        const std::size_t r = buf.size() % align;
        if (r != 0) buf.resize(buf.size() + (align - r));
    }
};

// ---- Build a synthetic MSF v7 ------------------------------------------

constexpr std::array<std::uint8_t, 32> kV7Magic{
    'M','i','c','r','o','s','o','f','t',' ','C','/','C','+','+',' ',
    'M','S','F',' ','7','.','0','0','\r','\n',0x1A,'D','S',0,0,0,
};
constexpr std::uint32_t kBlockSize = 1024;

// Lay out blocks in this order:
//   block 0: superblock
//   block 1: free-block-map (zeros — we don't read it)
//   block 2: stream 1 (PDB info, anything; we use 4 zero bytes "version")
//   block 3: stream 2 (TPI, empty)
//   block 4: stream 3 (DBI header — sym_record_stream = 4)
//   block 5: stream 4 (S_PUB32 records, our payload)
//   block 6: stream directory
//   block 7: directory block-map (one u32 pointing at block 6)

std::vector<std::byte> make_dbi_header() {
    W w;
    w.put_i32(-1);          // signature (NewDBI)
    w.put_u32(19990903);    // version (V70 — value not actually checked)
    w.put_u32(1);           // age
    w.put_u16(0xFFFF);      // GlobalStreamIndex
    w.put_u16(0);           // BuildNumber
    w.put_u16(0xFFFF);      // PublicStreamIndex
    w.put_u16(0);           // PdbDllVersion
    w.put_u16(4);           // SymRecordStream  ← parser reads this
    w.put_u16(0);           // PdbDllRbld
    // ModInfoSize, SectionContributionSize, SectionMapSize, SourceInfoSize,
    // TypeServerMapSize, MFCTypeServerIndex, OptionalDbgHeaderSize, ECSize:
    for (int i = 0; i < 8; ++i) w.put_u32(0);
    w.put_u16(0);           // Flags
    w.put_u16(0x8664);      // Machine (x86-64; not validated)
    w.put_u32(0);           // Padding
    return w.buf;
}

void put_s_pub32(W& w, std::string_view name, std::uint32_t flags,
                 std::uint32_t section_offset, std::uint16_t segment) {
    // Reserve length placeholder, fill at end.
    const std::size_t start = w.buf.size();
    w.put_u16(0);           // length (patched)
    w.put_u16(0x110E);      // S_PUB32
    w.put_u32(flags);
    w.put_u32(section_offset);
    w.put_u16(segment);
    w.put_cstr(name);
    // Pad to 4-byte alignment with f1/f2/f3 bytes (CodeView convention).
    while ((w.buf.size() - start) % 4 != 0) {
        const std::uint8_t pad =
            (w.buf.size() - start) % 4 == 1 ? 0xF3 :
            (w.buf.size() - start) % 4 == 2 ? 0xF2 : 0xF1;
        w.put_u8(pad);
    }
    const std::size_t total = w.buf.size() - start;
    const std::uint16_t reclen = static_cast<std::uint16_t>(total - 2);
    w.buf[start + 0] = static_cast<std::byte>(reclen & 0xFF);
    w.buf[start + 1] = static_cast<std::byte>((reclen >> 8) & 0xFF);
}

std::vector<std::byte> make_sym_record_stream() {
    W w;
    put_s_pub32(w, "do_thing",      /*flags=*/0x2, 0x100, 1);  // is_function
    put_s_pub32(w, "g_counter",     /*flags=*/0x0, 0x010, 2);  // data
    put_s_pub32(w, "?BadlyMangled", /*flags=*/0x2, 0x200, 1);  // function
    return w.buf;
}

std::vector<std::byte> build_msf() {
    const auto dbi = make_dbi_header();
    const auto sym = make_sym_record_stream();

    // Stream sizes — pre-compute layout. Stream 0 is "old dir" (we leave
    // empty); stream 1 minimal placeholder; stream 2 (TPI) empty; stream 3
    // = DBI header bytes; stream 4 = symbol records.
    const std::uint32_t s0 = 0;
    const std::uint32_t s1 = 4;          // 4 bytes of "PDB info"
    const std::uint32_t s2 = 0;
    const std::uint32_t s3 = static_cast<std::uint32_t>(dbi.size());
    const std::uint32_t s4 = static_cast<std::uint32_t>(sym.size());
    const std::array<std::uint32_t, 5> sizes{s0, s1, s2, s3, s4};

    auto blocks_for = [](std::uint32_t sz) {
        return sz == 0 ? 0u : (sz + kBlockSize - 1) / kBlockSize;
    };

    // Decide block indices up front.
    constexpr std::uint32_t kSuperblockBlock = 0;
    constexpr std::uint32_t kFreeBlock       = 1;
    // Streams pack starting at block 2.
    std::uint32_t next = 2;
    std::array<std::vector<std::uint32_t>, 5> stream_blocks;
    for (std::size_t i = 0; i < sizes.size(); ++i) {
        const std::uint32_t n = blocks_for(sizes[i]);
        for (std::uint32_t j = 0; j < n; ++j) stream_blocks[i].push_back(next++);
    }
    const std::uint32_t kDirBlock    = next++;
    const std::uint32_t kDirMapBlock = next++;
    const std::uint32_t kNumBlocks   = next;

    // Build the directory bytes:
    //   u32 num_streams
    //   u32 sizes[num_streams]
    //   u32 block_indices[concatenated]
    W dirw;
    dirw.put_u32(static_cast<std::uint32_t>(sizes.size()));
    for (std::uint32_t s : sizes) dirw.put_u32(s);
    for (const auto& bs : stream_blocks)
        for (std::uint32_t b : bs) dirw.put_u32(b);
    const std::uint32_t dir_size = static_cast<std::uint32_t>(dirw.buf.size());

    // Final image. We grow `out` block-by-block, writing each block at
    // its assigned position.
    std::vector<std::byte> out(static_cast<std::size_t>(kNumBlocks) * kBlockSize);
    auto write_block = [&](std::uint32_t block_idx, const std::byte* p,
                           std::size_t n) {
        const std::size_t off = static_cast<std::size_t>(block_idx) * kBlockSize;
        std::memcpy(out.data() + off, p, n);
    };

    // Superblock.
    {
        W w;
        w.put_bytes(kV7Magic.data(), kV7Magic.size());
        w.put_u32(kBlockSize);           // block size
        w.put_u32(kFreeBlock);           // free-block-map block index (we don't actually use it)
        w.put_u32(kNumBlocks);           // total blocks
        w.put_u32(dir_size);             // directory size in bytes
        w.put_u32(0);                    // unknown
        w.put_u32(kDirMapBlock);         // block index of the directory's block-map
        write_block(kSuperblockBlock, w.buf.data(), w.buf.size());
    }

    // Stream 1 placeholder (4 bytes).
    {
        W w;
        w.put_u32(20140508);
        write_block(stream_blocks[1][0], w.buf.data(), w.buf.size());
    }

    // Stream 3 (DBI).
    write_block(stream_blocks[3][0], dbi.data(), dbi.size());

    // Stream 4 (symbol records). May span multiple blocks; copy sequentially.
    {
        std::size_t copied = 0;
        for (std::uint32_t b : stream_blocks[4]) {
            const std::size_t take = std::min<std::size_t>(kBlockSize,
                sym.size() - copied);
            write_block(b, sym.data() + copied, take);
            copied += take;
        }
    }

    // Directory block (single block, since dir_size < kBlockSize).
    write_block(kDirBlock, dirw.buf.data(), dirw.buf.size());

    // Directory block-map: one u32 pointing at kDirBlock.
    {
        W w;
        w.put_u32(kDirBlock);
        write_block(kDirMapBlock, w.buf.data(), w.buf.size());
    }

    return out;
}

}  // namespace

int main() {
    auto bytes = build_msf();

    auto pubs = ember::pdb::load_publics_from_buffer(std::move(bytes));
    if (!pubs) {
        std::fprintf(stderr, "FAIL: load_publics_from_buffer: %s\n",
                     pubs.error().message.c_str());
        return 1;
    }

    check_eq_sz(pubs->size(), 3u, "publics count");
    if (pubs->size() == 3) {
        check_eq((*pubs)[0].name, std::string("do_thing"), "name[0]");
        check_eq((*pubs)[0].section_offset, 0x100u, "off[0]");
        check_eq((*pubs)[0].segment, std::uint16_t{1}, "seg[0]");
        check_eq((*pubs)[0].is_function, true, "is_fn[0]");

        check_eq((*pubs)[1].name, std::string("g_counter"), "name[1]");
        check_eq((*pubs)[1].section_offset, 0x010u, "off[1]");
        check_eq((*pubs)[1].segment, std::uint16_t{2}, "seg[1]");
        check_eq((*pubs)[1].is_function, false, "is_fn[1]");

        check_eq((*pubs)[2].name, std::string("?BadlyMangled"), "name[2]");
        check_eq((*pubs)[2].is_function, true, "is_fn[2]");
    }

    if (fails == 0) {
        std::fprintf(stderr, "pdb_test: ok\n");
        return 0;
    }
    return 1;
}
