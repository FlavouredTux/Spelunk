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

// ---- Richer fixture: TPI types + module symbol stream w/ type indices --
// Builds a more complete MSF that exercises the new code paths:
//   stream 0: old dir (empty)
//   stream 1: PDB info (version+sig+age+GUID)
//   stream 2: TPI with two records — LF_ARGLIST (one arg, char*),
//             LF_PROCEDURE returning int, taking that arglist
//   stream 3: DBI header + 1 ModInfo record pointing at stream 5
//   stream 4: legacy global symbol-record stream (one S_PUB32)
//   stream 5: module symbol stream — signature 4 + S_GPROC32 with
//             TypeIndex pointing at our LF_PROCEDURE record

constexpr std::uint32_t kTiBegin = 0x1000;

std::vector<std::byte> make_pdb_info_stream() {
    W w;
    w.put_u32(20091201);  // V70
    w.put_u32(0xCAFEBABE); // signature
    w.put_u32(7);          // age
    // 16-byte GUID — synthetic constant value.
    for (int i = 0; i < 16; ++i) w.put_u8(static_cast<std::uint8_t>(0x10 + i));
    return w.buf;
}

void put_record_header(W& w, std::uint16_t kind, std::size_t start) {
    // Pad to 4-byte alignment + patch length. Same convention as
    // CodeView symbol records.
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
    // Kind goes immediately after the length.
    w.buf[start + 2] = static_cast<std::byte>(kind & 0xFF);
    w.buf[start + 3] = static_cast<std::byte>((kind >> 8) & 0xFF);
}

void put_lf_arglist(W& w, std::vector<std::uint32_t> args) {
    const std::size_t start = w.buf.size();
    w.put_u16(0);       // length placeholder
    w.put_u16(0);       // kind placeholder
    w.put_u32(static_cast<std::uint32_t>(args.size()));
    for (auto a : args) w.put_u32(a);
    put_record_header(w, 0x1201 /* LF_ARGLIST */, start);
}

void put_lf_procedure(W& w, std::uint32_t return_ti, std::uint16_t param_count,
                      std::uint32_t arg_list_ti) {
    const std::size_t start = w.buf.size();
    w.put_u16(0);
    w.put_u16(0);
    w.put_u32(return_ti);
    w.put_u8(0);                 // CallConv (CV_CALL_NEAR_C)
    w.put_u8(0);                 // FuncAttrs
    w.put_u16(param_count);
    w.put_u32(arg_list_ti);
    put_record_header(w, 0x1008 /* LF_PROC */, start);
}

std::vector<std::byte> make_tpi_stream() {
    W w;
    // 56-byte header.
    w.put_u32(20040203);                // Version (V80)
    w.put_u32(56);                       // HeaderSize
    w.put_u32(kTiBegin);                 // TypeIndexBegin
    w.put_u32(kTiBegin + 2);             // TypeIndexEnd (we add 2 records)
    w.put_u32(0);                        // TypeRecordBytes (patched)
    w.put_u16(0xFFFF); w.put_u16(0xFFFF);// HashStreamIndex / Aux
    w.put_u32(0);                        // HashKeySize
    w.put_u32(0);                        // NumHashBuckets
    w.put_u32(0); w.put_u32(0);          // HashValue offset/length
    w.put_u32(0); w.put_u32(0);          // IndexOffset offset/length
    w.put_u32(0); w.put_u32(0);          // HashAdj offset/length

    const std::size_t records_start = w.buf.size();
    // Index 0x1000: LF_ARGLIST(1, char*)
    //   T_PCHAR (mode=4 ptr to T_RCHAR=0x70) = 0x470
    put_lf_arglist(w, { 0x470u });
    // Index 0x1001: LF_PROC returning int (T_INT4=0x74), 1 param, args=0x1000
    put_lf_procedure(w, /*return*/0x74u, /*params*/1, /*args*/kTiBegin);

    const std::size_t records_end = w.buf.size();
    const std::uint32_t records_bytes =
        static_cast<std::uint32_t>(records_end - records_start);
    // Patch TypeRecordBytes at +16.
    w.buf[16] = static_cast<std::byte>(records_bytes & 0xFF);
    w.buf[17] = static_cast<std::byte>((records_bytes >>  8) & 0xFF);
    w.buf[18] = static_cast<std::byte>((records_bytes >> 16) & 0xFF);
    w.buf[19] = static_cast<std::byte>((records_bytes >> 24) & 0xFF);
    return w.buf;
}

void put_s_gproc32(W& w, std::string_view name, std::uint32_t type_index,
                   std::uint32_t section_offset, std::uint16_t segment,
                   std::uint32_t code_size) {
    const std::size_t start = w.buf.size();
    w.put_u16(0);                  // length placeholder
    w.put_u16(0);                  // kind placeholder
    w.put_u32(0);                  // Parent
    w.put_u32(0);                  // End
    w.put_u32(0);                  // Next
    w.put_u32(code_size);          // CodeSize
    w.put_u32(0);                  // DbgStart
    w.put_u32(code_size);          // DbgEnd
    w.put_u32(type_index);         // TypeIndex
    w.put_u32(section_offset);     // Offset
    w.put_u16(segment);            // Segment
    w.put_u8(0);                   // Flags
    w.put_cstr(name);
    put_record_header(w, 0x1110 /* S_GPROC32 */, start);
}

std::vector<std::byte> make_module_stream() {
    W w;
    w.put_u32(4);                  // C13 signature
    put_s_gproc32(w, "do_things", /*ti=*/kTiBegin + 1, /*off=*/0x500, /*seg=*/1,
                  /*code_size=*/0x40);
    return w.buf;
}

std::vector<std::byte> make_dbi_header_with_module(std::uint16_t mod_sym_stream,
                                                   std::uint32_t mod_sym_size,
                                                   std::uint32_t mod_info_size) {
    W w;
    w.put_i32(-1);
    w.put_u32(19990903);
    w.put_u32(1);
    w.put_u16(0xFFFF);
    w.put_u16(0);
    w.put_u16(0xFFFF);
    w.put_u16(0);
    w.put_u16(4);                  // SymRecordStream = 4
    w.put_u16(0);
    w.put_u32(mod_info_size);      // ModInfoSize
    for (int i = 0; i < 7; ++i) w.put_u32(0); // SectionContrib, SectionMap, SourceInfo, TypeServerMap, MFC, OptionalDbgHeader, EC
    w.put_u16(0);                  // Flags
    w.put_u16(0x8664);
    w.put_u32(0);                  // Padding

    // Append the ModInfo array (only 1 record).
    const std::size_t mod_start = w.buf.size();
    w.put_u32(0);                  // Unused1
    // SectionContribEntry (28 bytes of zeros — we don't use it).
    for (int i = 0; i < 28; ++i) w.put_u8(0);
    w.put_u16(0);                  // Flags
    w.put_u16(mod_sym_stream);     // ModuleSymStream  ← important
    w.put_u32(mod_sym_size);       // SymByteSize     ← important
    w.put_u32(0);                  // C11ByteSize
    w.put_u32(0);                  // C13ByteSize
    w.put_u16(0);                  // SourceFileCount
    w.put_u16(0);                  // Padding
    w.put_u32(0);                  // Unused2
    w.put_u32(0);                  // SourceFileNameIndex
    w.put_u32(0);                  // PdbFilePathNameIndex
    w.put_cstr("a.obj");           // ModuleName
    w.put_cstr("a.obj");           // ObjFileName
    w.pad_to_align(4);
    const std::size_t mod_size = w.buf.size() - mod_start;
    // Patch ModInfoSize at +24.
    const std::uint32_t actual_mod_info_size = static_cast<std::uint32_t>(mod_size);
    w.buf[24] = static_cast<std::byte>(actual_mod_info_size & 0xFF);
    w.buf[25] = static_cast<std::byte>((actual_mod_info_size >>  8) & 0xFF);
    w.buf[26] = static_cast<std::byte>((actual_mod_info_size >> 16) & 0xFF);
    w.buf[27] = static_cast<std::byte>((actual_mod_info_size >> 24) & 0xFF);
    return w.buf;
}

std::vector<std::byte> build_rich_msf() {
    const auto pdb_info = make_pdb_info_stream();
    const auto tpi      = make_tpi_stream();
    const auto sym      = make_sym_record_stream();
    const auto modstm   = make_module_stream();
    // DBI header + ModInfo array — modules point at stream 5 carrying
    // S_GPROC32. mod_info_size will be patched after computing.
    const auto dbi = make_dbi_header_with_module(/*mod_sym_stream=*/5,
                                                  /*mod_sym_size=*/static_cast<std::uint32_t>(modstm.size()),
                                                  /*mod_info_size=*/0);

    // 6 streams: 0..5
    const std::uint32_t s0 = 0;
    const std::uint32_t s1 = static_cast<std::uint32_t>(pdb_info.size());
    const std::uint32_t s2 = static_cast<std::uint32_t>(tpi.size());
    const std::uint32_t s3 = static_cast<std::uint32_t>(dbi.size());
    const std::uint32_t s4 = static_cast<std::uint32_t>(sym.size());
    const std::uint32_t s5 = static_cast<std::uint32_t>(modstm.size());
    const std::array<std::uint32_t, 6> sizes{s0, s1, s2, s3, s4, s5};
    auto blocks_for = [](std::uint32_t sz) {
        return sz == 0 ? 0u : (sz + kBlockSize - 1) / kBlockSize;
    };

    constexpr std::uint32_t kSuperblockBlock = 0;
    constexpr std::uint32_t kFreeBlock       = 1;
    std::uint32_t next = 2;
    std::array<std::vector<std::uint32_t>, 6> stream_blocks;
    for (std::size_t i = 0; i < sizes.size(); ++i) {
        const std::uint32_t n = blocks_for(sizes[i]);
        for (std::uint32_t j = 0; j < n; ++j) stream_blocks[i].push_back(next++);
    }
    const std::uint32_t kDirBlock    = next++;
    const std::uint32_t kDirMapBlock = next++;
    const std::uint32_t kNumBlocks   = next;

    W dirw;
    dirw.put_u32(static_cast<std::uint32_t>(sizes.size()));
    for (std::uint32_t s : sizes) dirw.put_u32(s);
    for (const auto& bs : stream_blocks)
        for (std::uint32_t b : bs) dirw.put_u32(b);
    const std::uint32_t dir_size = static_cast<std::uint32_t>(dirw.buf.size());

    std::vector<std::byte> out(static_cast<std::size_t>(kNumBlocks) * kBlockSize);
    auto write_block = [&](std::uint32_t block_idx, const std::byte* p,
                           std::size_t n) {
        const std::size_t off = static_cast<std::size_t>(block_idx) * kBlockSize;
        std::memcpy(out.data() + off, p, n);
    };

    {
        W w;
        w.put_bytes(kV7Magic.data(), kV7Magic.size());
        w.put_u32(kBlockSize);
        w.put_u32(kFreeBlock);
        w.put_u32(kNumBlocks);
        w.put_u32(dir_size);
        w.put_u32(0);
        w.put_u32(kDirMapBlock);
        write_block(kSuperblockBlock, w.buf.data(), w.buf.size());
    }

    auto write_stream = [&](std::size_t idx, const std::vector<std::byte>& data) {
        if (data.empty()) return;
        std::size_t copied = 0;
        for (std::uint32_t b : stream_blocks[idx]) {
            const std::size_t take = std::min<std::size_t>(kBlockSize,
                data.size() - copied);
            write_block(b, data.data() + copied, take);
            copied += take;
        }
    };
    write_stream(1, pdb_info);
    write_stream(2, tpi);
    write_stream(3, dbi);
    write_stream(4, sym);
    write_stream(5, modstm);

    write_block(kDirBlock, dirw.buf.data(), dirw.buf.size());
    {
        W w;
        w.put_u32(kDirBlock);
        write_block(kDirMapBlock, w.buf.data(), w.buf.size());
    }
    return out;
}

void test_publics_only() {
    auto bytes = build_msf();

    auto pubs = ember::pdb::load_publics_from_buffer(std::move(bytes));
    if (!pubs) {
        std::fprintf(stderr, "FAIL: load_publics_from_buffer: %s\n",
                     pubs.error().message.c_str());
        ++fails;
        return;
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
}

void test_full_pdb_with_types() {
    auto bytes = build_rich_msf();
    auto rdr = ember::pdb::load_pdb_from_buffer(std::move(bytes));
    if (!rdr) {
        std::fprintf(stderr, "FAIL: load_pdb_from_buffer (rich): %s\n",
                     rdr.error().message.c_str());
        ++fails;
        return;
    }

    // PDB info round-trips.
    check_eq(rdr->info.signature, std::uint32_t{0xCAFEBABE}, "info.signature");
    check_eq(rdr->info.age, std::uint32_t{7}, "info.age");

    // Module symbol stream should yield one S_GPROC32 with type_index = 0x1001.
    check_eq_sz(rdr->procs.size(), 1u, "procs count");
    if (rdr->procs.size() == 1) {
        check_eq(rdr->procs[0].name, std::string("do_things"), "proc.name");
        check_eq(rdr->procs[0].section_offset, std::uint32_t{0x500}, "proc.off");
        check_eq(rdr->procs[0].segment, std::uint16_t{1}, "proc.seg");
        check_eq(rdr->procs[0].type_index, std::uint32_t{0x1001}, "proc.type_index");
        check_eq(rdr->procs[0].length, std::uint32_t{0x40}, "proc.length");
    }

    // TPI lookup should resolve the procedure record.
    const auto* proc = rdr->types.lookup(0x1001);
    if (proc == nullptr) {
        std::fprintf(stderr, "FAIL: TPI lookup(0x1001) returned nullptr\n");
        ++fails;
    } else {
        check_eq(static_cast<int>(proc->kind),
                 static_cast<int>(ember::pdb::TypeRecord::Kind::Procedure),
                 "proc.kind");
        check_eq(proc->base_type, std::uint32_t{0x74}, "proc.return_type");
        check_eq(proc->arg_list,  std::uint32_t{0x1000}, "proc.arg_list");
        check_eq(proc->param_count, std::uint16_t{1}, "proc.param_count");
    }

    // Render: returning `int`, taking one `char*`.
    const std::string ret_str = rdr->types.render_type(0x74);
    check_eq(ret_str, std::string("int"), "render T_INT4");
    const std::string char_p = rdr->types.render_type(0x470);
    check_eq(char_p, std::string("char*"), "render T_PCHAR");
    // Arglist itself.
    const auto* al = rdr->types.lookup(0x1000);
    if (al == nullptr) {
        std::fprintf(stderr, "FAIL: TPI lookup(0x1000) returned nullptr\n");
        ++fails;
    } else {
        check_eq_sz(al->arg_types.size(), 1u, "arglist count");
        if (al->arg_types.size() == 1) {
            check_eq(al->arg_types[0], std::uint32_t{0x470}, "arglist[0]");
        }
    }
}

int main() {
    test_publics_only();
    test_full_pdb_with_types();

    if (fails == 0) {
        std::fprintf(stderr, "pdb_test: ok\n");
        return 0;
    }
    return 1;
}
