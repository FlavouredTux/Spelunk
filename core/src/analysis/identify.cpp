#include <ember/analysis/identify.hpp>
#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <format>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <ember/analysis/pipeline.hpp>
#include <ember/binary/binary.hpp>
#include <ember/binary/symbol.hpp>
#include <ember/common/progress.hpp>
#include <ember/disasm/decoder.hpp>
#include <ember/disasm/instruction.hpp>

namespace ember {
namespace {

struct CS { u64 v; u8 mn; };  // constant signal: value + min_hits
struct IS { const char* n; };  // import signal: name substring

// YARA-like byte pattern: sequence of bytes where 0xFF = wildcard.
// Matches against raw function bytes.  Ideal for S-box tables,
// magic sequences, and any fixed byte signature.
struct BytePat {
    const u8* bytes;     // pattern bytes (0xFF = wildcard ?? )
    std::size_t len;     // pattern length
};

// Instruction-sequence pattern: matches a subsequence of decoded
// instructions by mnemonic and operand shape.  The `mnem` field
// matches the instruction mnemonic; `opmask` is a bitmask over
// the operand kinds present (see OpMask bits below).  This lets
// us recognise algorithmic structure — e.g. ChaCha quarter-round
// is rol-16 / add / xor / rol-12 / add / xor / rol-8 / add / xor / rol-7.
struct InsnPat {
    Mnemonic mnem;
    u8       opmask;  // bitmask of required operand kinds
};

// Operand-kind bits for InsnPat::opmask.
enum OpMask : u8 {
    OPM_REG = 1 << 0,   // at least one Register operand
    OPM_MEM = 1 << 1,   // at least one Memory operand
    OPM_IMM = 1 << 2,   // at least one Immediate operand
    OPM_REL = 1 << 3,   // at least one Relative operand
    OPM_ANY = 0xFF,     // don't care about operand shape
};

struct Profile {
    const char* name; IdentifyCategory cat; float mc; // min_coverage
    const CS* cs; std::size_t nc;
    const IS* is; std::size_t ni;
    const BytePat* bp; std::size_t nbp;   // byte patterns
    const InsnPat* ip; std::size_t nip;   // instruction patterns
};

// ---- Constant tables ----
static constexpr CS c_sha256h[]={{0x6a09e667,1},{0xbb67ae85,1},{0x3c6ef372,1},{0xa54ff53a,1},{0x510e527f,1},{0x9b05688c,1},{0x1f83d9ab,1},{0x5be0cd19,1}};
static constexpr CS c_sha256k[]={{0x428a2f98,1},{0x71374491,1},{0xb5c0fbcf,1},{0xe9b5dba5,1},{0x3956c25b,1},{0x59f111f1,1},{0x923f82a4,1},{0xab1c5ed5,1}};
static constexpr CS c_sha1[]={{0x67452301,1},{0xEFCDAB89,1},{0x98BADCFE,1},{0x10325476,1},{0xC3D2E1F0,1}};
static constexpr CS c_sha512[]={{0x6a09e667f3bcc908ull,1},{0xbb67ae8584caa73bull,1},{0x3c6ef372fe94f82bull,1},{0xa54ff53a5f1d36f1ull,1}};
static constexpr CS c_md5[]={{0x67452301,1},{0xefcdab89,1},{0x98badcfe,1},{0x10325476,1}};
static constexpr CS c_blake2b[]={{0x6a09e667f3bcc908ull,1},{0xbb67ae8584caa73bull,1},{0x3c6ef372fe94f82bull,1},{0xa54ff53a5f1d36f1ull,1},{0x510e527fade682d1ull,1},{0x9b05688c2b3e6c1full,1},{0x1f83d9abfb41bd6bull,1},{0x5be0cd19137e2179ull,1}};
static constexpr CS c_blake2s[]={{0x6a09e667,1},{0xbb67ae85,1},{0x3c6ef372,1},{0xa54ff53a,1},{0x510e527f,1},{0x9b05688c,1},{0x1f83d9ab,1},{0x5be0cd19,1}};
static constexpr CS c_blake3[]={{0x6a09e667,1},{0xbb67ae85,1},{0x3c6ef372,1},{0xa54ff53a,1},{0x510e527f,1},{0x9b05688c,1},{0x1f83d9ab,1},{0x5be0cd19,1}};
static constexpr CS c_fnv1a32[]={{0x811c9dc5,1},{0x01000193,1}};
static constexpr CS c_fnv1a64[]={{0xcbf29ce484222325ull,1},{0x00000100000001b3ull,1}};
static constexpr CS c_crc32[]={{0xedb88320,1}};
static constexpr CS c_murmur3[]={{0xcc9e2d51,1},{0x1b873593,1},{0xe6546b64,1}};
static constexpr CS c_chacha20[]={{0x61707865,1},{0x3320646e,1},{0x79622d32,1},{0x6b206574,1}};
static constexpr CS c_salsa20[]={{0x61707865,1},{0x3320646e,1},{0x79622d32,1},{0x6b206574,1}};
static constexpr CS c_aes_rcon[]={{0x01,0},{0x02,0},{0x04,0},{0x08,0},{0x10,0},{0x20,0},{0x40,0},{0x80,0},{0x1b,0},{0x36,0}};
static constexpr CS c_des[]={{0x0001030507090B0Dull,0},{0x0F111315171B1D1Full,0}};
static constexpr CS c_xtea[]={{0x9E3779B9,1}};

// ---- Import signal tables ----
static constexpr IS i_wsa[]={{"WSASend"},{"WSARecv"}};
static constexpr IS i_raknet[]={{"RakPeer"},{"RakNet"}};
static constexpr IS i_sendrecv[]={{"send"},{"recv"}};

// ---- Byte-pattern tables (0xFF = wildcard ??) ----

// AES S-box first 16 bytes — the most reliable AES fingerprint.
static constexpr u8 bp_aes_sbox[]={
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,
    0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76
};
static constexpr BytePat bpat_aes_sbox={bp_aes_sbox, sizeof(bp_aes_sbox)};

// AES Inverse S-box first 16 bytes — appears in AES decryption.
static constexpr u8 bp_aes_inv_sbox[]={
    0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,
    0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB
};
static constexpr BytePat bpat_aes_inv_sbox={bp_aes_inv_sbox, sizeof(bp_aes_inv_sbox)};

// RC4 KSA identity: the initial permutation 0,1,2,...,15 as a byte table.
// A custom RC4 implementation often embeds this as a lookup table.
static constexpr u8 bp_rc4_init[]={
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
};
static constexpr BytePat bpat_rc4_init={bp_rc4_init, sizeof(bp_rc4_init)};

// Base64 encoding table — the classic "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef..."
static constexpr u8 bp_base64[]={
    0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,  // A B C D E F G H
    0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F,0x50,  // I J K L M N O P
    0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,  // Q R S T U V W X
    0x59,0x5A,0x61,0x62,0x63,0x64,0x65,0x66   // Y Z a b c d e f
};
static constexpr BytePat bpat_base64={bp_base64, sizeof(bp_base64)};

// DES initial permutation (IP) table first 16 bytes.
static constexpr u8 bp_des_ip[]={
    0x3A,0x35,0x2C,0x28,0x24,0x1E,0x1A,0x11,
    0x0E,0x0A,0x06,0x03,0x3F,0x3B,0x37,0x33
};
static constexpr BytePat bpat_des_ip={bp_des_ip, sizeof(bp_des_ip)};

// ---- Instruction-sequence pattern tables ----

// ChaCha20 quarter-round signature: rol 16, add, xor, rol 12, add, xor,
// rol 8, add, xor, rol 7.  This sequence is extremely characteristic.
static constexpr InsnPat ipat_chacha_qr[]={
    {Mnemonic::Rol, OPM_IMM},   // rol reg, 16
    {Mnemonic::Add, OPM_REG},   // add reg, reg
    {Mnemonic::Xor, OPM_REG},   // xor reg, reg
    {Mnemonic::Rol, OPM_IMM},   // rol reg, 12
    {Mnemonic::Add, OPM_REG},   // add reg, reg
    {Mnemonic::Xor, OPM_REG},   // xor reg, reg
    {Mnemonic::Rol, OPM_IMM},   // rol reg, 8
    {Mnemonic::Add, OPM_REG},   // add reg, reg
    {Mnemonic::Xor, OPM_REG},   // xor reg, reg
    {Mnemonic::Rol, OPM_IMM},   // rol reg, 7
};

// AES key expansion: the pattern of rotating, substituting via S-box,
// and XOR with round constant appears as: shufps/xor/rol or pshufb/xor.
// A simplified structural signature: xor + shufps/shl + xor repeating.
static constexpr InsnPat ipat_aes_keyexp[]={
    {Mnemonic::Xor,  OPM_REG},  // xor with rcon
    {Mnemonic::Shl,  OPM_IMM},  // rotate/shift subkey
    {Mnemonic::Xor,  OPM_REG},  // xor into key schedule
    {Mnemonic::Xor,  OPM_REG},  // xor next word
    {Mnemonic::Xor,  OPM_REG},  // xor next word
    {Mnemonic::Xor,  OPM_REG},  // xor next word
};

// RC4 swap-and-add pattern: xchg + add + mov in a loop structure.
static constexpr InsnPat ipat_rc4_swap[]={
    {Mnemonic::Xchg, OPM_REG},  // swap S[i] and S[j]
    {Mnemonic::Add,  OPM_REG},  // add indices
    {Mnemonic::Mov,  OPM_REG},  // load S[i]+S[j]
    {Mnemonic::Xor,  OPM_REG},  // xor with plaintext
};

// ---- Profile table ----
static const Profile kProfiles[]={
  // Hash profiles — constant-based
  {"sha256",      IdentifyCategory::Hash,       0.5f, c_sha256h,8,  nullptr,0,     nullptr,0, nullptr,0},
  {"sha256_k",    IdentifyCategory::Hash,       0.5f, c_sha256k,8,  nullptr,0,     nullptr,0, nullptr,0},
  {"sha1",        IdentifyCategory::Hash,       0.6f, c_sha1,5,     nullptr,0,     nullptr,0, nullptr,0},
  {"sha512",      IdentifyCategory::Hash,       0.5f, c_sha512,4,   nullptr,0,     nullptr,0, nullptr,0},
  {"md5",         IdentifyCategory::Hash,       0.6f, c_md5,4,      nullptr,0,     nullptr,0, nullptr,0},
  {"blake2b",     IdentifyCategory::Hash,       0.5f, c_blake2b,8,  nullptr,0,     nullptr,0, nullptr,0},
  {"blake2s",     IdentifyCategory::Hash,       0.5f, c_blake2s,8,  nullptr,0,     nullptr,0, nullptr,0},
  {"blake3",      IdentifyCategory::Hash,       0.5f, c_blake3,8,   nullptr,0,     nullptr,0, nullptr,0},
  {"fnv1a_32",    IdentifyCategory::Hash,       1.0f, c_fnv1a32,2,  nullptr,0,     nullptr,0, nullptr,0},
  {"fnv1a_64",    IdentifyCategory::Hash,       1.0f, c_fnv1a64,2,  nullptr,0,     nullptr,0, nullptr,0},
  {"crc32",       IdentifyCategory::Hash,       1.0f, c_crc32,1,    nullptr,0,     nullptr,0, nullptr,0},
  {"murmurhash3", IdentifyCategory::Hash,       0.7f, c_murmur3,3,  nullptr,0,     nullptr,0, nullptr,0},
  // Encryption profiles — constant-based
  {"chacha20",    IdentifyCategory::Encryption, 0.75f,c_chacha20,4, nullptr,0,     nullptr,0, nullptr,0},
  {"salsa20",     IdentifyCategory::Encryption, 0.75f,c_salsa20,4, nullptr,0,     nullptr,0, nullptr,0},
  {"aes_rcon",    IdentifyCategory::Encryption, 0.4f, c_aes_rcon,10,nullptr,0,     nullptr,0, nullptr,0},
  {"des",         IdentifyCategory::Encryption, 0.5f, c_des,2,      nullptr,0,     nullptr,0, nullptr,0},
  {"xtea",        IdentifyCategory::Encryption, 1.0f, c_xtea,1,     nullptr,0,     nullptr,0, nullptr,0},
  // Encryption profiles — byte-pattern-based (YARA-like)
  {"aes_sbox",    IdentifyCategory::Encryption, 1.0f, nullptr,0,    nullptr,0,     &bpat_aes_sbox,1,    nullptr,0},
  {"aes_inv_sbox",IdentifyCategory::Encryption, 1.0f, nullptr,0,    nullptr,0,     &bpat_aes_inv_sbox,1,nullptr,0},
  {"rc4_table",   IdentifyCategory::Encryption, 0.7f, nullptr,0,    nullptr,0,     &bpat_rc4_init,1,    nullptr,0},
  {"des_ip_table",IdentifyCategory::Encryption, 1.0f, nullptr,0,    nullptr,0,     &bpat_des_ip,1,      nullptr,0},
  // Encoding profiles — byte-pattern-based
  {"base64",      IdentifyCategory::Encoding,   1.0f, nullptr,0,    nullptr,0,     &bpat_base64,1,      nullptr,0},
  // Encryption profiles — instruction-sequence-based
  {"chacha_qr",   IdentifyCategory::Encryption, 0.8f, nullptr,0,    nullptr,0,     nullptr,0, ipat_chacha_qr,10},
  {"aes_keyexp",  IdentifyCategory::Encryption, 0.6f, nullptr,0,    nullptr,0,     nullptr,0, ipat_aes_keyexp,6},
  {"rc4_swap",    IdentifyCategory::Encryption, 0.6f, nullptr,0,    nullptr,0,     nullptr,0, ipat_rc4_swap,4},
  // Network profiles — import-based
  {"wsa_sendrecv",IdentifyCategory::Network,    0.5f, nullptr,0,    i_wsa,2,       nullptr,0, nullptr,0},
  {"raknet",      IdentifyCategory::Network,    0.5f, nullptr,0,    i_raknet,2,    nullptr,0, nullptr,0},
  {"send_recv",   IdentifyCategory::Network,    0.5f, nullptr,0,    i_sendrecv,2,  nullptr,0, nullptr,0},
};
constexpr std::size_t kNP = std::size(kProfiles);

// Collect non-address immediate values from decoded instructions.
std::unordered_map<u64,u32> collect_imms(const Binary& b, addr_t start, u64 sz) {
    std::unordered_map<u64,u32> imms;
    auto dec_r = make_decoder(b);
    if (!dec_r) return imms;
    const Decoder& dec = **dec_r;
    addr_t pc = start;
    const addr_t end = sz ? start + sz : start + 0x10000;
    while (pc < end) {
        auto bytes = b.bytes_at(pc);
        if (bytes.empty()) break;
        auto r = dec.decode(bytes, pc);
        if (!r) break;
        const auto& insn = *r;
        for (u8 i = 0; i < insn.num_operands; ++i) {
            if (insn.operands[i].kind == Operand::Kind::Immediate) {
                u64 v = static_cast<u64>(insn.operands[i].imm.value);
                // Sign-extended 32-bit immediates look like 0xFFFFFFFF????????
                // on x86-64 — recover the original 32-bit pattern.
                if (v >= 0xFFFFFFFF00000000ull) v &= 0xFFFFFFFFull;
                if (v >= 0x100)
                    imms[v]++;
            }
        }
        pc += insn.length;
        if (insn.length == 0) break;
        if (insn.mnemonic == Mnemonic::Ret && sz == 0 && pc > start + 8) break;
    }
    return imms;
}

// Collect import names called via PLT from this function.
std::unordered_set<std::string> collect_imports(const Binary& b, addr_t start, u64 sz) {
    std::unordered_set<std::string> out;
    auto dec_r = make_decoder(b);
    if (!dec_r) return out;
    const Decoder& dec = **dec_r;
    addr_t pc = start;
    const addr_t end = sz ? start + sz : start + 0x10000;
    while (pc < end) {
        auto bytes = b.bytes_at(pc);
        if (bytes.empty()) break;
        auto r = dec.decode(bytes, pc);
        if (!r) break;
        const auto& insn = *r;
        if (is_call(insn.mnemonic) && insn.num_operands > 0) {
            const auto& op = insn.operands[0];
            if (op.kind == Operand::Kind::Relative)
                if (auto* sym = b.import_at_plt(op.rel.target))
                    out.insert(sym->name);
        }
        pc += insn.length;
        if (insn.length == 0) break;
        if (insn.mnemonic == Mnemonic::Ret && sz == 0 && pc > start + 8) break;
    }
    return out;
}

float score_profile(const Profile& p,
    const std::unordered_map<u64,u32>& imms,
    const std::unordered_set<std::string>& imp)
{
    float cs = 0.0f;
    if (p.nc > 0 && p.cs) {
        std::size_t matched = 0, required = 0;
        for (std::size_t i = 0; i < p.nc; ++i) {
            auto it = imms.find(p.cs[i].v);
            if (it != imms.end() && it->second >= p.cs[i].mn) ++matched;
            if (p.cs[i].mn > 0) ++required;
        }
        if (required > 0 && matched < required) return 0.0f;
        cs = static_cast<float>(matched) / static_cast<float>(p.nc);
        if (cs < p.mc) return 0.0f;
    }
    float is = 0.0f;
    if (p.ni > 0 && p.is) {
        std::size_t matched = 0;
        for (std::size_t i = 0; i < p.ni; ++i)
            for (const auto& n : imp)
                if (n.find(p.is[i].n) != std::string::npos) { ++matched; break; }
        is = static_cast<float>(matched) / static_cast<float>(p.ni);
        if (is < p.mc) return 0.0f;
    }
    if (p.nc > 0 && p.ni > 0) return cs * 0.7f + is * 0.3f;
    return p.nc > 0 ? cs : is;
}

std::string via_consts(const Profile& p, const std::unordered_map<u64,u32>& imms) {
    std::string s;
    for (std::size_t i = 0; i < p.nc; ++i)
        if (imms.count(p.cs[i].v)) { if (!s.empty()) s+=','; s+=std::format("{:x}",p.cs[i].v); }
    return s;
}

std::string via_imp(const Profile& p, const std::unordered_set<std::string>& imp) {
    std::string s;
    for (std::size_t i = 0; i < p.ni; ++i)
        for (const auto& n : imp)
            if (n.find(p.is[i].n) != std::string::npos) { if (!s.empty()) s+=','; s+=n; break; }
    return s;
}

// ---- Byte-pattern matching (YARA-like) ----

// Match a single BytePat against raw bytes in [start, start+sz).
// Returns the offset of the first match, or -1 if not found.
i64 match_bytepat(const BytePat& pat, const Binary& b, addr_t start, u64 sz) {
    if (pat.len == 0 || pat.bytes == nullptr) return -1;
    const addr_t end = sz ? start + sz : start + 0x10000;
    if (end <= start || static_cast<u64>(end - start) < pat.len) return -1;
    const addr_t limit = end - pat.len + 1;
    for (addr_t pos = start; pos < limit; ++pos) {
        auto chunk = b.bytes_at(pos);
        if (chunk.size() < pat.len) {
            // bytes_at may return a partial view near a section boundary;
            // fall back to byte-by-byte for the remainder.
            bool ok = true;
            for (std::size_t k = 0; k < pat.len; ++k) {
                auto one = b.bytes_at(pos + k);
                if (one.empty() || std::to_integer<u8>(one[0]) != pat.bytes[k]) {
                    if (pat.bytes[k] != 0xFF) { ok = false; break; }
                }
            }
            if (ok) return static_cast<i64>(pos - start);
            continue;
        }
        bool ok = true;
        for (std::size_t k = 0; k < pat.len; ++k) {
            if (pat.bytes[k] != 0xFF && std::to_integer<u8>(chunk[k]) != pat.bytes[k]) { ok = false; break; }
        }
        if (ok) return static_cast<i64>(pos - start);
    }
    return -1;
}

// Score byte-pattern profiles: returns fraction of patterns that matched.
float score_bytepat(const Profile& p, const Binary& b, addr_t start, u64 sz) {
    if (p.nbp == 0 || p.bp == nullptr) return 0.0f;
    std::size_t matched = 0;
    for (std::size_t i = 0; i < p.nbp; ++i)
        if (match_bytepat(p.bp[i], b, start, sz) >= 0) ++matched;
    return static_cast<float>(matched) / static_cast<float>(p.nbp);
}

std::string via_bytepat(const Profile& p, const Binary& b, addr_t start, u64 sz) {
    std::string s;
    for (std::size_t i = 0; i < p.nbp; ++i) {
        auto off = match_bytepat(p.bp[i], b, start, sz);
        if (off >= 0) {
            if (!s.empty()) s += ',';
            s += std::format("pattern[{}]@+{}", i, off);
        }
    }
    return s;
}

// ---- Instruction-sequence matching ----

// Compute the operand-kind bitmask for a single instruction.
u8 opmask_of(const Instruction& insn) {
    u8 m = 0;
    for (u8 i = 0; i < insn.num_operands; ++i) {
        switch (insn.operands[i].kind) {
            case Operand::Kind::Register:  m |= OPM_REG; break;
            case Operand::Kind::Memory:    m |= OPM_MEM; break;
            case Operand::Kind::Immediate: m |= OPM_IMM; break;
            case Operand::Kind::Relative:  m |= OPM_REL; break;
            default: break;
        }
    }
    return m;
}

// Decode all instructions in [start, start+sz) into a flat vector.
struct DecodedInsn { Mnemonic mnem; u8 opmask; };
std::vector<DecodedInsn> decode_insns(const Binary& b, addr_t start, u64 sz) {
    std::vector<DecodedInsn> out;
    auto dec_r = make_decoder(b);
    if (!dec_r) return out;
    const Decoder& dec = **dec_r;
    addr_t pc = start;
    const addr_t end = sz ? start + sz : start + 0x10000;
    while (pc < end) {
        auto bytes = b.bytes_at(pc);
        if (bytes.empty()) break;
        auto r = dec.decode(bytes, pc);
        if (!r) break;
        const auto& insn = *r;
        out.push_back({insn.mnemonic, opmask_of(insn)});
        pc += insn.length;
        if (insn.length == 0) break;
        if (insn.mnemonic == Mnemonic::Ret && sz == 0 && pc > start + 8) break;
    }
    return out;
}

// Match an instruction-sequence pattern as a subsequence.
// Returns true if the pattern is found (possibly with gaps between elements).
bool insn_subseq_match(const InsnPat* pat, std::size_t npat,
                       const DecodedInsn* insns, std::size_t ninsns) {
    if (npat == 0 || ninsns == 0) return false;
    std::size_t pi = 0;  // pattern index
    for (std::size_t ii = 0; ii < ninsns && pi < npat; ++ii) {
        const auto& p = pat[pi];
        const auto& d = insns[ii];
        if (d.mnem == p.mnem && (d.opmask & p.opmask) == p.opmask)
            ++pi;
    }
    return pi == npat;
}

// Score instruction-sequence profiles: returns 1.0 if the subsequence
// is found, 0.0 otherwise.  (Insn patterns are all-or-nothing since
// the subsequence must be complete to indicate the algorithm.)
float score_insnpat(const Profile& p, const std::vector<DecodedInsn>& insns) {
    if (p.nip == 0 || p.ip == nullptr) return 0.0f;
    return insn_subseq_match(p.ip, p.nip, insns.data(), insns.size()) ? 1.0f : 0.0f;
}

std::string via_insnpat(const Profile& p) {
    std::string s;
    for (std::size_t i = 0; i < p.nip; ++i) {
        if (!s.empty()) s += ',';
        char buf[32];
        auto name = mnemonic_name(p.ip[i].mnem);
        std::snprintf(buf, sizeof(buf), "%.*s", static_cast<int>(name.size()), name.data());
        s += buf;
    }
    return s;
}

} // anon namespace

std::vector<IdentifyHit> identify_functions(const Binary& b) {
    return identify_functions(b, 0.4f);
}

std::vector<IdentifyHit> identify_functions(const Binary& b, float threshold) {
    std::vector<IdentifyHit> hits;
    auto fns = enumerate_functions(b);
    if (fns.empty()) return hits;

    const bool show = progress_enabled();
    if (show) { std::fprintf(stderr, "identify: scanning %zu functions\n", fns.size()); std::fflush(stderr); }

    std::size_t done = 0;
    for (const auto& fn : fns) {
        // Collect constant and import signals (cheap).
        auto imms = collect_imms(b, fn.addr, fn.size);
        auto imp  = collect_imports(b, fn.addr, fn.size);

        // Decode instructions once for insn-pattern matching.
        // Only decode if any profile uses insn-patterns.
        std::vector<DecodedInsn> insns;
        bool need_insns = false;
        for (std::size_t pi = 0; pi < kNP; ++pi)
            if (kProfiles[pi].nip > 0) { need_insns = true; break; }
        if (need_insns) insns = decode_insns(b, fn.addr, fn.size);

        for (std::size_t pi = 0; pi < kNP; ++pi) {
            const auto& p = kProfiles[pi];

            // Score each signal type independently.
            float cs_score = score_profile(p, imms, imp);
            float bp_score = score_bytepat(p, b, fn.addr, fn.size);
            float ip_score = score_insnpat(p, insns);

            // Take the best signal as the overall score.
            float score = cs_score;
            if (bp_score > score) score = bp_score;
            if (ip_score > score) score = ip_score;

            // For profiles with multiple signal types, boost confidence
            // when more than one fires.
            int signals = 0;
            if (cs_score >= threshold) ++signals;
            if (bp_score >= p.mc) ++signals;
            if (ip_score >= p.mc) ++signals;
            if (signals >= 2) score = std::min(1.0f, score + 0.15f);

            if (score < threshold) continue;

            IdentifyHit h;
            h.addr = fn.addr;
            h.name = p.name;
            h.category = p.cat;
            h.confidence = score;

            // Report which signal(s) fired.
            if (cs_score >= threshold && p.nc > 0) {
                h.signal = "constants";
                h.via = via_consts(p, imms);
            } else if (cs_score >= threshold && p.ni > 0) {
                h.signal = "imports";
                h.via = via_imp(p, imp);
            }
            if (bp_score >= p.mc) {
                if (!h.signal.empty()) { h.signal += "+pattern"; }
                else { h.signal = "pattern"; }
                auto bv = via_bytepat(p, b, fn.addr, fn.size);
                if (!h.via.empty() && !bv.empty()) h.via += ';';
                h.via += bv;
            }
            if (ip_score >= p.mc) {
                if (!h.signal.empty()) { h.signal += "+insn_seq"; }
                else { h.signal = "insn_seq"; }
                auto iv = via_insnpat(p);
                if (!h.via.empty() && !iv.empty()) h.via += ';';
                h.via += iv;
            }
            if (!h.signal.empty()) hits.push_back(std::move(h));
        }
        ++done;
        if (show && done % 200 == 0) {
            std::fprintf(stderr, "  identify: %zu / %zu\n", done, fns.size());
            std::fflush(stderr);
        }
    }
    // Sort by address then confidence descending
    std::sort(hits.begin(), hits.end(), [](const IdentifyHit& lhs, const IdentifyHit& rhs) {
        if (lhs.addr != rhs.addr) return lhs.addr < rhs.addr;
        return lhs.confidence > rhs.confidence;
    });
    if (show) { std::fprintf(stderr, "identify: %zu hit(s)\n", hits.size()); std::fflush(stderr); }
    return hits;
}

std::string format_identify_tsv(const std::vector<IdentifyHit>& hits) {
    std::string out;
    for (const auto& h : hits) {
        out += std::format("{:x}\t{}\t{}\t{:.2f}\t{}\t{}\n",
            h.addr, h.name, category_name(h.category),
            h.confidence, h.signal, h.via);
    }
    return out;
}

} // namespace ember
