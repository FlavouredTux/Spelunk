#pragma once

#include <string>
#include <string_view>
#include <vector>

#include <ember/common/types.hpp>

namespace ember {

class Binary;

// YARA-like function identification: match known algorithm profiles
// (crypto hashes, encryption primitives, network protocol handlers)
// against functions in a binary by scanning for characteristic magic
// constants, byte patterns, and import call sequences.
//
// This is orthogonal to the TEEF recognizer (which matches whole
// functions against a corpus of known library builds).  Identification
// recognises *algorithm families* — e.g. "this function is SHA-256"
// even if it's a custom implementation, not a stock library copy.

// Category of an identified profile.
enum class IdentifyCategory : u8 {
    Hash,        // SHA-*, MD5, BLAKE*, FNV*, CRC*, MurmurHash*
    Encryption,  // AES, ChaCha20, Salsa20, RC4, DES, XTEA
    Network,     // RakNet, WSA send/recv, UDP/TCP dispatch
    Encoding,    // Base64, Base32, URL-encode, hex-encode
};

[[nodiscard]] constexpr std::string_view
category_name(IdentifyCategory c) noexcept {
    switch (c) {
        case IdentifyCategory::Hash:        return "hash";
        case IdentifyCategory::Encryption:  return "encryption";
        case IdentifyCategory::Network:     return "network";
        case IdentifyCategory::Encoding:    return "encoding";
    }
    return "?";
}

// One identification hit for a function.
struct IdentifyHit {
    addr_t              addr       = 0;
    std::string         name;       // e.g. "sha256", "chacha20", "aes_encrypt"
    IdentifyCategory    category   = IdentifyCategory::Hash;
    float               confidence = 0.0f;  // 0..1
    std::string         signal;    // "constants", "pattern", "imports"
    std::string         via;       // detail: "0x6a09e667,0xbb67ae85" etc.
};

// Run identification against every function in `b` and return all
// hits above the default confidence threshold.
[[nodiscard]] std::vector<IdentifyHit>
identify_functions(const Binary& b);

// Run identification with an explicit confidence threshold (0..1).
[[nodiscard]] std::vector<IdentifyHit>
identify_functions(const Binary& b, float threshold);

// Format identification results as TSV:
//   addr\tname\tcategory\tconfidence\tsignal\tvia
[[nodiscard]] std::string
format_identify_tsv(const std::vector<IdentifyHit>& hits);

}  // namespace ember
