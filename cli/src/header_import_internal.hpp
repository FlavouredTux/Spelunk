#pragma once

// Header/type models and binary renderers shared by the header importer and
// its CLI commands. Private to the header_import*.cpp translation units.

#include <array>
#include <cstddef>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <spelunk/binary/arch.hpp>
#include <spelunk/common/annotations.hpp>
#include <spelunk/common/error.hpp>
#include <spelunk/common/types.hpp>

namespace spelunk {
class Binary;
struct Relocation;
}

namespace spelunk::cli::header_import_model {

struct HeaderField {
    std::string name;
    std::string type;
    std::size_t offset = 0;
    std::size_t size = 0;
};

struct HeaderRecord {
    std::string name;
    std::size_t size = 0;
    bool is_union = false;
    std::vector<HeaderField> fields;
};

struct HeaderDatabase {
    std::map<std::string, FunctionSig, std::less<>> functions;
    std::map<std::string, HeaderRecord, std::less<>> records;
    std::map<std::string, std::string, std::less<>> globals;
    std::map<std::string, std::string, std::less<>> aliases;
    std::map<i64, std::string> enum_values;
    std::map<std::string, std::map<i64, std::string>, std::less<>> enums;
    std::size_t diagnostics = 0;
    std::vector<std::string> diagnostic_text;
};

[[nodiscard]] std::string trim(std::string s);
[[nodiscard]] std::string unqualified(std::string_view s);
[[nodiscard]] std::string base_type_name(std::string s);
[[nodiscard]] const HeaderRecord* record_for(const HeaderDatabase& db,
                                             std::string type);

struct TypeNode {
    enum class Kind { Scalar, Pointer, Array, Record } kind = Kind::Scalar;
    std::string name;
    std::size_t count = 0;
    const HeaderRecord* record = nullptr;
    std::unique_ptr<TypeNode> child;
};

struct RoundtripStats {
    std::size_t objects = 0;
    std::size_t bytes = 0;
    std::size_t pointers = 0;
    std::size_t relocations = 0;
};

[[nodiscard]] std::unique_ptr<TypeNode> parse_type(const HeaderDatabase& db,
                                                   std::string text);
[[nodiscard]] std::size_t type_size(const TypeNode& type,
                                    std::size_t pointer_size);
[[nodiscard]] u64 read_uint(const Binary& binary, addr_t at, std::size_t size);
void write_uint(std::span<std::byte> out, std::size_t offset,
                std::size_t size, u64 value, Endian endian);
[[nodiscard]] const Relocation* relocation_at(const Binary& binary,
                                              addr_t site,
                                              std::size_t size);
[[nodiscard]] std::string render_value(const HeaderDatabase& db,
                                       const Binary& binary,
                                       const TypeNode& type, addr_t at,
                                       unsigned depth,
                                       std::size_t pointer_size);
[[nodiscard]] Result<RoundtripStats>
verify_typed_roundtrip(const HeaderDatabase& db, const Binary& binary,
                       const TypeNode& root, addr_t root_at,
                       std::size_t pointer_size);

inline constexpr std::size_t kEvtOpcodeCount = 120;
extern const std::array<std::string_view, kEvtOpcodeCount> kEvtNames;

[[nodiscard]] std::string evt_arg(const Binary& binary, addr_t site, i32 value,
                                  bool pointer_hint);
[[nodiscard]] std::optional<i32>
evt_scalar_from_rendered(std::string_view rendered);

}  // namespace spelunk::cli::header_import_model
