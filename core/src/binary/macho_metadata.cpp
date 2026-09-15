#include <spelunk/binary/macho.hpp>

#include <algorithm>
#include <cstddef>
#include <format>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include <spelunk/binary/section.hpp>
#include <spelunk/binary/symbol.hpp>
#include <spelunk/common/bytes.hpp>
#include <spelunk/common/types.hpp>

namespace spelunk {

namespace {

constexpr u32 OBJC_RELATIVE_METHOD_LIST_FLAG = 0x80000000u;
constexpr u32 OBJC_SELECTOR_OFFSETS_FLAG     = 0x40000000u;

template <class T>
[[nodiscard]] T read_at(std::span<const LoadSegment> segments,
                        addr_t vaddr) noexcept {
    for (const auto& segment : segments) {
        if (vaddr < segment.vaddr) continue;
        const u64 offset = vaddr - segment.vaddr;
        if (offset > segment.filesz || sizeof(T) > segment.filesz - offset) {
            continue;
        }
        if (segment.data.empty()) continue;
        return read_le_at<T>(segment.data.data() + static_cast<std::size_t>(offset));
    }
    return T{};
}

[[nodiscard]] std::string
read_cstring(std::span<const std::byte> bytes) {
    std::string out;
    out.reserve(64);
    const std::size_t max_length = std::min<std::size_t>(bytes.size(), 512u);
    for (std::size_t i = 0; i < max_length; ++i) {
        const u8 c = static_cast<u8>(bytes[i]);
        if (c == 0) return out;
        if (c < 0x20 || c > 0x7e) return {};
        out.push_back(static_cast<char>(c));
    }
    return {};
}

// Metadata names are expected to be printable, NUL-terminated ASCII. Keep the
// read bounded so malformed pointers cannot turn a metadata scan into a sweep.
[[nodiscard]] std::string
read_cstring_at(std::span<const LoadSegment> segments, addr_t vaddr) {
    for (const auto& segment : segments) {
        if (vaddr < segment.vaddr) continue;
        const u64 offset = vaddr - segment.vaddr;
        if (offset >= segment.filesz || segment.data.empty()) continue;
        return read_cstring(
            segment.data.subspan(static_cast<std::size_t>(offset)));
    }
    return {};
}

[[nodiscard]] const Section*
find_section_suffix(std::span<const Section> sections,
                    std::string_view suffix) noexcept {
    for (const auto& section : sections) {
        const std::string_view name = section.name;
        if (name == suffix || name.ends_with(suffix)) return &section;
    }
    return nullptr;
}

void append_swift_symbol_piece(std::string& out, std::string_view name) {
    for (const char c : name) {
        const bool is_identifier_character =
            (c >= 'A' && c <= 'Z') ||
            (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '_';
        out.push_back(is_identifier_character ? c : '_');
    }
}

[[nodiscard]] std::string swift_symbol_name(std::string_view name) {
    std::string out = "swift_type_";
    append_swift_symbol_piece(out, name);
    return out;
}

[[nodiscard]] std::string swift_accessor_symbol_name(std::string_view name) {
    std::string out = swift_symbol_name(name);
    out += "_accessor";
    return out;
}

[[nodiscard]] std::string swift_field_symbol_name(std::string_view type_name,
                                                  std::string_view field_name) {
    std::string out = "swift_field_";
    append_swift_symbol_piece(out, type_name);
    out.push_back('_');
    append_swift_symbol_piece(out, field_name);
    return out;
}

}  // namespace

// Recover Objective-C method names from the class lists. This handles both
// absolute method entries and the relative form used by newer runtimes.
void MachOBinary::scan_objc_methods() {
    const Section* classlist = find_section_suffix(sections_, "__objc_classlist");
    if (!classlist || classlist->size < 8) return;
    // A standalone Mach-O has no shared-cache header carrying the global base.
    // Accept selector-buffer offsets only against its exact methname section.
    const Section* selector_strings =
        find_section_suffix(sections_, "__objc_methname");

    auto scan_class_data = [&](addr_t ro_ptr, std::string_view class_name,
                               bool is_metaclass) {
        if (ro_ptr == 0) return;

        const addr_t name_ptr = read_at<u64>(segments_, ro_ptr + 24);
        const addr_t methods_ptr = read_at<u64>(segments_, ro_ptr + 32);
        std::string resolved_name(class_name);
        if (resolved_name.empty() && name_ptr != 0) {
            resolved_name = read_cstring_at(segments_, name_ptr);
        }
        if (resolved_name.empty() || methods_ptr == 0) return;

        const u32 entry_flags = read_at<u32>(segments_, methods_ptr);
        const u32 count = read_at<u32>(segments_, methods_ptr + 4);
        const bool relative =
            (entry_flags & OBJC_RELATIVE_METHOD_LIST_FLAG) != 0;
        const bool selectors_use_buffer_offsets =
            (entry_flags & OBJC_SELECTOR_OFFSETS_FLAG) != 0;
        const u32 entry_size = relative ? (entry_flags & 0x3fffffffu)
                                        : (entry_flags & 0xfffcu);
        if ((!relative && entry_size != 24) ||
            (relative && entry_size < 12) || count > 100000) {
            return;
        }

        const char method_prefix = is_metaclass ? '+' : '-';
        for (u32 i = 0; i < count; ++i) {
            const addr_t entry = methods_ptr + 8 +
                static_cast<addr_t>(i) * entry_size;
            addr_t selector_ptr = 0;
            std::string selector;
            addr_t implementation = 0;
            if (relative) {
                const u32 selector_value = read_at<u32>(segments_, entry);
                const i32 implementation_delta = read_at<i32>(segments_, entry + 8);
                if (selectors_use_buffer_offsets) {
                    if (selector_strings != nullptr &&
                        selector_value < selector_strings->data.size()) {
                        selector = read_cstring(selector_strings->data.subspan(
                            static_cast<std::size_t>(selector_value)));
                    }
                } else {
                    const addr_t selector_reference = static_cast<addr_t>(
                        static_cast<i64>(entry) +
                        static_cast<i64>(static_cast<i32>(selector_value)));
                    selector_ptr = read_at<u64>(segments_, selector_reference);
                }
                implementation = static_cast<addr_t>(
                    static_cast<i64>(entry + 8) +
                    static_cast<i64>(implementation_delta));
            } else {
                selector_ptr = read_at<u64>(segments_, entry);
                implementation = read_at<u64>(segments_, entry + 16);
            }
            if (implementation == 0) continue;

            if (selector.empty() && selector_ptr != 0) {
                selector = read_cstring_at(segments_, selector_ptr);
            }
            if (selector.empty()) continue;

            Symbol symbol;
            symbol.name = std::format("{}[{} {}]", method_prefix,
                                      resolved_name, selector);
            symbol.addr = implementation;
            symbol.kind = SymbolKind::Function;
            symbols_.push_back(std::move(symbol));
        }
    };

    const std::size_t class_count =
        static_cast<std::size_t>(classlist->size / 8);
    for (std::size_t i = 0; i < class_count; ++i) {
        const addr_t slot = classlist->vaddr + static_cast<addr_t>(i) * 8u;
        const addr_t class_ptr = read_at<u64>(segments_, slot);
        if (class_ptr == 0) continue;

        const addr_t metaclass_ptr = read_at<u64>(segments_, class_ptr);
        const addr_t class_data = read_at<u64>(segments_, class_ptr + 32) &
                                  ~addr_t{0x7};
        const addr_t name_ptr = read_at<u64>(segments_, class_data + 24);
        const std::string class_name = name_ptr != 0
            ? read_cstring_at(segments_, name_ptr)
            : std::string{};

        scan_class_data(class_data, class_name, false);
        if (metaclass_ptr != 0) {
            const addr_t metaclass_data =
                read_at<u64>(segments_, metaclass_ptr + 32) & ~addr_t{0x7};
            scan_class_data(metaclass_data, class_name, true);
        }
    }
}

// Name Swift nominal type descriptors, accessors, and field-name records.
// This is deliberately bounded metadata recovery, not a Swift demangler.
void MachOBinary::scan_swift_types() {
    const Section* swift_types = find_section_suffix(sections_, "__swift5_types");
    if (!swift_types || swift_types->size < 4) return;

    const std::size_t descriptor_count = swift_types->size / 4;
    for (std::size_t i = 0; i < descriptor_count; ++i) {
        const addr_t entry = swift_types->vaddr + static_cast<addr_t>(i) * 4u;
        const i32 descriptor_delta = read_at<i32>(segments_, entry);
        const addr_t descriptor = static_cast<addr_t>(
            static_cast<i64>(entry) + static_cast<i64>(descriptor_delta));
        if (descriptor == 0) continue;

        const u32 kind = read_at<u32>(segments_, descriptor) & 0x1fu;
        if (kind != 16u && kind != 17u && kind != 18u) continue;

        const i32 name_delta = read_at<i32>(segments_, descriptor + 8);
        const addr_t name_address = static_cast<addr_t>(
            static_cast<i64>(descriptor + 8) + static_cast<i64>(name_delta));
        std::string type_name = read_cstring_at(segments_, name_address);
        if (type_name.empty()) continue;

        Symbol type;
        type.name = swift_symbol_name(type_name);
        type.addr = descriptor;
        type.kind = SymbolKind::Object;
        symbols_.push_back(std::move(type));

        const i32 accessor_delta = read_at<i32>(segments_, descriptor + 12);
        if (accessor_delta != 0) {
            const addr_t accessor = static_cast<addr_t>(
                static_cast<i64>(descriptor + 12) +
                static_cast<i64>(accessor_delta));
            const bool already_named = std::ranges::any_of(
                symbols_, [&](const Symbol& existing) {
                    return !existing.is_import &&
                           existing.kind == SymbolKind::Function &&
                           existing.addr == accessor;
                });
            if (!bytes_at(accessor).empty() && !already_named) {
                Symbol symbol;
                symbol.name = swift_accessor_symbol_name(type_name);
                symbol.addr = accessor;
                symbol.kind = SymbolKind::Function;
                symbols_.push_back(std::move(symbol));
            }
        }

        const i32 fields_delta = read_at<i32>(segments_, descriptor + 16);
        if (fields_delta == 0) continue;
        const addr_t fields = static_cast<addr_t>(
            static_cast<i64>(descriptor + 16) + static_cast<i64>(fields_delta));
        const u16 record_size = read_at<u16>(segments_, fields + 10);
        const u32 field_count = read_at<u32>(segments_, fields + 12);
        if (record_size < 12 || field_count > 10000) continue;

        for (u32 field_index = 0; field_index < field_count; ++field_index) {
            const addr_t record = fields + 16 +
                static_cast<addr_t>(field_index) * record_size;
            const i32 field_name_delta = read_at<i32>(segments_, record + 8);
            if (field_name_delta == 0) continue;
            const addr_t field_name_address = static_cast<addr_t>(
                static_cast<i64>(record + 8) +
                static_cast<i64>(field_name_delta));
            std::string field_name =
                read_cstring_at(segments_, field_name_address);
            if (field_name.empty()) continue;

            Symbol field;
            field.name = swift_field_symbol_name(type_name, field_name);
            field.addr = field_name_address;
            field.kind = SymbolKind::Object;
            symbols_.push_back(std::move(field));
        }
    }
}

}  // namespace spelunk
