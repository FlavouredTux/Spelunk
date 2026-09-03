#include <ember/binary/pdb.hpp>

#include <cstddef>
#include <expected>
#include <format>
#include <span>
#include <string>
#include <vector>

#include <ember/common/bytes.hpp>
#include <ember/common/error.hpp>
#include <ember/common/types.hpp>

#include "pdb_internal.hpp"

namespace ember::pdb {

namespace {

using detail::for_each_record;
using detail::read_cstr_advance;

// ---------------------------------------------------------------------------
// CodeView leaf (type record) kinds.
// ---------------------------------------------------------------------------
constexpr u16 kLfModifier = 0x1001;
constexpr u16 kLfPointer  = 0x1002;
constexpr u16 kLfProc     = 0x1008;
constexpr u16 kLfMFunc    = 0x1009;
constexpr u16 kLfArgList  = 0x1201;
constexpr u16 kLfFieldList = 0x1203;
constexpr u16 kLfBitfield = 0x1205;
constexpr u16 kLfArray    = 0x1503;
constexpr u16 kLfClass    = 0x1504;
constexpr u16 kLfStructure = 0x1505;
constexpr u16 kLfUnion    = 0x1506;
constexpr u16 kLfEnum     = 0x1507;
constexpr u16 kLfAlias    = 0x150A;

// ---------------------------------------------------------------------------
// Numeric-leaf prefix codes (variant-length lengths and sizes encoded
// inline within type records).
// ---------------------------------------------------------------------------
constexpr u16 kLfChar      = 0x8000;   // i8
constexpr u16 kLfShort     = 0x8001;   // i16
constexpr u16 kLfUShort    = 0x8002;   // u16
constexpr u16 kLfLong      = 0x8003;   // i32
constexpr u16 kLfULong     = 0x8004;   // u32
constexpr u16 kLfReal32    = 0x8005;
constexpr u16 kLfReal64    = 0x8006;
constexpr u16 kLfQuadword  = 0x8009;   // i64
constexpr u16 kLfUQuadword = 0x800A;   // u64

// Parse a CodeView numeric leaf starting at `body[pos]`. The first
// u16 is either an inline value (< 0x8000) or a leaf-code that names
// the actual type. On success, `value_out` carries the unsigned
// 64-bit promoted value and `pos` advances past the leaf.
//
// Returns false on truncated / unknown leaves; the caller treats
// "unknown" as zero (reasonable default for an unknown-size struct).
[[nodiscard]] bool read_numeric_leaf(std::span<const std::byte> body,
                                     std::size_t& pos, u64& value_out) noexcept {
    if (pos + 2 > body.size()) return false;
    const u16 head = read_le_at<u16>(body.data() + pos);
    pos += 2;
    if (head < 0x8000) { value_out = head; return true; }
    switch (head) {
        case kLfChar: {
            if (pos + 1 > body.size()) return false;
            value_out = static_cast<u64>(static_cast<i8>(body[pos++]));
            return true;
        }
        case kLfShort: {
            if (pos + 2 > body.size()) return false;
            const i16 v = static_cast<i16>(read_le_at<u16>(body.data() + pos));
            value_out = static_cast<u64>(static_cast<i64>(v));
            pos += 2; return true;
        }
        case kLfUShort: {
            if (pos + 2 > body.size()) return false;
            value_out = read_le_at<u16>(body.data() + pos); pos += 2; return true;
        }
        case kLfLong: {
            if (pos + 4 > body.size()) return false;
            const i32 v = static_cast<i32>(read_le_at<u32>(body.data() + pos));
            value_out = static_cast<u64>(static_cast<i64>(v));
            pos += 4; return true;
        }
        case kLfULong: {
            if (pos + 4 > body.size()) return false;
            value_out = read_le_at<u32>(body.data() + pos); pos += 4; return true;
        }
        case kLfQuadword: {
            if (pos + 8 > body.size()) return false;
            value_out = read_le_at<u64>(body.data() + pos); pos += 8; return true;
        }
        case kLfUQuadword: {
            if (pos + 8 > body.size()) return false;
            value_out = read_le_at<u64>(body.data() + pos); pos += 8; return true;
        }
        case kLfReal32:
        case kLfReal64: {
            // Floating-point numeric leaves are valid encodings (used
            // for template arguments, enum-of-floats values) but every
            // call site downstream consumes the result as an integer
            // (array sizes, struct offsets, bitfield widths). Rather
            // than silently feeding the raw bit pattern as if it were
            // an int, reject - callers handle "not a usable integer
            // literal" already and skip the record cleanly.
            return false;
        }
        default:
            return false;
    }
}

// ---------------------------------------------------------------------------
// TPI stream parser. The fixed 56-byte header tells us:
//   TypeIndexBegin / TypeIndexEnd - the [begin, end) range our records
//   cover. Indices below ti_begin_ refer to primitive types and don't
//   live in this stream.
//   TypeRecordBytes - bytes of records following the header.
// ---------------------------------------------------------------------------

[[nodiscard]] TypeRecord parse_pointer(std::span<const std::byte> body) {
    TypeRecord t;
    t.kind = TypeRecord::Kind::Pointer;
    if (body.size() < 8) return t;
    t.base_type   = read_le_at<u32>(body.data() + 0);
    const u32 a   = read_le_at<u32>(body.data() + 4);
    // PtrAttribs bit fields:
    //   bits 0..4  pointer kind (4=near32, 0xc=64bit)
    //   bits 5..7  pointer mode (0=ptr, 1=lvref, 2=ptr-to-data-member,
    //                            3=ptr-to-method, 4=rvref)
    //   bit  9     is_volatile
    //   bit  10    is_const
    //   bit  11    is_unaligned
    //   bits 13..18 size in bytes (6 bits)
    const u8 mode = static_cast<u8>((a >> 5) & 0x7);
    t.is_volatile = (a & (1u << 9))  != 0;
    t.is_const    = (a & (1u << 10)) != 0;
    t.is_unaligned= (a & (1u << 11)) != 0;
    const u8 size = static_cast<u8>((a >> 13) & 0x3F);
    if (size > 0) t.ptr_size = size;
    else t.ptr_size = 8;     // default to 64-bit on x64; correct for our scope
    t.is_reference  = (mode == 1 || mode == 4);
    t.is_rvalue_ref = (mode == 4);
    return t;
}

[[nodiscard]] TypeRecord parse_modifier(std::span<const std::byte> body) {
    TypeRecord t;
    t.kind = TypeRecord::Kind::Modifier;
    if (body.size() < 6) return t;
    t.base_type   = read_le_at<u32>(body.data() + 0);
    const u16 m   = read_le_at<u16>(body.data() + 4);
    t.is_const     = (m & 1u) != 0;
    t.is_volatile  = (m & 2u) != 0;
    t.is_unaligned = (m & 4u) != 0;
    return t;
}

[[nodiscard]] TypeRecord parse_proc(std::span<const std::byte> body) {
    TypeRecord t;
    t.kind = TypeRecord::Kind::Procedure;
    // Body layout (after the u16 length + u16 kind prefix):
    //   u32 ReturnType, u8 CallConv, u8 FuncAttrs, u16 NumParams, u32 ArgList
    // = 12 bytes minimum (16 once 4-byte aligned padding is added).
    if (body.size() < 12) return t;
    t.base_type   = read_le_at<u32>(body.data() + 0);
    t.call_conv   = static_cast<u8>(body[4]);
    // body[5] = func attribs
    t.param_count = read_le_at<u16>(body.data() + 6);
    t.arg_list    = read_le_at<u32>(body.data() + 8);
    return t;
}

[[nodiscard]] TypeRecord parse_mfunc(std::span<const std::byte> body) {
    TypeRecord t;
    t.kind = TypeRecord::Kind::MFunction;
    // u32 ReturnType, u32 ClassType, u32 ThisType, u8 CC, u8 Attrs,
    // u16 NumParams, u32 ArgList, i32 ThisAdjust = 24 bytes minimum.
    if (body.size() < 24) return t;
    t.base_type   = read_le_at<u32>(body.data() + 0);
    t.class_type  = read_le_at<u32>(body.data() + 4);
    t.this_type   = read_le_at<u32>(body.data() + 8);
    t.call_conv   = static_cast<u8>(body[12]);
    t.param_count = read_le_at<u16>(body.data() + 14);
    t.arg_list    = read_le_at<u32>(body.data() + 16);
    return t;
}

[[nodiscard]] TypeRecord parse_arg_list(std::span<const std::byte> body) {
    TypeRecord t;
    t.kind = TypeRecord::Kind::ArgList;
    if (body.size() < 4) return t;
    const u32 n = read_le_at<u32>(body.data() + 0);
    if (n > (body.size() - 4) / 4) return t;
    t.arg_types.reserve(n);
    for (u32 i = 0; i < n; ++i) {
        t.arg_types.push_back(read_le_at<u32>(body.data() + 4 + i * 4));
    }
    return t;
}

[[nodiscard]] TypeRecord parse_array(std::span<const std::byte> body) {
    TypeRecord t;
    t.kind = TypeRecord::Kind::Array;
    if (body.size() < 8) return t;
    t.base_type  = read_le_at<u32>(body.data() + 0);   // element type
    t.index_type = read_le_at<u32>(body.data() + 4);
    std::size_t pos = 8;
    u64 sz = 0;
    if (read_numeric_leaf(body, pos, sz)) t.array_size_bytes = sz;
    return t;
}

[[nodiscard]] TypeRecord parse_aggregate(u16 kind, std::span<const std::byte> body) {
    TypeRecord t;
    if (kind == kLfStructure || kind == kLfClass) {
        t.kind = TypeRecord::Kind::Structure;
    } else if (kind == kLfUnion) {
        t.kind = TypeRecord::Kind::Union;
    } else if (kind == kLfEnum) {
        t.kind = TypeRecord::Kind::Enum;
    }
    if (body.size() < 8) return t;
    // u16 NumMembers; u16 Properties; u32 FieldList;
    const u16 props = read_le_at<u16>(body.data() + 2);
    t.is_forward_ref = (props & 0x80u) != 0;     // CV_PROP_FWDREF
    t.field_list = read_le_at<u32>(body.data() + 4);
    std::size_t pos = 8;
    if (kind == kLfEnum) {
        // u32 UnderlyingType
        if (body.size() < 12) return t;
        t.base_type = read_le_at<u32>(body.data() + 8);
        pos = 12;
        // Enum then has its name (no size leaf - enums get their size
        // from the underlying type).
        t.name = read_cstr_advance(body, pos);
    } else if (kind == kLfUnion) {
        // u16 NumMembers (already read), u16 Props, u32 FieldList,
        // [size leaf], [name].
        u64 sz = 0;
        if (read_numeric_leaf(body, pos, sz)) t.size_bytes = sz;
        t.name = read_cstr_advance(body, pos);
    } else {
        // Structure / Class: NumMembers, Props, FieldList, DerivedFrom,
        // VShape, [size leaf], [name].
        if (body.size() < 16) return t;
        // body+8 = DerivedFrom (u32), body+12 = VShape (u32)
        pos = 16;
        u64 sz = 0;
        if (read_numeric_leaf(body, pos, sz)) t.size_bytes = sz;
        t.name = read_cstr_advance(body, pos);
    }
    return t;
}

[[nodiscard]] TypeRecord parse_bitfield(std::span<const std::byte> body) {
    TypeRecord t;
    t.kind = TypeRecord::Kind::Bitfield;
    if (body.size() < 6) return t;
    t.base_type   = read_le_at<u32>(body.data() + 0);
    // body[4] = bit-length, body[5] = bit-position; we don't need them
    // for type rendering.
    return t;
}

[[nodiscard]] TypeRecord parse_alias(std::span<const std::byte> body) {
    TypeRecord t;
    t.kind = TypeRecord::Kind::Alias;
    if (body.size() < 4) return t;
    t.base_type = read_le_at<u32>(body.data() + 0);
    std::size_t pos = 4;
    t.name = read_cstr_advance(body, pos);
    return t;
}

// Render a primitive type index. Below 0x1000 these encode (mode, type)
// bit-packed:
//   bits 0..7  primitive subtype
//   bits 8..10 mode (0=direct, 1..3 16-bit ptrs, 4=near32, 5=far32, 6=near64)
//   bits 11..15 size class
//
// We render the underlying primitive name and prefix with a `*` for
// any pointer mode.
std::string render_primitive(u32 ti) {
    const u32 sub  = ti & 0xFFu;
    const u32 mode = (ti >> 8) & 0x7u;
    auto name_for = [&]() -> std::string {
        switch (sub) {
            case 0x00: return "void_t";    // T_NOTYPE / T_ABS - rare
            case 0x03: return "void";
            case 0x08: return "HRESULT";
            // Signed-char aliases: 0x10 = signed char, 0x70 = char (rchar).
            case 0x10: return "signed char";
            case 0x11: return "short";
            case 0x12: return "long";
            case 0x13: return "long long";
            case 0x20: return "unsigned char";
            case 0x21: return "unsigned short";
            case 0x22: return "unsigned long";
            case 0x23: return "unsigned long long";
            case 0x30: return "bool";
            case 0x31: return "bool16";
            case 0x32: return "bool32";
            case 0x40: return "float";
            case 0x41: return "double";
            case 0x42: return "long double";
            case 0x68: return "int8_t";    // 8-bit int
            case 0x69: return "uint8_t";
            case 0x70: return "char";      // T_RCHAR
            case 0x71: return "wchar_t";
            case 0x72: return "int16_t";   // T_INT2
            case 0x73: return "uint16_t";
            case 0x74: return "int";       // T_INT4
            case 0x75: return "unsigned int";
            case 0x76: return "int64_t";
            case 0x77: return "uint64_t";
            case 0x7A: return "char16_t";
            case 0x7B: return "char32_t";
            case 0x7C: return "char8_t";
            default:
                return std::format("__primtype_{:#x}", sub);
        }
    };
    auto base = name_for();
    if (mode != 0) {
        // Any non-zero mode = pointer-flavored variant. We don't
        // distinguish near/far/huge here - Ember decompiles 64-bit
        // binaries; the size is implicit.
        base += "*";
    }
    return base;
}

}  // namespace

Result<TpiTable> TpiTable::parse(std::span<const std::byte> tpi_stream) {
    if (tpi_stream.size() < 56) {
        return std::unexpected(Error::truncated("pdb: TPI header truncated"));
    }
    TpiTable t;
    const auto hdr = tpi_stream.subspan(0, 56);
    // Layout fields we use:
    //   +0  Version
    //   +4  HeaderSize
    //   +8  TypeIndexBegin   (typically 0x1000)
    //   +12 TypeIndexEnd
    //   +16 TypeRecordBytes
    const u32 header_size       = read_le_at<u32>(hdr.data() + 4);
    t.ti_begin_                 = read_le_at<u32>(hdr.data() + 8);
    t.ti_end_                   = read_le_at<u32>(hdr.data() + 12);
    const u32 type_record_bytes = read_le_at<u32>(hdr.data() + 16);

    if (header_size < 56 || header_size > tpi_stream.size()) {
        return std::unexpected(Error::invalid_format(std::format(
            "pdb: TPI header size {} outside stream {}",
            header_size, tpi_stream.size())));
    }
    if (t.ti_end_ < t.ti_begin_) {
        return std::unexpected(Error::invalid_format(std::format(
            "pdb: TPI ti_end {} < ti_begin {}", t.ti_end_, t.ti_begin_)));
    }
    if (header_size + type_record_bytes > tpi_stream.size()) {
        return std::unexpected(Error::truncated(std::format(
            "pdb: TPI claims {} record bytes after {}-byte header in {}-byte stream",
            type_record_bytes, header_size, tpi_stream.size())));
    }
    if (t.ti_end_ == t.ti_begin_) {
        // No types - empty table is valid.
        return t;
    }

    const auto records_span = tpi_stream.subspan(header_size, type_record_bytes);
    const u32 expected = t.ti_end_ - t.ti_begin_;
    t.records_.resize(expected);

    u32 ti_cursor = t.ti_begin_;
    for_each_record(records_span, [&](u16 kind, std::span<const std::byte> body) {
        if (ti_cursor >= t.ti_end_) return false;
        const u32 slot = ti_cursor - t.ti_begin_;
        switch (kind) {
            case kLfPointer:  t.records_[slot] = parse_pointer(body);  break;
            case kLfModifier: t.records_[slot] = parse_modifier(body); break;
            case kLfProc:     t.records_[slot] = parse_proc(body);     break;
            case kLfMFunc:    t.records_[slot] = parse_mfunc(body);    break;
            case kLfArgList:  t.records_[slot] = parse_arg_list(body); break;
            case kLfArray:    t.records_[slot] = parse_array(body);    break;
            case kLfStructure:
            case kLfClass:
            case kLfUnion:
            case kLfEnum:     t.records_[slot] = parse_aggregate(kind, body); break;
            case kLfBitfield: t.records_[slot] = parse_bitfield(body); break;
            case kLfAlias:    t.records_[slot] = parse_alias(body);    break;
            case kLfFieldList:
                // Field lists are referenced by aggregate records but
                // we don't mine them yet - record presence so the
                // aggregate's field_list -> nullptr lookup doesn't
                // confuse callers.
                break;
            default:
                // Unrecognized leaves stay as Kind::Unknown (default).
                break;
        }
        ++ti_cursor;
        return true;
    });

    return t;
}

const TypeRecord* TpiTable::lookup(u32 type_index) const noexcept {
    if (type_index < ti_begin_ || type_index >= ti_end_) return nullptr;
    const u32 slot = type_index - ti_begin_;
    if (slot >= records_.size()) return nullptr;
    return &records_[slot];
}

std::string TpiTable::render_type(u32 type_index, int depth) const {
    if (depth > 8) return "?";   // recursion guard - pathological PDBs only
    if (type_index < ti_begin_) return render_primitive(type_index);

    const TypeRecord* r = lookup(type_index);
    if (!r) return std::format("__t_{:#x}", type_index);

    auto add_qualifiers = [](std::string& out, bool c, bool v) {
        if (c) out = "const " + out;
        if (v) out = "volatile " + out;
    };

    switch (r->kind) {
        case TypeRecord::Kind::Unknown:
            return std::format("__t_{:#x}", type_index);

        case TypeRecord::Kind::Pointer: {
            std::string base = render_type(r->base_type, depth + 1);
            add_qualifiers(base, r->is_const, r->is_volatile);
            base += r->is_rvalue_ref ? "&&"
                  : r->is_reference  ? "&"
                                     : "*";
            return base;
        }

        case TypeRecord::Kind::Modifier: {
            std::string base = render_type(r->base_type, depth + 1);
            add_qualifiers(base, r->is_const, r->is_volatile);
            return base;
        }

        case TypeRecord::Kind::Array: {
            const std::string elem = render_type(r->base_type, depth + 1);
            // Approximate count from byte size / element size - too
            // expensive to chase down sizeof through arbitrary types,
            // so we just print the byte size as a comment.
            return std::format("{}[/* {} bytes */]", elem, r->array_size_bytes);
        }

        case TypeRecord::Kind::Procedure:
        case TypeRecord::Kind::MFunction: {
            // Function types only show up as the pointee of LF_POINTER
            // (or the member-function class type); render to a brief
            // signature so users see something useful instead of "?".
            const std::string ret = render_type(r->base_type, depth + 1);
            return ret + "()";
        }

        case TypeRecord::Kind::Structure:
        case TypeRecord::Kind::Union: {
            if (!r->name.empty()) {
                // Use plain `Foo` rather than `struct Foo` - easier on
                // the eyes in pseudo-C output, and matches what
                // FunctionSig.params already look like for user-typed
                // signatures.
                return r->name;
            }
            return r->kind == TypeRecord::Kind::Union
                ? std::string("union /* anon */")
                : std::string("struct /* anon */");
        }

        case TypeRecord::Kind::Enum:
            return r->name.empty() ? std::string("enum /* anon */")
                                    : r->name;

        case TypeRecord::Kind::Bitfield:
            return render_type(r->base_type, depth + 1);

        case TypeRecord::Kind::Alias:
            return r->name.empty()
                ? render_type(r->base_type, depth + 1)
                : r->name;

        case TypeRecord::Kind::ArgList:
            // ArgList isn't a real "type" - caller mishandled if it
            // ever asks for one.
            return "(arglist)";
    }
    return "?";
}

}  // namespace ember::pdb
