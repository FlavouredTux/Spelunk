#include <ember/analysis/import_sigs.hpp>

#include <cstdio>

namespace {

int failures = 0;

void check(bool condition, const char* message) {
    if (condition) return;
    std::fprintf(stderr, "FAIL: %s\n", message);
    ++failures;
}

}  // namespace

int main() {
    using ember::ImportStringKind;
    using ember::import_arg_string_kind;

    ember::TypeArena arena;
    const auto strcasestr = ember::lookup_import_sig("strcasestr", arena);
    check(strcasestr.has_value(), "strcasestr has a typed import signature");
    if (strcasestr) {
        check(strcasestr->params.size() == 2,
              "strcasestr signature has two parameters");
        check(!strcasestr->variadic,
              "strcasestr signature is not variadic");

        const auto is_char_pointer = [&](ember::TypeRef type) {
            const auto& node = arena.node(type);
            return node.kind == ember::TypeKind::Ptr &&
                   arena.kind(node.p.pointee) == ember::TypeKind::Int &&
                   arena.node(node.p.pointee).i.bits == 8;
        };
        check(is_char_pointer(strcasestr->ret),
              "strcasestr returns char pointer");
        if (strcasestr->params.size() == 2) {
            check(is_char_pointer(strcasestr->params[0]),
                  "strcasestr haystack type is char pointer");
            check(is_char_pointer(strcasestr->params[1]),
                  "strcasestr needle type is char pointer");
        }
    }

    check(import_arg_string_kind("strcasestr", 1) ==
              ImportStringKind::Narrow,
          "strcasestr haystack is a narrow string");
    check(import_arg_string_kind("strcasestr", 2) ==
              ImportStringKind::Narrow,
          "strcasestr needle is a narrow string");
    check(import_arg_string_kind("CreateFileA", 1) ==
              ImportStringKind::Narrow,
          "CreateFileA path is a narrow string");

    check(import_arg_string_kind("lstrlenW", 1) == ImportStringKind::Wide,
          "lstrlenW input is a wide string");
    check(import_arg_string_kind("CreateFileW", 1) == ImportStringKind::Wide,
          "CreateFileW path is a wide string");

    check(import_arg_string_kind("strcasestr", 0) == ImportStringKind::None,
          "string argument positions are 1-based");
    check(import_arg_string_kind("strcasestr", 3) == ImportStringKind::None,
          "strcasestr has no third string argument");
    check(import_arg_string_kind("strchr", 2) == ImportStringKind::None,
          "strchr search character is scalar");
    check(import_arg_string_kind("strnlen", 2) == ImportStringKind::None,
          "strnlen length is scalar");
    check(import_arg_string_kind("strsep", 1) == ImportStringKind::None,
          "strsep pointer-to-pointer is not a string");
    check(import_arg_string_kind("memcpy", 1) == ImportStringKind::None,
          "memcpy source is a raw buffer");
    check(import_arg_string_kind("unknown_import", 1) ==
              ImportStringKind::None,
          "unknown import has no string metadata");

    return failures == 0 ? 0 : 1;
}
