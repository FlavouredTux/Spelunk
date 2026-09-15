#include <spelunk/analysis/import_sigs.hpp>
#include <spelunk/binary/symbol.hpp>

#include <cstdio>
#include <string_view>

namespace {

int failures = 0;

void check(bool condition, const char* message) {
    if (condition) return;
    std::fprintf(stderr, "FAIL: %s\n", message);
    ++failures;
}

}  // namespace

int main() {
    using spelunk::ImportStringKind;
    using spelunk::import_arg_string_kind;

    const auto check_import_name = [](std::string_view decorated,
                                      std::string_view expected,
                                      const char* message,
                                      bool raw_macho = false) {
        check(spelunk::strip_import_name_decorations(decorated, raw_macho) == expected,
              message);
    };
    check_import_name("puts@GLIBC_2.2.5", "puts",
                      "ELF import version is removed");
    check_import_name("memcpy@@GLIBC_2.14", "memcpy",
                      "default ELF import version is removed");
    check_import_name("__imp_CreateFileW", "CreateFileW",
                      "PE import thunk prefix is removed");
    check_import_name("kernel32.dll!__imp_CreateFileW@KERNELBASE_1.0",
                      "CreateFileW",
                      "module, thunk, and version decorations compose");
    check_import_name("_puts", "_puts",
                      "loader-normalized mode preserves a leading underscore");
    check_import_name("_puts", "puts",
                      "raw Mach-O mode removes its C-ABI underscore", true);
    check_import_name("___assert_rtn", "__assert_rtn",
                      "raw Mach-O mode removes exactly one underscore", true);

    check_import_name("?method@Widget@@QEAAXXZ", "?method@Widget@@QEAAXXZ",
                      "MSVC decoration is not mistaken for an ELF version");
    check_import_name("__imp_?method@Widget@@QEAAXXZ",
                      "?method@Widget@@QEAAXXZ",
                      "PE thunk removal preserves MSVC decoration");
    check_import_name("_Function@8", "Function",
                      "stdcall decoration is removed");
    check_import_name("@FastFunction@8", "FastFunction",
                      "fastcall decoration is removed");
    check_import_name("__imp__Sleep@4", "Sleep",
                      "PE thunk and stdcall decorations compose");
    check_import_name("__imp_Sleep@@4", "Sleep",
                      "PE thunk and vectorcall decorations compose");
    check_import_name("plain@", "plain@",
                      "empty version suffix is preserved");
    check_import_name("operator!", "operator!",
                      "trailing exclamation mark is not a module qualifier");
    check_import_name("!puts", "!puts",
                      "empty module qualifier is preserved");

    spelunk::TypeArena arena;
    const auto decorated_sleep = spelunk::lookup_import_sig(
        spelunk::strip_import_name_decorations("__imp__Sleep@4"), arena);
    check(decorated_sleep.has_value() && decorated_sleep->params.size() == 1,
          "decorated stdcall import reaches its typed signature");

    const auto strcasestr = spelunk::lookup_import_sig("strcasestr", arena);
    check(strcasestr.has_value(), "strcasestr has a typed import signature");
    if (strcasestr) {
        check(strcasestr->params.size() == 2,
              "strcasestr signature has two parameters");
        check(!strcasestr->variadic,
              "strcasestr signature is not variadic");

        const auto is_char_pointer = [&](spelunk::TypeRef type) {
            const auto& node = arena.node(type);
            return node.kind == spelunk::TypeKind::Ptr &&
                   arena.kind(node.p.pointee) == spelunk::TypeKind::Int &&
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
