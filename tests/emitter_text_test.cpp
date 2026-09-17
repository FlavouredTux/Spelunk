#include "emitter_text.hpp"

#include <cstdio>
#include <string>
#include <string_view>

namespace {

int failures = 0;

void check(bool condition, const char* message) {
    if (condition) return;
    std::fprintf(stderr, "FAIL: %s\n", message);
    ++failures;
}

void check_text(std::string_view actual, std::string_view expected,
                const char* message) {
    if (actual == expected) return;
    std::fprintf(stderr, "FAIL: %s\nExpected:\n%.*s\nActual:\n%.*s\n",
                 message, static_cast<int>(expected.size()), expected.data(),
                 static_cast<int>(actual.size()), actual.data());
    ++failures;
}

void test_identifier_queries() {
    using spelunk::emit::text_contains_identifier_in_code;
    check(!text_contains_identifier_in_code(
              R"(log("value", 'v'); /* value */ // value)", "value"),
          "literals and comments are not code uses");
    check(text_contains_identifier_in_code(
              R"(log("https://host", value);)", "value"),
          "a URL does not hide a later code use");
    check(text_contains_identifier_in_code(
              R"(log("/*", value, "*/");)", "value"),
          "quoted comment delimiters do not hide code");
    check(text_contains_identifier_in_code(
              "/* // ignored\n*/ return value;", "value"),
          "line comment spelling inside a block comment does not hide its end");
    check(!text_contains_identifier_in_code("va/**/lue;", "value"),
          "comments separate tokens instead of joining identifiers");
    check(!text_contains_identifier_in_code(
              R"(log("escaped \" value", '\'');)", "value"),
          "escaped quotes stay inside their literals");
    check(!text_contains_identifier_in_code(
              "value_2 + prevalue + value2", "value"),
          "identifier queries require complete tokens");
}

void test_identifier_replacement() {
    using spelunk::emit::replace_identifier;
    check_text(replace_identifier(
        "t7 += t7; log(\"t7\", 't'); // t7\n/* t7 */ t70 = t7;",
        "t7", "saved"),
        "saved += saved; log(\"t7\", 't'); // t7\n/* t7 */ t70 = saved;",
        "renaming preserves literals, comments, and larger identifiers");
    check_text(replace_identifier("'x' + x + L\"x\"", "x", "item"),
               "'x' + item + L\"x\"", "character and wide literals survive renaming");
    check_text(replace_identifier("x", "", "item"), "x",
               "an empty identifier leaves the text unchanged");
    check_text(replace_identifier("x /* x", "x", "item"), "item /* x",
               "an unfinished comment is preserved");
    check_text(replace_identifier("x + \"x", "x", "item"), "item + \"x",
               "an unfinished literal is preserved");
    check_text(replace_identifier("L\"x\" + L", "L", "item"),
               "L\"x\" + item", "literal prefixes are not identifiers");
}

void test_code_mask_and_declarations() {
    using namespace spelunk::emit;
    const std::string source = "x; /* hidden\ncontinued */ y = \"value\";\n";
    const std::string code = code_only_text(source);
    check(code.size() == source.size(), "mask preserves byte offsets");
    for (std::size_t i = 0; i < source.size(); ++i) {
        check((source[i] == '\n') == (code[i] == '\n'),
              "mask preserves newlines");
    }
    check(code.find("x;") == source.find("x;") &&
          code.find("y =") == source.find("y ="),
          "code tokens retain their original positions");
    check(!text_declares_identifier(
              "/*\n uint32_t t7;\n*/ log(\"uint32_t t7;\");", "t7"),
          "declaration checks ignore strings and multiline comments");
    check(text_declares_identifier(
              "/* uint32_t t7; */\n  uint32_t t7 = 0;", "t7"),
          "declaration checks find a real declaration after comments");
    check(!line_declares_identifier("uint32_t x;", ""),
          "an empty name is not a declaration");
    check(!line_declares_identifier("return xmm0_5;", "xmm0_5"),
          "return expressions are not declarations");
    check(!line_declares_identifier("goto label;", "label"),
          "goto targets are not declarations");
    check(count_untyped_pointer_index_sites(
              "void* p;\nlog(\"p[0]\"); /* p[1] */\np[2];") == 1,
          "untyped pointer diagnostics count code uses only");
}

void test_ppc_presentation() {
    using namespace spelunk::emit;
    check_text(rename_ppc_temporaries(
        "  uint32_t t7 = read();\n  log(\"t7\", t7); // t7\n"),
        "  uint32_t value = read();\n  log(\"t7\", value); // t7\n",
        "PPC temporary naming changes code only");
    check_text(rename_ppc_temporaries("  log(\"t7\"); // t8\n"),
               "  log(\"t7\"); // t8\n",
               "literal-only temporary names are left alone");
    check_text(compact_ppc_type_names(
        "typedef union PpcState7 { int x; } PpcState7;\n"
        "PpcState7* p; // PpcState7\nlog(\"PpcState7\");\n"),
        "typedef union PpcState { int x; } PpcState;\n"
        "PpcState* p; // PpcState7\nlog(\"PpcState7\");\n",
        "PPC type compaction preserves literal and comment contents");
    check_text(fix_ppc_offset_pointer_declarations(
        "  log(\"void* x = (a << 2) & 7;\");\n"
        "  void* x = (a << 2) & 7;\n"),
        "  log(\"void* x = (a << 2) & 7;\");\n"
        "  uint32_t x = (a << 2) & 7;\n",
        "PPC pointer cleanup ignores declaration text inside strings");
}

}  // namespace

int main() {
    test_identifier_queries();
    test_identifier_replacement();
    test_code_mask_and_declarations();
    test_ppc_presentation();
    return failures == 0 ? 0 : 1;
}
