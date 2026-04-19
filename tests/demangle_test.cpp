#include <ember/analysis/demangle.hpp>

#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>

namespace {

int fails = 0;

void check(std::string_view mangled, std::string_view expected) {
    const std::string got = ember::pretty_symbol(mangled);
    if (got != expected) {
        std::fprintf(stderr, "FAIL: %.*s\n  got:      %s\n  expected: %.*s\n",
                     static_cast<int>(mangled.size()), mangled.data(),
                     got.c_str(),
                     static_cast<int>(expected.size()), expected.data());
        ++fails;
    }
}

}  // namespace

int main() {
    // Top-level free function with a plain arg list.
    check("_Z3foov",  "foo()");
    check("_Z3fooi",  "foo(int)");
    check("_Z3fooii", "foo(int, int)");

    // Nested names.
    check("_ZN3foo3barEv", "foo::bar()");
    check("_ZN3foo3barEi", "foo::bar(int)");

    // Ctor/dtor resolve against the enclosing class.
    check("_ZN3std6stringC1EPKc", "std::string::string(const char*)");
    check("_ZN3std6stringD1Ev",   "std::string::~string()");

    // CV-qualified member functions get the suffix after args.
    check("_ZNK3foo3barEv", "foo::bar() const");

    // Operator overloads.
    check("_ZN3fooplERKNS_3barE", "foo::operator+(const foo::bar&)");

    // Template args.
    check("_Z3mapIiE",              "map<int>");
    check("_ZN5boost5regexIcEE",    "boost::regex<char>");

    // `St` is a namespace abbreviation for std::.
    check("_ZSt3mini", "std::min(int)");

    // Substitutions + CV qualifiers + refs.
    check("_ZN5boost6system6detail10hash_valueERKNS1_10error_codeE",
          "boost::system::detail::hash_value(const boost::system::detail::error_code&)");

    // Not mangled → returned unchanged.
    check("not_mangled", "not_mangled");
    check("main",         "main");

    // pretty_symbol_base strips the trailing signature so the header
    // builder can attach its own argument list without duplication.
    auto check_base = [](std::string_view m, std::string_view want) {
        const std::string got = ember::pretty_symbol_base(m);
        if (got != want) {
            std::fprintf(stderr, "FAIL base: %.*s\n  got:      %s\n  expected: %.*s\n",
                         static_cast<int>(m.size()), m.data(),
                         got.c_str(),
                         static_cast<int>(want.size()), want.data());
            ++fails;
        }
    };
    check_base("_Z3foov",                     "foo");
    check_base("_ZN3foo3barEi",               "foo::bar");
    check_base("_ZNK3foo3barEv",              "foo::bar");
    check_base("_ZN3std6stringC1EPKc",        "std::string::string");
    check_base("_ZNSt6vectorIiSaIiEE9push_backEOi",
               "std::vector<int, std::allocator<int>>::push_back");
    check_base("plain_name", "plain_name");

    if (fails) {
        std::fprintf(stderr, "%d failure(s)\n", fails);
        return EXIT_FAILURE;
    }
    std::puts("ok");
    return EXIT_SUCCESS;
}
