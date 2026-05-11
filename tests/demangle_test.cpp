#include <ember/analysis/demangle.hpp>
#include <ember/analysis/msvc_demangle.hpp>

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

void check_msvc(std::string_view mangled, std::string_view expected) {
    auto got_opt = ember::demangle_msvc(mangled);
    const std::string got = got_opt ? *got_opt : std::string("<nullopt>");
    if (got != expected) {
        std::fprintf(stderr, "FAIL msvc: %.*s\n  got:      %s\n  expected: %.*s\n",
                     static_cast<int>(mangled.size()), mangled.data(),
                     got.c_str(),
                     static_cast<int>(expected.size()), expected.data());
        ++fails;
    }
}

void check_msvc_full(std::string_view mangled, std::string_view expected) {
    auto got_opt = ember::demangle_msvc_full(mangled);
    const std::string got = got_opt ? *got_opt : std::string("<nullopt>");
    if (got != expected) {
        std::fprintf(stderr, "FAIL msvc full: %.*s\n  got:      %s\n  expected: %.*s\n",
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

    // ---- MSVC demangler ----------------------------------------------
    // RTTI type descriptors: ".?AV<name>@@" / ".?AU<name>@@".
    check_msvc(".?AVFoo@@",                   "Foo");
    check_msvc(".?AUBar@@",                   "Bar");
    check_msvc(".?AVInner@Outer@@",           "Outer::Inner");
    check_msvc(".?AVDeep@Mid@Out@NS@@",       "NS::Out::Mid::Deep");

    // Templated RTTI names. `?$` introduces a template; H = int.
    check_msvc(".?AV?$vector@H@std@@",        "std::vector<int>");
    check_msvc(".?AV?$pair@HM@std@@",         "std::pair<int, float>");
    // Pointer / const decoration on a template arg.
    check_msvc(".?AV?$ptr@PEAH@my@@",         "my::ptr<int*>");
    check_msvc(".?AV?$ptr@PEBD@my@@",         "my::ptr<const char*>");

    // Public mangled symbols.
    check_msvc("?foo@@YAXXZ",                 "foo");
    check_msvc("?bar@Foo@@QEAAXXZ",           "Foo::bar");
    check_msvc("?baz@N@O@@QEAAXXZ",           "O::N::baz");

    // Constructors and destructors.
    check_msvc("??0Foo@@QEAA@XZ",             "Foo::Foo");
    check_msvc("??1Foo@@QEAA@XZ",             "Foo::~Foo");
    check_msvc("??_GFoo@@UEAAPEAXI@Z",        "Foo::~Foo");
    check_msvc("??1Inner@Outer@@QEAA@XZ",     "Outer::Inner::~Inner");

    // Operators.
    check_msvc("??4Foo@@QEAAAEAU0@AEBU0@@Z",  "Foo::operator=");
    check_msvc("??_7Foo@@6B@",                "Foo::`vftable'");

    // Full MSVC signatures keep the old name-only API separate.
    check_msvc_full("?foo@@YAXXZ",                 "void foo()");
    check_msvc_full("?take_int@@YAXH@Z",           "void take_int(int)");
    check_msvc_full("?sum@@YAHHH@Z",               "int sum(int, int)");
    check_msvc_full("?bar@Foo@@QEAAXH@Z",          "void Foo::bar(int)");
    check_msvc_full("?size@Foo@@QEBAHXZ",          "int Foo::size() const");
    check_msvc_full("?tick@Foo@@QECAHXZ",          "int Foo::tick() volatile");
    check_msvc_full("?stat@Foo@@SAXH@Z",           "void Foo::stat(int)");
    check_msvc_full("?make@Foo@@SAPEAV1@XZ",       "Foo* Foo::make()");
    check_msvc_full("?cstr@@YAPEBDXZ",             "const char* cstr()");
    check_msvc_full("?puts2@@YAXPEBD@Z",           "void puts2(const char*)");
    check_msvc_full("??0Foo@@QEAA@XZ",             "Foo::Foo()");
    check_msvc_full("??1Foo@@QEAA@XZ",             "Foo::~Foo()");
    check_msvc_full("??4Foo@@QEAAAEAU0@AEBU0@@Z",  "Foo& Foo::operator=(const Foo&)");

    // Data symbols: common global / static-member decorated tails.
    check_msvc_full("?g_counter@@3HA",              "int g_counter");
    check_msvc_full("?limit@Foo@@2HB",              "int Foo::limit");
    check_msvc_full("?g_name@@3PEBDA",              "const char* g_name");

    check("?foo@@YAXH@Z",                 "void foo(int)");
    check("?size@Foo@@QEBAHXZ",           "int Foo::size() const");
    check("?g_counter@@3HA",              "int g_counter");
    check_base("?bar@Foo@@QEAAXH@Z",      "Foo::bar");
    check_base("?g_counter@@3HA",         "g_counter");

    // Not mangled / unsupported → nullopt (rendered as "<nullopt>").
    check_msvc("plain_name",                  "<nullopt>");
    check_msvc("",                            "<nullopt>");

    if (fails) {
        std::fprintf(stderr, "%d failure(s)\n", fails);
        return EXIT_FAILURE;
    }
    std::puts("ok");
    return EXIT_SUCCESS;
}
