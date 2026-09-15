// Rebrand guard: Ember -> Spelunk renamed the CLI, cache dir, namespaces
// and CMake targets. This locks the runtime-visible bits so a stale
// "ember" path can't creep back in unnoticed.
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

#include <spelunk/analysis/demangle.hpp>
#include <spelunk/common/cache.hpp>

namespace fs = std::filesystem;

namespace {

int fails = 0;

void check(bool cond, const char* ctx) {
    if (!cond) {
        std::fprintf(stderr, "FAIL: %s\n", ctx);
        ++fails;
    }
}

void check_eq_str(const std::string& got, const std::string& want, const char* ctx) {
    if (got != want) {
        std::fprintf(stderr, "FAIL: %s\n  got:  '%s'\n  want: '%s'\n", ctx, got.c_str(),
                     want.c_str());
        ++fails;
    }
}

// Temporarily override an env var, restoring the old value on destruction.
struct EnvGuard {
    std::string name;
    std::string old_value;
    bool had_old = false;
    bool active = false;

    explicit EnvGuard(const char* n) : name(n) {
        if (const char* v = std::getenv(n)) {
            old_value = v;
            had_old = true;
        }
        active = true;
    }
    void set(const std::string& v) { ::setenv(name.c_str(), v.c_str(), 1); }
    void unset() { ::unsetenv(name.c_str()); }
    ~EnvGuard() {
        if (!active)
            return;
        if (had_old)
            ::setenv(name.c_str(), old_value.c_str(), 1);
        else
            ::unsetenv(name.c_str());
    }
};

fs::path scratch_root(const char* tag) {
    auto p = fs::temp_directory_path() / tag;
    std::error_code ec;
    fs::remove_all(p, ec);
    fs::create_directories(p, ec);
    return p;
}

void write_file(const fs::path& p, std::string_view bytes) {
    fs::create_directories(p.parent_path());
    std::ofstream o(p, std::ios::binary | std::ios::trunc);
    o.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
}

} // namespace

int main() {
    // 1. XDG_CACHE_HOME respected, leaf dir is exactly "spelunk".
    {
        EnvGuard xdg("XDG_CACHE_HOME");
        EnvGuard home("HOME");
        const auto root = scratch_root("spelunk_rebrand_xdg");
        xdg.set((root / "xdg").string());
        const auto dir = spelunk::cache::default_dir();
        check_eq_str(dir.string(), (root / "xdg" / "spelunk").string(),
                     "XDG_CACHE_HOME/<...>/spelunk");
        check(dir.filename() == "spelunk", "cache leaf is 'spelunk' (xdg)");
        check(dir.string().find("ember") == std::string::npos, "no 'ember' in XDG cache dir");
    }

    // 2. HOME fallback is ~/.cache/spelunk.
    {
        EnvGuard xdg("XDG_CACHE_HOME");
        EnvGuard home("HOME");
        const auto root = scratch_root("spelunk_rebrand_home");
        xdg.unset();
        home.set((root / "home").string());
        const auto dir = spelunk::cache::default_dir();
        check_eq_str(dir.string(), (root / "home" / ".cache" / "spelunk").string(),
                     "HOME fallback is ~/.cache/spelunk");
        check(dir.string().find("ember") == std::string::npos, "no 'ember' in HOME cache dir");
    }

    // 3. Cache write/read round-trips (atomic write + rename path).
    {
        const auto root = scratch_root("spelunk_rebrand_rw");
        const auto dir = root / "cache";
        const std::string key = "deadbeef01234567";
        check(spelunk::cache::write(dir, key, "probe", "hello-spelunk").has_value(),
              "cache::write ok");
        auto back = spelunk::cache::read(dir, key, "probe");
        check(back.has_value(), "cache::read hit after write");
        if (back)
            check_eq_str(*back, "hello-spelunk", "cache round-trip bytes");
        check(!spelunk::cache::read(dir, key, "missing").has_value(),
              "cache::read miss on unknown tag");
        check(!spelunk::cache::read(dir, "no-such-key", "probe").has_value(),
              "cache::read miss on unknown key");
    }

    // 4. Cache keys: stable for same input, scoped by tag.
    {
        const auto root = scratch_root("spelunk_rebrand_key");
        const auto bin = root / "probe.bin";
        write_file(bin, "spelunk-key-bytes");
        auto k1 = spelunk::cache::key_for(bin, "");
        auto k2 = spelunk::cache::key_for(bin, "");
        check(k1.has_value() && k2.has_value(), "key_for ok on real file");
        if (k1 && k2)
            check_eq_str(*k1, *k2, "key_for stable without scope");
        auto ks = spelunk::cache::key_for(bin, "module:foo.dll");
        check(ks.has_value(), "key_for ok with scope tag");
        if (k1 && ks)
            check(*k1 != *ks, "scope tag changes cache key");
        auto missing = spelunk::cache::key_for(root / "does-not-exist", "");
        check(!missing.has_value(), "key_for errors on missing file");
    }

    // 5. spelunk:: namespace smoke: demangler survived the rebrand.
    check_eq_str(spelunk::pretty_symbol("_Z3foov"), "foo()",
                 "spelunk::pretty_symbol still demangles Itanium");
    check_eq_str(spelunk::pretty_symbol("main"), "main", "plain names pass through");

    if (fails == 0)
        std::puts("ok");
    return fails == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
