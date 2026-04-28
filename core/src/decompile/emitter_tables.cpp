#include "emitter_tables.hpp"

#include <cstddef>
#include <utility>

namespace ember::detail {

namespace {

// Printf/scanf family. `format_index` is the zero-based position of the
// format-string argument in the call.
struct VariadicImport {
    std::string_view name;
    u8               format_index;
};

constexpr VariadicImport kVariadicImports[] = {
    {"printf",    0}, {"vprintf",   0},
    {"fprintf",   1}, {"vfprintf",  1},
    {"dprintf",   1}, {"vdprintf",  1},
    {"sprintf",   1}, {"vsprintf",  1},
    {"snprintf",  2}, {"vsnprintf", 2},
    {"asprintf",  1}, {"vasprintf", 1},
    {"syslog",    1}, {"vsyslog",   1},
    {"warn",      0}, {"warnx",     0},
    {"err",       1}, {"errx",      1},
    {"scanf",     0}, {"vscanf",    0},
    {"fscanf",    1}, {"vfscanf",   1},
    {"sscanf",    1}, {"vsscanf",   1},
};

}  // namespace

std::optional<u8> variadic_format_index(std::string_view n) noexcept {
    for (const auto& v : kVariadicImports) {
        if (v.name == n) return v.format_index;
    }
    return std::nullopt;
}

// Count arg-consuming `%` specifiers in a printf-style format string.
// `%%` is ignored; `%*` and `%*N$` add one for the width/precision arg.
// Positional `%N$` specifiers make arg count = max(N) across all specs; when
// present we assume the author was consistent (mixing with non-positional is
// UB per POSIX). Without positionals, we count specs left-to-right.
// Length modifiers are skipped, not understood.
u8 count_printf_specifiers(std::string_view fmt) noexcept {
    u8 sequential = 0;
    u8 max_pos    = 0;
    bool seen_pos = false;

    auto parse_pos = [&](std::size_t& i) -> u8 {
        // `\d+\$` starting at i. On match, advance i past the `$` and
        // return the decoded position (clamped to u8). On no match, leave i.
        std::size_t j = i;
        u32 v = 0;
        while (j < fmt.size() && fmt[j] >= '0' && fmt[j] <= '9') {
            v = v * 10 + static_cast<u32>(fmt[j] - '0');
            if (v > 255) v = 255;
            ++j;
        }
        if (j == i || j >= fmt.size() || fmt[j] != '$') return 0;
        i = j + 1;
        return static_cast<u8>(v);
    };

    for (std::size_t i = 0; i < fmt.size(); ) {
        if (fmt[i] != '%') { ++i; continue; }
        ++i;
        if (i >= fmt.size()) break;
        if (fmt[i] == '%') { ++i; continue; }               // literal %%

        const u8 pos = parse_pos(i);
        if (pos > 0) { seen_pos = true; if (pos > max_pos) max_pos = pos; }

        // Walk flags/width/precision/length until we hit a conversion.
        bool converted = false;
        while (i < fmt.size()) {
            const char c = fmt[i];
            if (c == '*') {
                ++i;
                const u8 wpos = parse_pos(i);
                if (wpos > 0) {
                    seen_pos = true;
                    if (wpos > max_pos) max_pos = wpos;
                } else if (sequential < 255) {
                    ++sequential;
                }
                continue;
            }
            const bool is_conv =
                (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
            if (is_conv && c != 'l' && c != 'h' && c != 'L' && c != 'z' &&
                c != 'j' && c != 't') {
                if (pos == 0 && sequential < 255) ++sequential;
                ++i;
                converted = true;
                break;
            }
            ++i;
        }
        if (!converted) break;                              // malformed tail
    }

    return seen_pos ? max_pos : sequential;
}

// Fixed-arity libc/POSIX imports we recognize by name so that
// `puts(local_18, rsi, rdx, ...)` trims to `puts(local_18)`.
// Variadic entries live in `kVariadicImports` above.
// Element type uses `unsigned` (not u8) so the brace-init list `{"strlen", 1}`
// doesn't trip MSVC's C4244 narrowing warning under -Werror. The arity itself
// is small (always ≤ 6) but the storage type doesn't matter — every caller
// reads it back into a u8 / int via `*x.value`.
std::optional<u8> libc_arity_by_name(std::string_view n) noexcept {
    static const std::pair<std::string_view, unsigned> kTable[] = {
        {"strlen", 1}, {"strnlen", 2}, {"strdup", 1}, {"strndup", 2},
        {"strchr", 2}, {"strrchr", 2}, {"strstr", 2}, {"strcasestr", 2},
        {"strcmp", 2}, {"strncmp", 3}, {"strcasecmp", 2}, {"strncasecmp", 3},
        {"strcpy", 2}, {"strncpy", 3}, {"stpcpy", 2}, {"stpncpy", 3},
        {"strcat", 2}, {"strncat", 3},
        {"strtok", 2}, {"strtok_r", 3}, {"strsep", 2},
        {"strpbrk", 2}, {"strspn", 2}, {"strcspn", 2},
        {"index", 2}, {"rindex", 2},
        {"basename", 1}, {"dirname", 1},
        {"memcpy", 3}, {"memmove", 3}, {"memset", 3}, {"memcmp", 3},
        {"memchr", 3}, {"memrchr", 3}, {"mempcpy", 3},
        {"bzero", 2}, {"explicit_bzero", 2}, {"bcopy", 3},
        {"puts", 1}, {"fputs", 2}, {"fgets", 3}, {"fputc", 2},
        {"fgetc", 1}, {"getc", 1}, {"putc", 2}, {"ungetc", 2},
        {"putchar", 1}, {"getchar", 0}, {"gets", 1},
        {"GetTickCount", 0}, {"GetLastError", 0}, {"Sleep", 1},
        {"ExitProcess", 1}, {"CloseHandle", 1},
        {"OutputDebugStringA", 1}, {"OutputDebugStringW", 1},
        {"GetModuleHandleA", 1}, {"GetModuleHandleW", 1},
        {"LoadLibraryA", 1}, {"LoadLibraryW", 1},
        {"FreeLibrary", 1}, {"GetProcAddress", 2},
        {"VirtualAlloc", 4}, {"VirtualFree", 3}, {"VirtualProtect", 4},
        {"HeapAlloc", 3}, {"HeapFree", 3},
        {"TlsAlloc", 0}, {"TlsGetValue", 1}, {"TlsSetValue", 2}, {"TlsFree", 1},
        {"CreateFileA", 7}, {"CreateFileW", 7},
        {"DeleteFileA", 1}, {"DeleteFileW", 1},
        {"fopen", 2}, {"fdopen", 2}, {"freopen", 3}, {"fclose", 1},
        {"fflush", 1}, {"setbuf", 2}, {"setvbuf", 4},
        {"fread", 4}, {"fwrite", 4}, {"fseek", 3}, {"ftell", 1},
        {"fseeko", 3}, {"ftello", 1}, {"rewind", 1},
        {"fgetpos", 2}, {"fsetpos", 2},
        {"ferror", 1}, {"feof", 1}, {"clearerr", 1}, {"perror", 1},
        {"fileno", 1}, {"tmpfile", 0}, {"tmpnam", 1},
        {"remove", 1}, {"rename", 2},
        {"open", 2}, {"openat", 3}, {"close", 1},
        {"read", 3}, {"write", 3}, {"pread", 4}, {"pwrite", 4},
        {"readv", 3}, {"writev", 3},
        {"lseek", 3}, {"dup", 1}, {"dup2", 2}, {"dup3", 3}, {"pipe", 1},
        {"fcntl", 2}, {"ioctl", 2},
        {"stat", 2}, {"lstat", 2}, {"fstat", 2}, {"access", 2},
        {"chmod", 2}, {"fchmod", 2}, {"chown", 3}, {"fchown", 3}, {"lchown", 3},
        {"unlink", 1}, {"unlinkat", 3}, {"link", 2}, {"symlink", 2},
        {"mkdir", 2}, {"rmdir", 1}, {"chdir", 1}, {"getcwd", 2},
        {"getenv", 1}, {"secure_getenv", 1},
        {"setenv", 3}, {"unsetenv", 1}, {"putenv", 1}, {"clearenv", 0},
        {"atoi", 1}, {"atol", 1}, {"atoll", 1}, {"atof", 1},
        {"strtol", 3}, {"strtoul", 3}, {"strtoll", 3}, {"strtoull", 3},
        {"strtod", 2}, {"strtof", 2}, {"strtold", 2},
        {"malloc", 1}, {"calloc", 2}, {"realloc", 2}, {"reallocarray", 3},
        {"free", 1}, {"aligned_alloc", 2}, {"posix_memalign", 3},
        {"memalign", 2}, {"valloc", 1}, {"pvalloc", 1},
        {"mmap", 6}, {"munmap", 2}, {"mprotect", 3}, {"madvise", 3},
        {"mremap", 4}, {"msync", 3},
        {"exit", 1}, {"_exit", 1}, {"_Exit", 1}, {"abort", 0}, {"atexit", 1},
        {"quick_exit", 1}, {"at_quick_exit", 1},
        {"signal", 2}, {"raise", 1}, {"kill", 2}, {"sigaction", 3},
        {"sigprocmask", 3}, {"sigemptyset", 1}, {"sigfillset", 1},
        {"sigaddset", 2}, {"sigdelset", 2}, {"sigismember", 2},
        {"getpid", 0}, {"getppid", 0}, {"getuid", 0}, {"geteuid", 0},
        {"getgid", 0}, {"getegid", 0},
        {"fork", 0}, {"vfork", 0}, {"execv", 2}, {"execvp", 2},
        {"execve", 3}, {"execl", 2}, {"execlp", 2},
        {"waitpid", 3}, {"wait", 1}, {"system", 1},
        {"time", 1}, {"clock", 0}, {"gettimeofday", 2},
        {"clock_gettime", 2}, {"clock_settime", 2},
        {"sleep", 1}, {"usleep", 1}, {"nanosleep", 2},
        {"pthread_create", 4}, {"pthread_join", 2}, {"pthread_detach", 1},
        {"pthread_mutex_init", 2}, {"pthread_mutex_destroy", 1},
        {"pthread_mutex_lock", 1}, {"pthread_mutex_unlock", 1},
        {"pthread_mutex_trylock", 1},
        {"pthread_cond_init", 2}, {"pthread_cond_destroy", 1},
        {"pthread_cond_wait", 2}, {"pthread_cond_signal", 1},
        {"pthread_cond_broadcast", 1},
        {"qsort", 4}, {"bsearch", 5},
        {"abs", 1}, {"labs", 1}, {"llabs", 1},
        {"rand", 0}, {"srand", 1}, {"random", 0}, {"srandom", 1},
        {"isalpha", 1}, {"isdigit", 1}, {"isalnum", 1}, {"isspace", 1},
        {"isupper", 1}, {"islower", 1}, {"isprint", 1}, {"ispunct", 1},
        {"iscntrl", 1}, {"isxdigit", 1}, {"tolower", 1}, {"toupper", 1},
    };
    for (const auto& [k, v] : kTable) {
        if (k == n) return static_cast<u8>(v);
    }
    return std::nullopt;
}

bool import_returns_void(std::string_view n) noexcept {
    static const std::string_view kTable[] = {
        "Sleep",
        "ExitProcess",
        "OutputDebugStringA", "OutputDebugStringW",
        "DeleteFileA", "DeleteFileW",
        "free", "abort",
        "__stack_chk_fail",
    };
    for (auto name : kTable) {
        if (name == n) return true;
    }
    return false;
}

// Libc/POSIX functions whose parameter at `arg_index_1based` is a
// NUL-terminated string. Used to back-propagate `char*` onto the caller's
// own arg slots. Positions listed are 1-based.
bool libc_arg_is_charp(std::string_view name, u8 arg_idx_1) noexcept {
    struct Entry { std::string_view fn; u8 slot; };
    static const Entry kTable[] = {
        {"strlen", 1}, {"strnlen", 1},
        {"strdup", 1}, {"strndup", 1},
        {"strchr", 1}, {"strrchr", 1},
        {"strstr", 1}, {"strstr", 2},
        {"strcasestr", 1}, {"strcasestr", 2},
        {"strcmp", 1}, {"strcmp", 2},
        {"strncmp", 1}, {"strncmp", 2},
        {"strcasecmp", 1}, {"strcasecmp", 2},
        {"strncasecmp", 1}, {"strncasecmp", 2},
        {"strcpy", 1}, {"strcpy", 2},
        {"strncpy", 1}, {"strncpy", 2},
        {"stpcpy", 1}, {"stpcpy", 2},
        {"stpncpy", 1}, {"stpncpy", 2},
        {"strcat", 1}, {"strcat", 2},
        {"strncat", 1}, {"strncat", 2},
        {"strpbrk", 1}, {"strpbrk", 2},
        {"strspn", 1}, {"strspn", 2},
        {"strcspn", 1}, {"strcspn", 2},
        {"strtok", 1}, {"strtok", 2},
        {"strtok_r", 1}, {"strtok_r", 2},
        {"strsep", 2},
        {"index", 1}, {"rindex", 1},
        {"basename", 1}, {"dirname", 1},
        {"puts", 1}, {"fputs", 1}, {"perror", 1}, {"gets", 1},
        {"lstrlenA", 1}, {"lstrlenW", 1},
        {"OutputDebugStringA", 1}, {"OutputDebugStringW", 1},
        {"GetModuleHandleA", 1}, {"GetModuleHandleW", 1},
        {"LoadLibraryA", 1}, {"LoadLibraryW", 1},
        {"GetProcAddress", 2}, {"CreateFileA", 1}, {"CreateFileW", 1},
        {"DeleteFileA", 1}, {"DeleteFileW", 1},
        {"fopen", 1}, {"fopen", 2},
        {"freopen", 1}, {"freopen", 2},
        {"fdopen", 2},
        {"getenv", 1}, {"secure_getenv", 1},
        {"setenv", 1}, {"setenv", 2},
        {"unsetenv", 1}, {"putenv", 1},
        {"atoi", 1}, {"atol", 1}, {"atoll", 1}, {"atof", 1},
        {"strtol", 1}, {"strtoul", 1}, {"strtoll", 1}, {"strtoull", 1},
        {"strtod", 1}, {"strtof", 1}, {"strtold", 1},
        {"remove", 1}, {"rename", 1}, {"rename", 2},
        {"unlink", 1}, {"mkdir", 1}, {"rmdir", 1},
        {"chdir", 1}, {"access", 1}, {"chmod", 1}, {"chown", 1},
        {"stat", 1}, {"lstat", 1},
        {"open", 1}, {"system", 1},
    };
    for (const auto& e : kTable) {
        if (e.fn == name && e.slot == arg_idx_1) return true;
    }
    return false;
}

std::string_view c_type_name(IrType t) noexcept {
    switch (t) {
        case IrType::I1:  return "bool";
        case IrType::I8:  return "u8";
        case IrType::I16: return "u16";
        case IrType::I32: return "u32";
        case IrType::I64: return "u64";
        case IrType::F32: return "float";
        case IrType::F64: return "double";
    }
    return "?";
}

}  // namespace ember::detail
