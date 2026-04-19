#include <ember/decompile/emitter.hpp>

#include <array>
#include <cctype>
#include <cstddef>
#include <format>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <tuple>
#include <vector>

#include <ember/analysis/arity.hpp>
#include <ember/common/types.hpp>
#include <ember/disasm/x64_decoder.hpp>
#include <ember/ir/ssa.hpp>

namespace ember {

namespace {

// SsaKey and ssa_key() live in <ember/ir/ssa.hpp>.

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

[[nodiscard]] std::optional<u8> variadic_format_index(std::string_view n) noexcept {
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
[[nodiscard]] u8 count_printf_specifiers(std::string_view fmt) noexcept {
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
[[nodiscard]] std::optional<u8> libc_arity_by_name(std::string_view n) noexcept {
    static const std::pair<std::string_view, u8> kTable[] = {
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
        if (k == n) return v;
    }
    return std::nullopt;
}

// C operator precedence, scaled so "tighter binds" = higher value. Used to
// decide whether a sub-expression needs wrapping in parens. Only the handful
// of levels the emitter actually produces are enumerated; add more as new
// operator kinds start rendering.
enum class Prec : int {
    Stmt    = 0,
    LogOr   = 3,
    LogAnd  = 4,
    BitOr   = 5,
    BitXor  = 6,
    BitAnd  = 7,
    Eq      = 8,    // == !=
    Rel     = 9,    // < <= > >=
    Shift   = 10,   // << >>
    Add     = 11,   // + -
    Mul     = 12,   // * / %
    Unary   = 13,   // ! ~ unary- (T)x *x &x
    Primary = 15,   // ident, literal, call, t[i], foo()
};

[[nodiscard]] inline std::string
wrap_if_lt(std::string s, Prec own, int min_prec) {
    if (static_cast<int>(own) < min_prec) return "(" + std::move(s) + ")";
    return s;
}

// Libc/POSIX functions whose parameter at `arg_index_1based` is a
// NUL-terminated string. Used to back-propagate `char*` onto the caller's
// own arg slots. Positions listed are 1-based.
[[nodiscard]] bool libc_arg_is_charp(std::string_view name, u8 arg_idx_1) noexcept {
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

[[nodiscard]] std::string_view c_type_name(IrType t) noexcept {
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

struct Emitter {
    const IrFunction*                                fn = nullptr;
    const Binary*                                    binary = nullptr;
    const Annotations*                               annotations = nullptr;
    EmitOptions                                      options{};
    // Number of int-register args for the function being emitted. Set once
    // at the start of emit() from infer_sysv_arity() or the declared sig, and
    // used to name raw rdi/rsi/... reads as a1/a2/... when no annotation
    // overrides them.
    u8                                               self_arity = 0;
    std::map<SsaKey, const IrInst*>                  defs;
    std::map<SsaKey, std::pair<std::size_t, std::size_t>> def_pos;
    std::map<SsaKey, u32>                            uses;
    std::set<std::pair<std::size_t, std::size_t>>    hidden;
    mutable std::map<u64, std::optional<std::string>> string_cache;
    // Call sites whose return value flows straight into a Return(rax). The
    // Call statement is suppressed and its rendered expression is stashed in
    // `fold_return_expr`, keyed on the rax SSA key; the Return handler then
    // emits `return foo(args);` instead of `foo(args); return rax;`.
    std::set<std::pair<std::size_t, std::size_t>>    fold_call_positions;
    std::map<std::pair<std::size_t, std::size_t>, SsaKey> fold_call_ssa_key;
    mutable std::map<SsaKey, std::string>            fold_return_expr;
    // rax/xmm0 SSA key → bound local name for Call returns whose result is
    // read downstream. Makes `fopen(...); if (rax == 0)` render as
    // `u64 r_fopen = fopen(...); if (r_fopen == 0)`.
    std::map<SsaKey, std::string>                    call_return_names;
    std::map<std::pair<std::size_t, std::size_t>, SsaKey> bound_call_key;

    // Try to resolve an integer immediate as a pointer to a NUL-terminated
    // printable string in the binary image. Results are cached.
    [[nodiscard]] std::optional<std::string> try_string_at(u64 addr) const {
        if (!binary) return std::nullopt;
        auto it = string_cache.find(addr);
        if (it != string_cache.end()) return it->second;

        std::optional<std::string> result;
        auto span = binary->bytes_at(static_cast<addr_t>(addr));
        const std::size_t max_len = 512;
        if (!span.empty()) {
            std::string s;
            s.reserve(64);
            bool terminated = false;
            const std::size_t limit = std::min(span.size(), max_len);
            for (std::size_t i = 0; i < limit; ++i) {
                const auto c = static_cast<unsigned char>(span[i]);
                if (c == 0) { terminated = true; break; }
                // Accept printable ASCII + common whitespace escapes.
                if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') {
                    s.clear();
                    break;
                }
                if (c > 0x7e) {
                    s.clear();
                    break;
                }
                s.push_back(static_cast<char>(c));
            }
            if (terminated && s.size() >= 1) {
                result = std::move(s);
            }
        }
        string_cache.emplace(addr, result);
        return result;
    }

    // Cached per-target arity via infer_sysv_arity().
    mutable std::map<u64, u8> arity_cache;

    [[nodiscard]] u8 infer_arity(addr_t target) const {
        auto it = arity_cache.find(static_cast<u64>(target));
        if (it != arity_cache.end()) return it->second;
        const u8 a = binary ? infer_sysv_arity(*binary, target) : u8{6};
        arity_cache.emplace(static_cast<u64>(target), a);
        return a;
    }

    // Drop ELF `@GLIBC_*` / `@@GLIBC_*` version suffix that clutters import
    // names in pseudo-C (e.g. "puts@GLIBC_2.2.5" → "puts").
    [[nodiscard]] static std::string clean_import_name(std::string_view n) {
        auto pos = n.find('@');
        if (pos != std::string_view::npos) return std::string(n.substr(0, pos));
        return std::string(n);
    }

    // For `call <abs_target>`: if the target is a PLT stub, return the
    // import's name. Nullopt means "render as sub_XXXX".
    [[nodiscard]] std::optional<std::string>
    import_name_for_direct_call(addr_t target) const {
        if (!binary) return std::nullopt;
        if (const Symbol* s = binary->import_at_plt(target); s) {
            return clean_import_name(s->name);
        }
        return std::nullopt;
    }

    // Walk Assign copies until we hit something that's plausibly the
    // address of a string (an Imm, or a Reg). For an Imm, try to read the
    // NUL-terminated string at that address.
    [[nodiscard]] std::optional<std::string>
    resolve_string_value(const IrValue& v) const {
        IrValue cur = v;
        for (int step = 0; step < 8; ++step) {
            if (cur.kind == IrValueKind::Imm) {
                return try_string_at(static_cast<u64>(cur.imm));
            }
            const IrInst* d = def_of(cur);
            if (!d) return std::nullopt;
            if (d->op == IrOp::Assign && d->src_count >= 1) {
                cur = d->srcs[0];
                continue;
            }
            return std::nullopt;
        }
        return std::nullopt;
    }

    // Compute arity for a printf/scanf family call given its format-arg
    // index in `args`. Falls back to `format_index + 1` (emit format, drop
    // the rest) when the format isn't a literal string.
    [[nodiscard]] u8 variadic_arity(const std::vector<IrValue>& args,
                                    u8 format_index) const {
        if (format_index >= args.size()) return format_index;
        auto fmt = resolve_string_value(args[format_index]);
        if (!fmt) return static_cast<u8>(format_index + 1);
        return static_cast<u8>(format_index + 1 + count_printf_specifiers(*fmt));
    }

    // For `call.ind <expr>`: if `expr` traces back to a Load of a constant
    // address that matches a known GOT slot, return the import's name.
    [[nodiscard]] std::optional<std::string>
    import_name_for_indirect_call(const IrValue& v) const {
        if (!binary) return std::nullopt;
        const IrInst* d = def_stripped(v);
        if (!d || d->op != IrOp::Load || d->src_count < 1) return std::nullopt;

        IrValue addr_v = d->srcs[0];
        // Drill through Assign copies and also direct immediates.
        for (int step = 0; step < 8; ++step) {
            if (addr_v.kind == IrValueKind::Imm) break;
            const IrInst* d2 = def_of(addr_v);
            if (!d2) return std::nullopt;
            if (d2->op != IrOp::Assign || d2->src_count < 1) return std::nullopt;
            addr_v = d2->srcs[0];
        }
        if (addr_v.kind != IrValueKind::Imm) return std::nullopt;

        const addr_t got = static_cast<addr_t>(addr_v.imm);
        if (const Symbol* s = binary->import_at_got(got); s) {
            return clean_import_name(s->name);
        }
        return std::nullopt;
    }

    // SysV x86-64 calling convention: integer/pointer params consume the
    // int-reg sequence rdi, rsi, rdx, rcx, r8, r9 in order; float/double
    // params consume the xmm sequence xmm0..xmm7. The two sequences are
    // independent. Given a declared signature and a canonical register,
    // return the matching param's name (or null if nothing matches).
    [[nodiscard]] const std::string*
    sysv_param_for(const FunctionSig& sig, Reg r) const noexcept {
        static constexpr Reg kIntRegs[6] = {
            Reg::Rdi, Reg::Rsi, Reg::Rdx, Reg::Rcx, Reg::R8, Reg::R9,
        };
        static constexpr Reg kFpRegs[8] = {
            Reg::Xmm0, Reg::Xmm1, Reg::Xmm2, Reg::Xmm3,
            Reg::Xmm4, Reg::Xmm5, Reg::Xmm6, Reg::Xmm7,
        };
        const Reg canon = canonical_reg(r);
        std::size_t int_idx = 0;
        std::size_t fp_idx  = 0;
        for (const auto& p : sig.params) {
            const bool is_fp =
                p.type.find("double") != std::string::npos ||
                p.type.find("float")  != std::string::npos;
            if (is_fp) {
                if (fp_idx < 8 && kFpRegs[fp_idx] == canon) return &p.name;
                ++fp_idx;
            } else {
                if (int_idx < 6 && kIntRegs[int_idx] == canon) return &p.name;
                ++int_idx;
            }
        }
        return nullptr;
    }

    // If `r` is a SysV int-arg register and the current function actually
    // takes that arg (per annotations or inferred arity), return the param's
    // display name. Otherwise nullopt.
    [[nodiscard]] std::optional<std::string>
    arg_name_for_live_in(Reg r) const {
        if (annotations && fn) {
            if (const FunctionSig* sig = annotations->signature_for(fn->start); sig) {
                if (const std::string* nm = sysv_param_for(*sig, r); nm && !nm->empty()) {
                    return *nm;
                }
            }
        }
        static constexpr Reg kIntArgs[6] = {
            Reg::Rdi, Reg::Rsi, Reg::Rdx, Reg::Rcx, Reg::R8, Reg::R9,
        };
        const Reg canon = canonical_reg(r);
        for (u8 i = 0; i < 6 && i < self_arity; ++i) {
            if (kIntArgs[i] == canon) return std::format("a{}", i + 1);
        }
        return std::nullopt;
    }

    // Render a Reg IrValue's leaf name. Resolution order:
    //   1. A Call-return binding for this (canonical reg, version).
    //   2. Chase Assign aliases:
    //        - reg = reg              → keep chasing
    //        - reg = non-reg          → render the rvalue expression (this is
    //          what turns `r12` into `*(u64*)((a2 + 0x8))` when the compiler
    //          stashed a computed pointer into a callee-saved reg at prologue)
    //        - version 0 + arg-reg    → parameter name
    //   3. Raw register mnemonic.
    [[nodiscard]] std::string render_reg_leaf(Reg r, u32 version, int depth = 0) const {
        Reg cur_reg = r;
        u32 cur_ver = version;
        for (int hop = 0; hop < 8; ++hop) {
            SsaKey k{0, static_cast<u32>(canonical_reg(cur_reg)), cur_ver};
            if (auto it = call_return_names.find(k); it != call_return_names.end()) {
                return it->second;
            }
            if (cur_ver == 0) {
                if (auto n = arg_name_for_live_in(cur_reg)) return *n;
                break;
            }
            IrValue v{};
            v.kind = IrValueKind::Reg;
            v.reg = cur_reg;
            v.version = cur_ver;
            const IrInst* d = def_of(v);
            if (!d) break;
            if (d->op == IrOp::Assign && d->src_count >= 1) {
                const auto& src = d->srcs[0];
                if (src.kind == IrValueKind::Reg) {
                    cur_reg = src.reg;
                    cur_ver = src.version;
                    continue;
                }
                if (depth < 10) return expr(src, depth + 1);
                break;
            }
            // Phi-merged reg: if every incoming operand renders to the
            // same expression (common for `rax = phi(rax_v1, t17)` where
            // t17 traces back to the same call's return), emit that.
            if (d->op == IrOp::Phi && depth < 10 && !d->phi_operands.empty()) {
                std::string unified;
                bool all_match = true;
                for (const auto& op : d->phi_operands) {
                    auto opk = ssa_key(op);
                    if (opk && *opk == k) continue;  // self-reference
                    const std::string s = expr(op, depth + 1);
                    if (s.empty()) { all_match = false; break; }
                    if (unified.empty()) unified = s;
                    else if (s != unified) { all_match = false; break; }
                }
                if (all_match && !unified.empty()) return unified;
            }
            break;
        }
        // Phi/merged value with divergent incoming edges or a non-inlinable
        // producer: render a stable name rather than a raw register so the
        // output never mentions architectural names like `rax`, `rdx`.
        if (version > 0) {
            return std::format("{}_{}", reg_name(r), version);
        }
        return std::string(reg_name(r));
    }

    // For a raw code address, pick a display name. Priority (highest first):
    //   1. User rename (from the annotations sidecar).
    //   2. Named defined function symbol from the binary itself.
    //   3. Fallback `sub_<hex>`.
    [[nodiscard]] std::string function_display_name(addr_t target) const {
        if (annotations) {
            if (const std::string* n = annotations->name_for(target); n) return *n;
        }
        if (binary) {
            if (const Symbol* s = binary->defined_object_at(target); s) {
                if (s->kind == SymbolKind::Function && s->addr == target &&
                    !s->name.empty()) {
                    return s->name;
                }
            }
        }
        return std::format("sub_{:x}", target);
    }

    [[nodiscard]] static std::string escape_string(const std::string& s) {
        std::string out;
        out.reserve(s.size() + 2);
        out += '"';
        for (char c : s) {
            switch (c) {
                case '\\': out += "\\\\"; break;
                case '"':  out += "\\\""; break;
                case '\n': out += "\\n";  break;
                case '\r': out += "\\r";  break;
                case '\t': out += "\\t";  break;
                default:   out += c;      break;
            }
        }
        out += '"';
        return out;
    }

    // An arg reg is "stale" if the caller never deliberately set it before the
    // call: either it's still the function's live-in (version 0) and no user
    // signature claims it, or its most recent def is a Clobber from a prior
    // call. Both cases look like `strlen(... rsi, rdx, r8, r9)` noise.
    [[nodiscard]] bool is_stale_arg_reg(const IrValue& a) const {
        if (a.kind != IrValueKind::Reg) return false;
        if (a.version == 0) {
            if (annotations && fn) {
                if (const FunctionSig* sig = annotations->signature_for(fn->start); sig) {
                    if (sysv_param_for(*sig, a.reg)) return false;
                }
            }
            return true;
        }
        if (const IrInst* d = def_of(a); d && d->op == IrOp::Clobber) return true;
        return false;
    }

    // Arity for an import by name — user signature at its PLT address beats
    // the baked-in libc table.
    [[nodiscard]] std::optional<u8>
    import_arity(addr_t plt_addr, std::string_view name) const {
        if (annotations) {
            if (const FunctionSig* sig = annotations->signature_for(plt_addr); sig) {
                return static_cast<u8>(sig->params.size());
            }
        }
        return libc_arity_by_name(name);
    }

    [[nodiscard]] static bool is_call_arg_barrier(const IrInst& inst) noexcept {
        return inst.op == IrOp::Intrinsic &&
               (inst.name == "call.args.1" || inst.name == "call.args.2");
    }

    [[nodiscard]] static bool is_callee_saved(Reg r) noexcept {
        const Reg c = canonical_reg(r);
        return c == Reg::Rbx || c == Reg::Rbp ||
               c == Reg::R12 || c == Reg::R13 ||
               c == Reg::R14 || c == Reg::R15;
    }

    void analyze(const IrFunction& f) {
        fn = &f;
        for (std::size_t bi = 0; bi < f.blocks.size(); ++bi) {
            const auto& bb = f.blocks[bi];
            for (std::size_t ii = 0; ii < bb.insts.size(); ++ii) {
                const auto& inst = bb.insts[ii];
                if (auto k = ssa_key(inst.dst); k) {
                    defs[*k] = &inst;
                    def_pos[*k] = {bi, ii};
                }
                // Skip uses from call.args.* intrinsics — they get absorbed into the
                // following Call, so they shouldn't keep their operand-feeding assignments alive.
                if (is_call_arg_barrier(inst)) continue;
                if (inst.op == IrOp::Phi) {
                    for (const auto& op : inst.phi_operands)
                        if (auto k = ssa_key(op); k) uses[*k]++;
                } else {
                    for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i)
                        if (auto k = ssa_key(inst.srcs[i]); k) uses[*k]++;
                }
            }
        }
        analyze_abi_noise();
    }

    // Self-arg slots (a1..a6) known to flow into a libc char* parameter.
    // Populated by infer_charp_args(); consumed by the header builder.
    std::array<bool, 6> charp_arg = {false, false, false, false, false, false};

    // Trace `v` back through Assign copies and trivial phis to a version-0
    // SysV int-arg register (rdi..r9). Returns the 0-based slot (0..5), or
    // nullopt if the value isn't live-in from a self arg.
    [[nodiscard]] std::optional<u8>
    trace_to_self_arg_slot(const IrValue& v, int depth = 0) const {
        if (depth > 8) return std::nullopt;
        static constexpr Reg kArgs[6] = {
            Reg::Rdi, Reg::Rsi, Reg::Rdx, Reg::Rcx, Reg::R8, Reg::R9,
        };
        IrValue cur = v;
        for (int hop = 0; hop < 8; ++hop) {
            if (cur.kind != IrValueKind::Reg) return std::nullopt;
            const Reg canon = canonical_reg(cur.reg);
            if (cur.version == 0) {
                for (u8 i = 0; i < 6; ++i) if (kArgs[i] == canon) return i;
                return std::nullopt;
            }
            const IrInst* d = def_of(cur);
            if (!d) return std::nullopt;
            if (d->op == IrOp::Assign && d->src_count == 1) {
                cur = d->srcs[0];
                continue;
            }
            if (d->op == IrOp::Phi && !d->phi_operands.empty()) {
                std::optional<u8> common;
                for (const auto& op : d->phi_operands) {
                    auto opk = ssa_key(op);
                    if (opk && *opk == ssa_key(cur)) continue;  // self-ref
                    auto slot = trace_to_self_arg_slot(op, depth + 1);
                    if (!slot) return std::nullopt;
                    if (!common) common = *slot;
                    else if (*common != *slot) return std::nullopt;
                }
                return common;
            }
            return std::nullopt;
        }
        return std::nullopt;
    }

    // For each call-to-libc in the body, consult the call.args.1/2 packing
    // to recover per-arg IrValues; if an arg is a self live-in reg and the
    // callee takes a `char*` at that position, tag the caller's own slot.
    void infer_charp_args() {
        if (!binary) return;
        for (const auto& bb : fn->blocks) {
            std::vector<IrValue> args;
            args.reserve(6);
            for (const auto& inst : bb.insts) {
                if (inst.op == IrOp::Intrinsic && inst.name == "call.args.1") {
                    args.clear();
                    for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i)
                        args.push_back(inst.srcs[i]);
                    continue;
                }
                if (inst.op == IrOp::Intrinsic && inst.name == "call.args.2") {
                    for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i)
                        args.push_back(inst.srcs[i]);
                    continue;
                }
                if (inst.op == IrOp::Call) {
                    const Symbol* s = binary->import_at_plt(inst.target1);
                    if (!s) { args.clear(); continue; }
                    const std::string callee = clean_import_name(s->name);
                    for (std::size_t i = 0; i < args.size(); ++i) {
                        if (!libc_arg_is_charp(callee, static_cast<u8>(i + 1))) continue;
                        auto slot = trace_to_self_arg_slot(args[i]);
                        if (slot && *slot < charp_arg.size()) charp_arg[*slot] = true;
                    }
                    args.clear();
                    continue;
                }
                // Any non-arg, non-Clobber inst between the packing and the
                // Call invalidates the accumulator.
                if (inst.op != IrOp::Clobber &&
                    !is_call_arg_barrier(inst)) {
                    // Nothing: but stash in case Call follows after pure
                    // side-effect-free compute (common with lea).
                }
            }
        }
    }

    // Raise self_arity when the body reads a live-in SysV int-arg register
    // (rdi..r9) that the inferred arity didn't cover. Without this, raw
    // register names leak into the emitted C as e.g. `fputs(rdx, stdout)`.
    // Call only when the caller hasn't pinned an explicit signature.
    void bump_arity_from_body_reads() {
        static constexpr Reg kIntArgs[6] = {
            Reg::Rdi, Reg::Rsi, Reg::Rdx, Reg::Rcx, Reg::R8, Reg::R9,
        };
        u8 need = self_arity;
        auto check = [&](const IrValue& v) {
            if (v.kind != IrValueKind::Reg) return;
            if (v.version != 0) return;
            const Reg canon = canonical_reg(v.reg);
            for (u8 i = 0; i < 6; ++i) {
                if (kIntArgs[i] == canon) {
                    if (i + 1 > need) need = static_cast<u8>(i + 1);
                    return;
                }
            }
        };
        for (std::size_t bi = 0; bi < fn->blocks.size(); ++bi) {
            const auto& bb = fn->blocks[bi];
            for (std::size_t ii = 0; ii < bb.insts.size(); ++ii) {
                if (hidden.contains({bi, ii})) continue;
                const auto& inst = bb.insts[ii];
                // call.args.* packs live-in regs as trailing placeholders the
                // callee may never consume; Clobbers are ABI markers; Phis
                // conservatively name every arg reg at join points regardless
                // of whether anything downstream reads it. None of these
                // represents a real body read.
                if (is_call_arg_barrier(inst)) continue;
                if (inst.op == IrOp::Clobber)  continue;
                if (inst.op == IrOp::Phi)      continue;
                for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i)
                    check(inst.srcs[i]);
            }
        }
        self_arity = need;
    }

    // Find Return regions whose value is rax coming directly from a call's
    // Clobber — record the Call position and the rax SSA key so emit_block
    // suppresses the statement and the Return handler folds the expression.
    void analyze_return_folds(const Region& r) {
        for (const auto& c : r.children) analyze_return_folds(*c);
        if (r.kind != RegionKind::Return) return;
        const IrValue& cond = r.condition;
        if (cond.kind != IrValueKind::Reg) return;
        if (canonical_reg(cond.reg) != Reg::Rax) return;
        auto cond_key = ssa_key(cond);
        if (!cond_key) return;
        const IrInst* def = def_of(cond);
        if (!def || def->op != IrOp::Clobber) return;
        auto pos_it = def_pos.find(*cond_key);
        if (pos_it == def_pos.end()) return;
        auto [bi, ii] = pos_it->second;
        const auto& bb = fn->blocks[bi];
        // Walk back past the clobber sequence the lifter emits after a call.
        while (ii > 0) {
            --ii;
            const IrInst& prev = bb.insts[ii];
            if (prev.op == IrOp::Clobber || prev.op == IrOp::Nop) continue;
            if (prev.op == IrOp::Call || prev.op == IrOp::CallIndirect) {
                fold_call_positions.insert({bi, ii});
                fold_call_ssa_key.emplace(std::pair{bi, ii}, *cond_key);
            }
            return;  // first non-clobber: either the Call we want, or abort
        }
    }

    // For each Call with a downstream-used rax return, pick a display name
    // and record (call position → rax SsaKey). `analyze_return_folds` must
    // run first so calls whose return folds straight into a Return are
    // skipped here.
    void bind_call_returns() {
        std::set<std::string> used;
        for (std::size_t bi = 0; bi < fn->blocks.size(); ++bi) {
            const auto& bb = fn->blocks[bi];
            for (std::size_t ii = 0; ii < bb.insts.size(); ++ii) {
                const auto& inst = bb.insts[ii];
                if (inst.op != IrOp::Call && inst.op != IrOp::CallIndirect) continue;
                if (fold_call_positions.contains({bi, ii})) continue;

                // The rax Clobber for this call is the next inst (Clobbers
                // run immediately post-Call in the lifter's output).
                std::optional<SsaKey> rax_key;
                for (std::size_t jj = ii + 1; jj < bb.insts.size(); ++jj) {
                    const auto& c = bb.insts[jj];
                    if (c.op != IrOp::Clobber) break;
                    if (c.dst.kind != IrValueKind::Reg) continue;
                    if (canonical_reg(c.dst.reg) != Reg::Rax) continue;
                    rax_key = ssa_key(c.dst);
                    break;
                }
                if (!rax_key) continue;
                // Always bind a name for the rax clobber when the call wasn't
                // folded into a Return. Reads that happen only through
                // structured-region conditions (e.g. `return rax;`) don't
                // appear in IR srcs and so can't be counted up-front; the
                // dead-decl pass at the end strips any binding nothing ended
                // up referencing.

                std::string base = callee_display_short(inst);
                std::string name = "r_" + base;
                for (int n = 2; used.contains(name); ++n) {
                    name = std::format("r_{}_{}", base, n);
                }
                used.insert(name);
                call_return_names.emplace(*rax_key, name);
                bound_call_key.emplace(std::pair{bi, ii}, *rax_key);
            }
        }
    }

    [[nodiscard]] u32 use_count_by_key(const SsaKey& k) const {
        auto it = uses.find(k);
        return it != uses.end() ? it->second : 0u;
    }

    [[nodiscard]] u32 count_uses_with_call_args(const SsaKey& k) const {
        u32 n = 0;
        for (const auto& bb : fn->blocks) {
            for (const auto& inst : bb.insts) {
                if (inst.op == IrOp::Phi) {
                    for (const auto& op : inst.phi_operands) {
                        if (auto ok = ssa_key(op); ok && *ok == k) ++n;
                    }
                } else {
                    for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
                        if (auto ok = ssa_key(inst.srcs[i]); ok && *ok == k) ++n;
                    }
                }
            }
        }
        return n;
    }

    // A short identifier derived from the callee's display name, sanitized
    // to valid C identifier chars.
    [[nodiscard]] std::string callee_display_short(const IrInst& call_inst) const {
        std::string raw;
        if (call_inst.op == IrOp::Call) {
            if (auto n = import_name_for_direct_call(call_inst.target1)) raw = *n;
            else raw = std::format("sub_{:x}", call_inst.target1);
        } else if (call_inst.op == IrOp::CallIndirect && call_inst.src_count >= 1) {
            if (auto n = import_name_for_indirect_call(call_inst.srcs[0])) raw = *n;
            else raw = "ind";
        } else {
            raw = "call";
        }
        std::string out;
        out.reserve(raw.size());
        for (char c : raw) {
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') || c == '_') {
                out += c;
            }
        }
        return out.empty() ? std::string("call") : out;
    }

    // Detect prologue/epilogue noise: saves/restores of callee-saved regs, rsp/rbp
    // frame manipulation, plus any temps whose uses are entirely within hidden insts.
    void analyze_abi_noise() {
        // Pass 1: direct pattern matches.
        for (std::size_t bi = 0; bi < fn->blocks.size(); ++bi) {
            const auto& bb = fn->blocks[bi];
            for (std::size_t ii = 0; ii < bb.insts.size(); ++ii) {
                if (is_abi_noise(bb.insts[ii])) hidden.insert({bi, ii});
            }
        }
        // Pass 2: propagate. A pure temp whose every use is in a hidden inst is itself dead.
        bool changed = true;
        int guard = 0;
        while (changed && guard++ < 16) {
            changed = false;
            for (std::size_t bi = 0; bi < fn->blocks.size(); ++bi) {
                const auto& bb = fn->blocks[bi];
                for (std::size_t ii = 0; ii < bb.insts.size(); ++ii) {
                    if (hidden.contains({bi, ii})) continue;
                    const auto& inst = bb.insts[ii];
                    if (inst.dst.kind != IrValueKind::Temp) continue;
                    if (!inlinable_op(inst.op)) continue;
                    auto target_key = ssa_key(inst.dst);
                    if (!target_key) continue;
                    bool has_use = false, all_hidden = true;
                    for (std::size_t bj = 0; bj < fn->blocks.size() && all_hidden; ++bj) {
                        const auto& bb2 = fn->blocks[bj];
                        for (std::size_t ij = 0; ij < bb2.insts.size() && all_hidden; ++ij) {
                            const auto& inst2 = bb2.insts[ij];
                            auto check = [&](const IrValue& v) {
                                if (ssa_key(v) == target_key) {
                                    has_use = true;
                                    if (!hidden.contains({bj, ij}) && !is_call_arg_barrier(inst2))
                                        all_hidden = false;
                                }
                            };
                            if (inst2.op == IrOp::Phi) {
                                for (const auto& op : inst2.phi_operands) check(op);
                            } else {
                                for (u8 k = 0; k < inst2.src_count && k < inst2.srcs.size(); ++k)
                                    check(inst2.srcs[k]);
                            }
                        }
                    }
                    if (has_use && all_hidden) {
                        hidden.insert({bi, ii});
                        changed = true;
                    }
                }
            }
        }
    }

    [[nodiscard]] static bool is_canary_load(const IrInst& inst) noexcept {
        return inst.op == IrOp::Load && inst.segment == Reg::Fs &&
               inst.src_count >= 1 &&
               inst.srcs[0].kind == IrValueKind::Imm &&
               inst.srcs[0].imm == 0x28;
    }

    // Walk Assigns back to a real producer and return its def (or null).
    [[nodiscard]] const IrInst* def_through_assigns(const IrValue& v) const {
        const IrInst* d = def_of(v);
        while (d && d->op == IrOp::Assign && d->src_count == 1) {
            d = def_of(d->srcs[0]);
        }
        return d;
    }

    [[nodiscard]] bool traces_to_canary_load(const IrValue& v) const {
        if (const IrInst* d = def_through_assigns(v); d) return is_canary_load(*d);
        return false;
    }

    [[nodiscard]] bool is_abi_noise(const IrInst& inst) const {
        // rsp/rbp = <anything>  → frame manipulation
        if (inst.op == IrOp::Assign && inst.dst.kind == IrValueKind::Reg) {
            const Reg c = canonical_reg(inst.dst.reg);
            if (c == Reg::Rsp || c == Reg::Rbp) return true;
        }
        // Prologue canary: Store of fs:[0x28] into a stack slot.
        if (inst.op == IrOp::Store && inst.src_count >= 2) {
            if (stack_offset(inst.srcs[0]).has_value() &&
                traces_to_canary_load(inst.srcs[1])) {
                return true;
            }
        }
        // Store of a live-in callee-saved reg into a stack slot → prologue save
        if (inst.op == IrOp::Store && inst.src_count >= 2) {
            const auto& val = inst.srcs[1];
            if (val.kind == IrValueKind::Reg && val.version == 0 &&
                is_callee_saved(val.reg) && stack_offset(inst.srcs[0]).has_value())
                return true;
        }
        // callee-saved = <Load [stack]>  → epilogue restore
        if (inst.op == IrOp::Assign && inst.dst.kind == IrValueKind::Reg &&
            is_callee_saved(inst.dst.reg) && inst.src_count >= 1) {
            const IrInst* src_def = def_of(inst.srcs[0]);
            while (src_def && src_def->op == IrOp::Assign && src_def->src_count == 1)
                src_def = def_of(src_def->srcs[0]);
            if (src_def && src_def->op == IrOp::Load && src_def->src_count >= 1 &&
                stack_offset(src_def->srcs[0]).has_value())
                return true;
        }
        return false;
    }

    // The canary check is a compare/sub/xor whose operands are:
    //   - a Load from fs:[0x28]  AND
    //   - a Load from a stack slot (the saved cookie).
    [[nodiscard]] bool is_canary_compare_inst(const IrInst& inst) const {
        if (inst.src_count < 2) return false;
        switch (inst.op) {
            case IrOp::Sub: case IrOp::Xor:
            case IrOp::CmpEq: case IrOp::CmpNe:
                break;
            default:
                return false;
        }
        const IrInst* a = def_through_assigns(inst.srcs[0]);
        const IrInst* b = def_through_assigns(inst.srcs[1]);
        if (!a || !b) return false;
        auto is_stack_load = [&](const IrInst* d) {
            return d && d->op == IrOp::Load && d->src_count >= 1 &&
                   stack_offset(d->srcs[0]).has_value() && d->segment == Reg::None;
        };
        auto is_fs28 = [&](const IrInst* d) { return d && is_canary_load(*d); };
        return (is_stack_load(a) && is_fs28(b)) ||
               (is_stack_load(b) && is_fs28(a));
    }

    // Chase a branch condition back until we hit a Sub/Xor/CmpEq/CmpNe between
    // the canary cookie and fs:[0x28]. Handles the typical `zf = cmp.eq(x,0)`
    // followed by `not` wrapper that x86 condition codes produce.
    [[nodiscard]] bool is_canary_condition(const IrValue& cond) const {
        IrValue cur = cond;
        for (int step = 0; step < 10; ++step) {
            const IrInst* d = def_of(cur);
            if (!d) return false;
            if (is_canary_compare_inst(*d)) return true;
            // Follow Assign, Not, and Cmp chains.
            if (d->op == IrOp::Assign && d->src_count >= 1) { cur = d->srcs[0]; continue; }
            if (d->op == IrOp::Not && d->src_count >= 1)    { cur = d->srcs[0]; continue; }
            if ((d->op == IrOp::CmpEq || d->op == IrOp::CmpNe) && d->src_count >= 1) {
                // Compare against a constant (`cmp.eq(x, 0)` / zf). Peek through
                // to x and try again — the real canary compare is one step up.
                if (d->src_count >= 2 &&
                    d->srcs[1].kind == IrValueKind::Imm && d->srcs[1].imm == 0) {
                    cur = d->srcs[0];
                    continue;
                }
                return false;
            }
            return false;
        }
        return false;
    }

    [[nodiscard]] bool region_calls_stack_chk_fail(const Region& r) const {
        // Find a Block/Seq whose body contains a Call to __stack_chk_fail.
        auto block_matches = [&](addr_t block_addr) {
            auto it = fn->block_at.find(block_addr);
            if (it == fn->block_at.end()) return false;
            const auto& bb = fn->blocks[it->second];
            for (const auto& inst : bb.insts) {
                if (inst.op != IrOp::Call) continue;
                if (!binary) continue;
                if (const Symbol* s = binary->import_at_plt(inst.target1); s) {
                    if (clean_import_name(s->name) == "__stack_chk_fail") return true;
                }
            }
            return false;
        };
        if (r.kind == RegionKind::Block) return block_matches(r.block_start);
        for (const auto& c : r.children) {
            if (c && region_calls_stack_chk_fail(*c)) return true;
        }
        return false;
    }

    // Rewrite If/IfElse regions whose condition is a canary check: replace the
    // region with its non-fail branch so the canary guard vanishes entirely.
    void suppress_canary_regions(Region& r) const {
        for (auto& c : r.children) {
            if (c) suppress_canary_regions(*c);
        }
        if (r.kind != RegionKind::IfThen && r.kind != RegionKind::IfElse) return;
        if (!is_canary_condition(r.condition)) return;

        const bool has_else = r.kind == RegionKind::IfElse;
        auto* then_branch = r.children.empty() ? nullptr : r.children[0].get();
        auto* else_branch = (has_else && r.children.size() >= 2) ? r.children[1].get() : nullptr;

        const bool then_fails = then_branch && region_calls_stack_chk_fail(*then_branch);
        const bool else_fails = else_branch && region_calls_stack_chk_fail(*else_branch);
        if (!then_fails && !else_fails) return;

        // Pull the surviving branch up; if neither survives, collapse to Empty.
        std::unique_ptr<Region> keep;
        if (then_fails && else_branch) keep = std::move(r.children[1]);
        else if (else_fails && !r.children.empty()) keep = std::move(r.children[0]);

        if (keep) {
            r = std::move(*keep);
        } else {
            r.kind = RegionKind::Empty;
            r.children.clear();
            r.condition = {};
        }
    }

    [[nodiscard]] const IrInst* def_of(const IrValue& v) const {
        auto k = ssa_key(v);
        if (!k) return nullptr;
        auto it = defs.find(*k);
        return it != defs.end() ? it->second : nullptr;
    }

    [[nodiscard]] u32 use_count(const IrValue& v) const {
        auto k = ssa_key(v);
        if (!k) return 0;
        auto it = uses.find(*k);
        return it != uses.end() ? it->second : 0u;
    }

    // Uses that actually survive into emitted output: skip hidden insts
    // (ABI noise), call.args barriers, AND phi instructions (phis aren't
    // emitted as statements, so their operand reads don't count toward
    // whether we need to materialize a local). A temp with visible_use_count
    // <= 1 can be inlined / its declaration dropped.
    [[nodiscard]] u32 visible_use_count(const IrValue& v) const {
        auto key = ssa_key(v);
        if (!key) return 0u;
        u32 n = 0;
        for (std::size_t bi = 0; bi < fn->blocks.size(); ++bi) {
            const auto& bb = fn->blocks[bi];
            for (std::size_t ii = 0; ii < bb.insts.size(); ++ii) {
                if (hidden.contains({bi, ii})) continue;
                const auto& inst = bb.insts[ii];
                if (is_call_arg_barrier(inst)) continue;
                if (inst.op == IrOp::Phi) continue;
                for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i)
                    if (auto ok = ssa_key(inst.srcs[i]); ok && *ok == *key) ++n;
            }
        }
        return n;
    }

    [[nodiscard]] static bool inlinable_op(IrOp op) noexcept {
        switch (op) {
            case IrOp::Load:
            case IrOp::Assign:
            case IrOp::Add: case IrOp::Sub: case IrOp::Mul:
            case IrOp::And: case IrOp::Or:  case IrOp::Xor:
            case IrOp::Neg: case IrOp::Not:
            case IrOp::Shl: case IrOp::Lshr: case IrOp::Ashr:
            case IrOp::CmpEq: case IrOp::CmpNe:
            case IrOp::CmpSlt: case IrOp::CmpSle:
            case IrOp::CmpSgt: case IrOp::CmpSge:
            case IrOp::CmpUlt: case IrOp::CmpUle:
            case IrOp::CmpUgt: case IrOp::CmpUge:
            case IrOp::ZExt:  case IrOp::SExt:  case IrOp::Trunc:
            case IrOp::AddCarry:    case IrOp::SubBorrow:
            case IrOp::AddOverflow: case IrOp::SubOverflow:
                return true;
            default:
                return false;
        }
    }

    [[nodiscard]] bool should_inline(const IrValue& v) const {
        if (v.kind != IrValueKind::Temp) return false;
        const auto* d = def_of(v);
        if (!d) return false;
        if (!inlinable_op(d->op)) return false;
        if (visible_use_count(v) > 1) return false;
        return true;
    }

    // Trace a value back through Add/Sub/Assign chains to see if it's rsp/rbp-relative.
    [[nodiscard]] std::optional<i64> stack_offset(const IrValue& v, int depth = 0) const {
        if (depth > 16) return std::nullopt;
        if (v.kind == IrValueKind::Reg) {
            const Reg canon = canonical_reg(v.reg);
            if (canon == Reg::Rsp || canon == Reg::Rbp) return 0;
            return std::nullopt;
        }
        if (v.kind != IrValueKind::Temp) return std::nullopt;
        const auto* d = def_of(v);
        if (!d) return std::nullopt;
        switch (d->op) {
            case IrOp::Assign:
                return d->src_count >= 1
                    ? stack_offset(d->srcs[0], depth + 1)
                    : std::nullopt;
            case IrOp::Add: {
                if (d->src_count < 2) return std::nullopt;
                auto base = stack_offset(d->srcs[0], depth + 1);
                if (base && d->srcs[1].kind == IrValueKind::Imm) {
                    return *base + d->srcs[1].imm;
                }
                auto base2 = stack_offset(d->srcs[1], depth + 1);
                if (base2 && d->srcs[0].kind == IrValueKind::Imm) {
                    return *base2 + d->srcs[0].imm;
                }
                return std::nullopt;
            }
            case IrOp::Sub: {
                if (d->src_count < 2) return std::nullopt;
                auto base = stack_offset(d->srcs[0], depth + 1);
                if (base && d->srcs[1].kind == IrValueKind::Imm) {
                    return *base - d->srcs[1].imm;
                }
                return std::nullopt;
            }
            default:
                return std::nullopt;
        }
    }

    [[nodiscard]] static std::string stack_name(i64 off) {
        if (off < 0) {
            return std::format("local_{:x}", static_cast<u64>(-off));
        }
        if (off == 0) return "stack_top";
        return std::format("arg_{:x}", static_cast<u64>(off));
    }

    [[nodiscard]] std::string format_imm(const IrValue& v) const {
        // If the immediate points into the binary and resolves to a NUL-terminated
        // printable string, render as a C string literal.
        if (binary && v.imm > 0 && static_cast<u64>(v.imm) >= 0x100) {
            if (auto s = try_string_at(static_cast<u64>(v.imm)); s) {
                return escape_string(*s);
            }
        }
        // Small single-digit ints read much better as decimal; larger values
        // are generally addresses, masks, or byte counts where hex carries
        // information.
        if (v.imm >= 0 && v.imm <= 9) return std::format("{}", v.imm);
        if (v.imm < 0 && v.imm >= -9) return std::format("{}", v.imm);
        if (v.imm < 0) {
            const u64 abs_v = static_cast<u64>(0) - static_cast<u64>(v.imm);
            return std::format("-{:#x}", abs_v);
        }
        return std::format("{:#x}", static_cast<u64>(v.imm));
    }

    [[nodiscard]] std::string expr(const IrValue& v, int depth = 0,
                                   int min_prec = 0) const;
    [[nodiscard]] std::string expand(const IrInst& d, int depth,
                                     int min_prec = 0) const;

    // Try to resolve an address IrValue to a concrete immediate address,
    // drilling through single-assign copies. Returns nullopt for any
    // non-constant address.
    [[nodiscard]] std::optional<i64>
    try_resolve_imm_addr(const IrValue& v) const {
        if (v.kind == IrValueKind::Imm) return v.imm;
        const IrInst* d = def_stripped(v);
        if (d && d->op == IrOp::Assign && d->src_count == 1 &&
            d->srcs[0].kind == IrValueKind::Imm) {
            return d->srcs[0].imm;
        }
        return std::nullopt;
    }

    // If `addr` resolves to an absolute address inside a named global
    // object, render the access in terms of that symbol's name. Covers
    // exact-match (→ `name`), symbol-start cast mismatch (→ `*(T*)&name`),
    // and offsets (→ `*(T*)(&name + off)`). Returns nullopt when no global
    // matches.
    [[nodiscard]] std::optional<std::string>
    render_global_mem(const IrValue& addr, IrType t) const {
        if (!binary) return std::nullopt;
        auto imm = try_resolve_imm_addr(addr);
        if (!imm) return std::nullopt;
        const addr_t a = static_cast<addr_t>(*imm);
        const Symbol* s = binary->defined_object_at(a);
        if (!s || s->kind != SymbolKind::Object) return std::nullopt;
        if (s->name.empty()) return std::nullopt;

        const unsigned t_bytes = type_bits(t) / 8;
        const i64 off = static_cast<i64>(a) - static_cast<i64>(s->addr);

        if (off == 0 && s->size == t_bytes) {
            return s->name;
        }
        if (off == 0) {
            return std::format("*({}*)&{}", c_type_name(t), s->name);
        }
        return std::format("*({}*)(&{} + {:#x})",
                           c_type_name(t), s->name,
                           static_cast<u64>(off));
    }

    // Chase Assigns/Imm to resolve a value to a constant integer, if one exists.
    [[nodiscard]] std::optional<i64> resolve_imm(const IrValue& v) const {
        if (v.kind == IrValueKind::Imm) return v.imm;
        IrValue cur = v;
        for (int hop = 0; hop < 8; ++hop) {
            const IrInst* d = def_of(cur);
            if (!d || d->op != IrOp::Assign || d->src_count < 1) return std::nullopt;
            if (d->srcs[0].kind == IrValueKind::Imm) return d->srcs[0].imm;
            cur = d->srcs[0];
        }
        return std::nullopt;
    }

    // Pointer-indexing fold: `*(u64*)(base)` and `*(u64*)(base + 8*N)` render
    // as `base[N]` when base isn't stack- or global-relative. Restricted to
    // u64 loads — that's the common argv/table-of-pointers pattern and the
    // width the reader expects. Smaller loads keep their `*(T*)(addr)` form
    // so struct-field accesses stay semantically honest.
    [[nodiscard]] std::optional<std::string>
    try_render_array_index(const IrValue& addr, IrType t) const {
        if (t != IrType::I64) return std::nullopt;
        IrValue base = addr;
        i64     off  = 0;
        if (const IrInst* d = def_stripped(addr);
            d && d->op == IrOp::Add && d->src_count >= 2) {
            if (auto r = resolve_imm(d->srcs[1])) {
                base = d->srcs[0];
                off  = *r;
            } else if (auto l = resolve_imm(d->srcs[0])) {
                base = d->srcs[1];
                off  = *l;
            } else {
                return std::nullopt;
            }
        }
        if (off < 0) return std::nullopt;
        if ((off & 0x7) != 0) return std::nullopt;
        if (stack_offset(base).has_value()) return std::nullopt;
        if (base.kind != IrValueKind::Reg && base.kind != IrValueKind::Temp) {
            return std::nullopt;
        }
        return std::format("{}[{}]", expr(base), off >> 3);
    }

    [[nodiscard]] std::string format_mem(const IrValue& addr, IrType t, Reg seg) const {
        if (seg == Reg::None) {
            if (auto off = stack_offset(addr); off) {
                return stack_name(*off);
            }
            if (auto g = render_global_mem(addr, t); g) {
                return *g;
            }
            if (auto s = try_render_array_index(addr, t); s) {
                return *s;
            }
            return std::format("*({}*)({})", c_type_name(t), expr(addr));
        }
        return std::format("*({}*){}:[{}]",
                           c_type_name(t), reg_name(seg), expr(addr));
    }

    [[nodiscard]] std::string format_binop(const IrInst& d, std::string_view op,
                                            int depth, int min_prec,
                                            Prec self_prec,
                                            bool commutative) const {
        const int p = static_cast<int>(self_prec);
        // Left operand can share our precedence (left-assoc). Right operand
        // of a non-commutative op must bind strictly tighter to avoid
        // reassociation — e.g. `a - (b - c)` must stay parenthesized.
        std::string L = expr(d.srcs[0], depth, p);
        std::string R = expr(d.srcs[1], depth, commutative ? p : p + 1);
        std::string result = std::format("{} {} {}", L, op, R);
        return wrap_if_lt(std::move(result), self_prec, min_prec);
    }

    [[nodiscard]] std::string format_stmt(const IrInst& inst) const;
    [[nodiscard]] std::string format_store(const IrInst& inst) const;

    void emit_region(const Region& r, int depth, std::string& out) const;
    void emit_block(addr_t block_addr, int depth, std::string& out) const;

    // ===== Flag-pattern simplification =====
    // Maps compiler idioms from CMP/SUB + Jcc into direct C compare expressions.
    //   zf from sub(a,b)            → a == b
    //   !zf                         → a != b
    //   cf from sub(a,b)            → a < b   (unsigned)
    //   !cf                         → a >= b  (unsigned)
    //   cf | zf                     → a <= b  (unsigned)
    //   !zf & !cf                   → a > b   (unsigned)
    //   sf ^ of (same sub)          → a < b   (signed)
    //   !(sf ^ of)                  → a >= b  (signed)
    //   zf | (sf ^ of)              → a <= b  (signed)
    //   !zf & !(sf ^ of)            → a > b   (signed)

    struct SubOps { IrValue a; IrValue b; };

    [[nodiscard]] const IrInst* def_stripped(const IrValue& v) const noexcept {
        const IrInst* d = def_of(v);
        while (d && d->op == IrOp::Assign && d->src_count == 1) {
            const IrInst* n = def_of(d->srcs[0]);
            if (!n) return d;
            d = n;
        }
        return d;
    }

    [[nodiscard]] bool same_ssa(const IrValue& a, const IrValue& b) const noexcept {
        if (a.kind != b.kind) return false;
        if (a.kind == IrValueKind::Imm) return a.imm == b.imm && a.type == b.type;
        return ssa_key(a) == ssa_key(b);
    }

    [[nodiscard]] std::optional<SubOps> match_sub_result(const IrValue& v) const {
        const IrInst* d = def_stripped(v);
        if (!d || d->op != IrOp::Sub || d->src_count < 2) return std::nullopt;
        return SubOps{d->srcs[0], d->srcs[1]};
    }

    [[nodiscard]] std::optional<SubOps> match_zf(const IrValue& v) const {
        const IrInst* d = def_stripped(v);
        if (!d || d->op != IrOp::CmpEq || d->src_count < 2) return std::nullopt;
        if (d->srcs[1].kind != IrValueKind::Imm || d->srcs[1].imm != 0) return std::nullopt;
        return match_sub_result(d->srcs[0]);
    }

    [[nodiscard]] std::optional<SubOps> match_sf(const IrValue& v) const {
        const IrInst* d = def_stripped(v);
        if (!d || d->op != IrOp::CmpSlt || d->src_count < 2) return std::nullopt;
        if (d->srcs[1].kind != IrValueKind::Imm || d->srcs[1].imm != 0) return std::nullopt;
        return match_sub_result(d->srcs[0]);
    }

    [[nodiscard]] std::optional<SubOps> match_cf(const IrValue& v) const {
        const IrInst* d = def_stripped(v);
        if (!d || d->op != IrOp::SubBorrow || d->src_count < 2) return std::nullopt;
        return SubOps{d->srcs[0], d->srcs[1]};
    }

    [[nodiscard]] std::optional<SubOps> match_of(const IrValue& v) const {
        const IrInst* d = def_stripped(v);
        if (!d || d->op != IrOp::SubOverflow || d->src_count < 2) return std::nullopt;
        return SubOps{d->srcs[0], d->srcs[1]};
    }

    [[nodiscard]] bool same_ops(const SubOps& x, const SubOps& y) const {
        return same_ssa(x.a, y.a) && same_ssa(x.b, y.b);
    }

    [[nodiscard]] std::optional<SubOps> match_sf_xor_of(const IrValue& v) const {
        const IrInst* d = def_stripped(v);
        if (!d || d->op != IrOp::Xor || d->src_count < 2) return std::nullopt;
        auto sf1 = match_sf(d->srcs[0]);
        auto of1 = match_of(d->srcs[1]);
        if (sf1 && of1 && same_ops(*sf1, *of1)) return *sf1;
        auto sf2 = match_sf(d->srcs[1]);
        auto of2 = match_of(d->srcs[0]);
        if (sf2 && of2 && same_ops(*sf2, *of2)) return *sf2;
        return std::nullopt;
    }

    [[nodiscard]] std::optional<SubOps> match_or_cf_zf(const IrValue& v) const {
        const IrInst* d = def_stripped(v);
        if (!d || d->op != IrOp::Or || d->src_count < 2) return std::nullopt;
        auto c1 = match_cf(d->srcs[0]); auto z1 = match_zf(d->srcs[1]);
        if (c1 && z1 && same_ops(*c1, *z1)) return *c1;
        auto c2 = match_cf(d->srcs[1]); auto z2 = match_zf(d->srcs[0]);
        if (c2 && z2 && same_ops(*c2, *z2)) return *c2;
        return std::nullopt;
    }

    [[nodiscard]] std::optional<SubOps> match_or_zf_sfxorof(const IrValue& v) const {
        const IrInst* d = def_stripped(v);
        if (!d || d->op != IrOp::Or || d->src_count < 2) return std::nullopt;
        auto z1 = match_zf(d->srcs[0]); auto x1 = match_sf_xor_of(d->srcs[1]);
        if (z1 && x1 && same_ops(*z1, *x1)) return *z1;
        auto z2 = match_zf(d->srcs[1]); auto x2 = match_sf_xor_of(d->srcs[0]);
        if (z2 && x2 && same_ops(*z2, *x2)) return *z2;
        return std::nullopt;
    }

    // Matches Not(v) and returns the inner operand (via def chain).
    [[nodiscard]] const IrInst* match_not(const IrValue& v) const {
        return def_stripped(v);
    }

    [[nodiscard]] std::optional<SubOps> match_and_notzf_notcf(const IrValue& v) const {
        const IrInst* d = def_stripped(v);
        if (!d || d->op != IrOp::And || d->src_count < 2) return std::nullopt;
        // Each operand should be Not(zf) or Not(cf)
        auto try_match = [&](const IrValue& left, const IrValue& right) -> std::optional<SubOps> {
            const IrInst* ld = def_stripped(left);
            const IrInst* rd = def_stripped(right);
            if (!ld || !rd) return std::nullopt;
            if (ld->op != IrOp::Not || rd->op != IrOp::Not) return std::nullopt;
            auto zf = match_zf(ld->srcs[0]);
            auto cf = match_cf(rd->srcs[0]);
            if (zf && cf && same_ops(*zf, *cf)) return *zf;
            return std::nullopt;
        };
        if (auto r = try_match(d->srcs[0], d->srcs[1]); r) return r;
        if (auto r = try_match(d->srcs[1], d->srcs[0]); r) return r;
        return std::nullopt;
    }

    [[nodiscard]] std::optional<SubOps> match_and_notzf_not_sfxorof(const IrValue& v) const {
        const IrInst* d = def_stripped(v);
        if (!d || d->op != IrOp::And || d->src_count < 2) return std::nullopt;
        auto try_match = [&](const IrValue& left, const IrValue& right) -> std::optional<SubOps> {
            const IrInst* ld = def_stripped(left);
            const IrInst* rd = def_stripped(right);
            if (!ld || !rd) return std::nullopt;
            if (ld->op != IrOp::Not || rd->op != IrOp::Not) return std::nullopt;
            auto zf = match_zf(ld->srcs[0]);
            auto xr = match_sf_xor_of(rd->srcs[0]);
            if (zf && xr && same_ops(*zf, *xr)) return *zf;
            return std::nullopt;
        };
        if (auto r = try_match(d->srcs[0], d->srcs[1]); r) return r;
        if (auto r = try_match(d->srcs[1], d->srcs[0]); r) return r;
        return std::nullopt;
    }

    [[nodiscard]] std::string render_cmp(std::string_view op, const IrValue& a,
                                         const IrValue& b, int depth,
                                         bool signed_cmp,
                                         bool in_bool_ctx = false,
                                         int min_prec = 0) const {
        // In boolean context, `x != 0` is spelled `x` and `x == 0` is `!x`.
        // Applies to either operand being an Imm(0).
        if (in_bool_ctx && (op == "!=" || op == "==")) {
            const IrValue* nonzero = nullptr;
            if (a.kind == IrValueKind::Imm && a.imm == 0) nonzero = &b;
            else if (b.kind == IrValueKind::Imm && b.imm == 0) nonzero = &a;
            if (nonzero) {
                if (op == "!=") {
                    return expr(*nonzero, depth + 1, min_prec);
                }
                std::string rendered = expr(*nonzero, depth + 1,
                                            static_cast<int>(Prec::Unary));
                return wrap_if_lt("!" + rendered, Prec::Unary, min_prec);
            }
        }
        const Prec own = (op == "==" || op == "!=") ? Prec::Eq : Prec::Rel;
        const int p = static_cast<int>(own);
        const std::string_view c = "i64";
        const bool cast_l = signed_cmp && a.kind != IrValueKind::Imm;
        const bool cast_r = signed_cmp && b.kind != IrValueKind::Imm;
        // If we're going to wrap in `(i64)`, the inner must bind at Unary;
        // otherwise the compare's own precedence is enough.
        const int lp = cast_l ? static_cast<int>(Prec::Unary) : p;
        const int rp = cast_r ? static_cast<int>(Prec::Unary) : p + 1;
        std::string left  = expr(a, depth + 1, lp);
        std::string right = expr(b, depth + 1, rp);
        if (cast_l) left  = std::format("({}){}", c, left);
        if (cast_r) right = std::format("({}){}", c, right);
        return wrap_if_lt(std::format("{} {} {}", left, op, right), own, min_prec);
    }

    // `negate`: emit the semantic NOT of the matched compare (e.g., Je → ==, with negate → !=).
    // This cleanly cancels double-negation when the structurer wraps a CondBranch that
    // was itself a Not-of-flag.
    // `in_bool_ctx`: caller is rendering an `if`/`while` condition, so `x != 0`
    // can collapse to `x` and `x == 0` to `!x`.
    [[nodiscard]] std::optional<std::string>
    try_simplify_flag(const IrValue& v, int depth, bool negate = false,
                      bool in_bool_ctx = false, int min_prec = 0) const {
        if (depth >= 12) return std::nullopt;
        if (v.type != IrType::I1) return std::nullopt;

        auto emit_sub = [&](std::string_view op, std::string_view neg_op,
                            const SubOps& s, bool sign_cmp) {
            return render_cmp(negate ? neg_op : op, s.a, s.b, depth, sign_cmp,
                              in_bool_ctx, min_prec);
        };
        auto emit_cmp = [&](std::string_view op, std::string_view neg_op,
                            const IrValue& a, const IrValue& b, bool sign_cmp) {
            return render_cmp(negate ? neg_op : op, a, b, depth, sign_cmp,
                              in_bool_ctx, min_prec);
        };

        // Compound sub-flag patterns (most specific first)
        if (auto s = match_sf_xor_of(v); s)              return emit_sub("<",  ">=", *s, true);
        if (auto s = match_or_cf_zf(v); s)               return emit_sub("<=", ">",  *s, false);
        if (auto s = match_or_zf_sfxorof(v); s)          return emit_sub("<=", ">",  *s, true);
        if (auto s = match_and_notzf_notcf(v); s)        return emit_sub(">",  "<=", *s, false);
        if (auto s = match_and_notzf_not_sfxorof(v); s)  return emit_sub(">",  "<=", *s, true);

        const IrInst* d = def_stripped(v);

        // Not(x): recurse with flipped negate (cancels double-negation cleanly).
        if (d && d->op == IrOp::Not && d->src_count == 1) {
            if (auto r = try_simplify_flag(d->srcs[0], depth + 1, !negate,
                                           in_bool_ctx, min_prec);
                r) return r;
        }

        // Atomic sub-flag patterns
        if (auto s = match_zf(v); s) return emit_sub("==", "!=", *s, false);
        if (auto s = match_cf(v); s) return emit_sub("<",  ">=", *s, false);

        // Direct Cmp* ops (with negate, emit complementary)
        if (d && d->src_count >= 2) {
            switch (d->op) {
                case IrOp::CmpEq:  return emit_cmp("==", "!=", d->srcs[0], d->srcs[1], false);
                case IrOp::CmpNe:  return emit_cmp("!=", "==", d->srcs[0], d->srcs[1], false);
                case IrOp::CmpSlt: return emit_cmp("<",  ">=", d->srcs[0], d->srcs[1], true);
                case IrOp::CmpSle: return emit_cmp("<=", ">",  d->srcs[0], d->srcs[1], true);
                case IrOp::CmpSgt: return emit_cmp(">",  "<=", d->srcs[0], d->srcs[1], true);
                case IrOp::CmpSge: return emit_cmp(">=", "<",  d->srcs[0], d->srcs[1], true);
                case IrOp::CmpUlt: return emit_cmp("<",  ">=", d->srcs[0], d->srcs[1], false);
                case IrOp::CmpUle: return emit_cmp("<=", ">",  d->srcs[0], d->srcs[1], false);
                case IrOp::CmpUgt: return emit_cmp(">",  "<=", d->srcs[0], d->srcs[1], false);
                case IrOp::CmpUge: return emit_cmp(">=", "<",  d->srcs[0], d->srcs[1], false);
                default: break;
            }
        }

        return std::nullopt;
    }

    [[nodiscard]] std::string render_condition(const IrValue& v, bool invert) const {
        // Condition is rendered into `if (...)`, so no outer wrapping needed.
        if (auto s = try_simplify_flag(v, 0, invert, /*in_bool_ctx=*/true, 0); s) return *s;
        if (invert) {
            std::string base = expr(v, 0, static_cast<int>(Prec::Unary));
            return std::format("!{}", base);
        }
        return expr(v, 0, 0);
    }
};

std::string Emitter::expr(const IrValue& v, int depth, int min_prec) const {
    // Recognize compiler flag-based compare idioms and emit direct C comparisons.
    if (v.type == IrType::I1 &&
        (v.kind == IrValueKind::Temp || v.kind == IrValueKind::Flag)) {
        if (auto s = try_simplify_flag(v, depth, false, false, min_prec); s) return *s;
    }
    switch (v.kind) {
        case IrValueKind::None:
            return "";
        case IrValueKind::Reg: {
            // For versioned regs, inline a trivial Imm assignment — lets the
            // absorbed call() show the actual constant instead of an orphan reg name.
            if (v.version > 0 && depth < 12) {
                const IrInst* d = def_of(v);
                while (d && d->op == IrOp::Assign && d->src_count == 1) {
                    const auto& src = d->srcs[0];
                    if (src.kind == IrValueKind::Imm) return expr(src, depth + 1, min_prec);
                    if (src.kind == IrValueKind::Reg && src.version == 0) {
                        return render_reg_leaf(src.reg, src.version, depth + 1);
                    }
                    break;
                }
            }
            return render_reg_leaf(v.reg, v.version, depth);
        }
        case IrValueKind::Flag:
            return std::string(flag_name(v.flag));
        case IrValueKind::Imm:
            return format_imm(v);
        case IrValueKind::Temp: {
            // A temp whose value is a stack-relative address renders as &local_X
            // at every use, so we don't need a named def line like "u64 tN = &local_X;".
            if (auto off = stack_offset(v); off) {
                return std::format("&{}", stack_name(*off));
            }
            if (depth < 12 && should_inline(v)) {
                if (const auto* d = def_of(v)) return expand(*d, depth + 1, min_prec);
            }
            return std::format("t{}", v.temp);
        }
    }
    return "";
}

std::string Emitter::expand(const IrInst& d, int depth, int min_prec) const {
    switch (d.op) {
        case IrOp::Assign:
            return d.src_count >= 1 ? expr(d.srcs[0], depth, min_prec) : "";

        case IrOp::Add: {
            if (auto off = stack_offset(IrValue::make_temp(d.dst.temp, d.dst.type)); off) {
                return std::format("&{}", stack_name(*off));
            }
            return format_binop(d, "+", depth, min_prec, Prec::Add, /*commutative=*/true);
        }
        case IrOp::Sub: {
            if (auto off = stack_offset(IrValue::make_temp(d.dst.temp, d.dst.type)); off) {
                return std::format("&{}", stack_name(*off));
            }
            return format_binop(d, "-", depth, min_prec, Prec::Add, /*commutative=*/false);
        }
        case IrOp::Mul:  return format_binop(d, "*", depth, min_prec, Prec::Mul,   true);
        case IrOp::And:  return format_binop(d, "&", depth, min_prec, Prec::BitAnd, true);
        case IrOp::Or:   return format_binop(d, "|", depth, min_prec, Prec::BitOr,  true);
        case IrOp::Xor:  return format_binop(d, "^", depth, min_prec, Prec::BitXor, true);
        case IrOp::Shl:  return format_binop(d, "<<", depth, min_prec, Prec::Shift, false);
        case IrOp::Lshr: return format_binop(d, ">>", depth, min_prec, Prec::Shift, false);
        case IrOp::Ashr: return format_binop(d, ">>", depth, min_prec, Prec::Shift, false);

        case IrOp::Neg: {
            std::string inner = expr(d.srcs[0], depth, static_cast<int>(Prec::Unary));
            return wrap_if_lt("-" + inner, Prec::Unary, min_prec);
        }
        case IrOp::Not: {
            const char* op = (d.dst.type == IrType::I1) ? "!" : "~";
            std::string inner = expr(d.srcs[0], depth, static_cast<int>(Prec::Unary));
            return wrap_if_lt(std::string(op) + inner, Prec::Unary, min_prec);
        }

        case IrOp::CmpEq:  return format_binop(d, "==", depth, min_prec, Prec::Eq,  true);
        case IrOp::CmpNe:  return format_binop(d, "!=", depth, min_prec, Prec::Eq,  true);
        case IrOp::CmpSlt:
        case IrOp::CmpUlt: return format_binop(d, "<",  depth, min_prec, Prec::Rel, false);
        case IrOp::CmpSle:
        case IrOp::CmpUle: return format_binop(d, "<=", depth, min_prec, Prec::Rel, false);
        case IrOp::CmpSgt:
        case IrOp::CmpUgt: return format_binop(d, ">",  depth, min_prec, Prec::Rel, false);
        case IrOp::CmpSge:
        case IrOp::CmpUge: return format_binop(d, ">=", depth, min_prec, Prec::Rel, false);

        case IrOp::ZExt:
        case IrOp::SExt:
        case IrOp::Trunc: {
            const IrValue& src = d.srcs[0];
            // No-op: cast to the same type the value already has.
            if (src.type == d.dst.type) {
                return expr(src, depth, min_prec);
            }
            // `zext(trunc(x, T))` → `(T)x`. The trunc already produces the
            // observable value; widening back to a bigger type is redundant
            // for the reader.
            if (d.op == IrOp::ZExt) {
                if (const IrInst* inner = def_stripped(src);
                    inner && inner->op == IrOp::Trunc && inner->src_count >= 1 &&
                    type_bits(inner->dst.type) <= type_bits(d.dst.type)) {
                    std::string casted = std::format(
                        "({}){}",
                        c_type_name(inner->dst.type),
                        expr(inner->srcs[0], depth, static_cast<int>(Prec::Unary)));
                    return wrap_if_lt(std::move(casted), Prec::Unary, min_prec);
                }
            }
            std::string casted = std::format(
                "({}){}",
                c_type_name(d.dst.type),
                expr(src, depth, static_cast<int>(Prec::Unary)));
            return wrap_if_lt(std::move(casted), Prec::Unary, min_prec);
        }

        case IrOp::Load:
            return format_mem(d.srcs[0], d.dst.type, d.segment);

        case IrOp::AddCarry:
            return std::format("carry_add({}, {})",
                               expr(d.srcs[0], depth, 0), expr(d.srcs[1], depth, 0));
        case IrOp::SubBorrow:
            return std::format("borrow_sub({}, {})",
                               expr(d.srcs[0], depth, 0), expr(d.srcs[1], depth, 0));
        case IrOp::AddOverflow:
            return std::format("overflow_add({}, {})",
                               expr(d.srcs[0], depth, 0), expr(d.srcs[1], depth, 0));
        case IrOp::SubOverflow:
            return std::format("overflow_sub({}, {})",
                               expr(d.srcs[0], depth, 0), expr(d.srcs[1], depth, 0));

        case IrOp::Intrinsic:
            return std::format("__{}()", d.name);

        default:
            return std::format("t{}", d.dst.temp);
    }
}

std::string Emitter::format_store(const IrInst& inst) const {
    if (inst.src_count < 2) return "";
    const auto& addr = inst.srcs[0];
    const auto& val  = inst.srcs[1];
    if (inst.segment == Reg::None) {
        if (auto off = stack_offset(addr); off) {
            return std::format("{} = {};", stack_name(*off), expr(val));
        }
    }
    return std::format("{} = {};", format_mem(addr, val.type, inst.segment), expr(val));
}

std::string Emitter::format_stmt(const IrInst& inst) const {
    switch (inst.op) {
        case IrOp::Store:
            return format_store(inst);

        case IrOp::Assign: {
            if (inst.src_count < 1) return "";
            if (inst.dst.kind == IrValueKind::Reg) {
                // With rvalue forwarding in render_reg_leaf, a single reader
                // inlines the source expression directly. The `reg = expr;`
                // line becomes redundant in that case.
                if (visible_use_count(inst.dst) <= 1) return "";
                return std::format("{} = {};",
                                   reg_name(inst.dst.reg), expr(inst.srcs[0]));
            }
            if (inst.dst.kind == IrValueKind::Flag) {
                if (use_count(inst.dst) == 0) return "";
                return std::format("{} = {};",
                                   flag_name(inst.dst.flag), expr(inst.srcs[0]));
            }
            if (inst.dst.kind == IrValueKind::Temp) {
                if (use_count(inst.dst) <= 1) return "";
                return std::format("{} t{} = {};",
                                   c_type_name(inst.dst.type),
                                   inst.dst.temp,
                                   expr(inst.srcs[0]));
            }
            return "";
        }

        case IrOp::Load: {
            if (use_count(inst.dst) == 0) return "";
            if (use_count(inst.dst) == 1) return "";  // will be inlined
            return std::format("{} t{} = {};",
                               c_type_name(inst.dst.type),
                               inst.dst.temp,
                               format_mem(inst.srcs[0], inst.dst.type, inst.segment));
        }

        case IrOp::Intrinsic:
            // CET markers are emitted at every function entry on toolchains
            // with -fcf-protection (Ubuntu 24.04's gcc-14 defaults to it).
            // They're NOPs semantically, so suppress them from the output.
            if (inst.name == "endbr64" || inst.name == "endbr32") return "";
            return std::format("{}();", inst.name);

        default:
            if (inlinable_op(inst.op) && inst.dst.kind == IrValueKind::Temp) {
                if (visible_use_count(inst.dst) <= 1) return "";
                if (stack_offset(inst.dst).has_value()) return "";
                return std::format("{} t{} = {};",
                                   c_type_name(inst.dst.type),
                                   inst.dst.temp,
                                   expand(inst, 0));
            }
            return "";
    }
}

void Emitter::emit_block(addr_t block_addr, int depth, std::string& out) const {
    auto it = fn->block_at.find(block_addr);
    if (it == fn->block_at.end()) return;
    const auto& bb = fn->blocks[it->second];

    const std::string ind(static_cast<std::size_t>(depth) * 2u, ' ');
    if (options.show_bb_labels) {
        out += std::format("{}// bb_{:x}\n", ind, bb.start);
    }

    std::vector<IrValue> pending_args;
    bool                 have_pending = false;

    auto flush_args_as_intrinsics = [&]() {
        if (have_pending) {
            out += std::format("{}// stray call.args: {} values\n",
                               ind, pending_args.size());
            pending_args.clear();
            have_pending = false;
        }
    };

    // Fallback for callees with no known arity: drop args that look stale
    // (live-in regs the caller never set, or regs whose most recent def is
    // a Clobber from an earlier call).
    auto format_call_args_fallback = [&](const std::vector<IrValue>& args) {
        std::string s;
        bool first = true;
        for (const auto& a : args) {
            if (is_stale_arg_reg(a)) continue;
            if (!first) s += ", ";
            s += expr(a);
            first = false;
        }
        return s;
    };

    // When we know the callee's arity, show exactly that many args.
    auto format_call_args_with_arity = [&](const std::vector<IrValue>& args, u8 arity) {
        const std::size_t limit = std::min<std::size_t>(arity, args.size());
        std::string s;
        for (std::size_t i = 0; i < limit; ++i) {
            if (i > 0) s += ", ";
            s += expr(args[i]);
        }
        return s;
    };

    for (std::size_t ii = 0; ii < bb.insts.size(); ++ii) {
        const auto& inst = bb.insts[ii];
        // Skip ABI-noise prologue/epilogue insts detected during analysis.
        if (hidden.contains({it->second, ii})) continue;
        switch (inst.op) {
            case IrOp::Branch:
            case IrOp::CondBranch:
            case IrOp::BranchIndirect:
            case IrOp::Return:
            case IrOp::Unreachable:
            case IrOp::Nop:
            case IrOp::Phi:
            case IrOp::Clobber:   // ABI-marker; models call-clobber of caller-saved regs
                continue;
            default:
                break;
        }

        if (inst.op == IrOp::Intrinsic && inst.name == "call.args.1") {
            pending_args.clear();
            for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
                pending_args.push_back(inst.srcs[i]);
            }
            have_pending = true;
            continue;
        }
        if (inst.op == IrOp::Intrinsic && inst.name == "call.args.2") {
            for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
                pending_args.push_back(inst.srcs[i]);
            }
            continue;
        }

        if (inst.op == IrOp::Call) {
            auto import_name = import_name_for_direct_call(inst.target1);
            // Arity sources: imports → user sig at PLT / baked-in libc table;
            // printf/scanf family → parse format string to count args;
            // defined functions → infer_sysv_arity. No arity known → fallback
            // drops stale-looking args.
            std::optional<u8> arity;
            if (import_name) {
                arity = import_arity(inst.target1, *import_name);
                if (!arity) {
                    if (auto fi = variadic_format_index(*import_name); fi) {
                        arity = variadic_arity(pending_args, *fi);
                    }
                }
            } else {
                arity = infer_arity(inst.target1);
            }
            const std::string args = arity
                ? format_call_args_with_arity(pending_args, *arity)
                : format_call_args_fallback(pending_args);
            pending_args.clear();
            have_pending = false;
            const std::string callee = import_name
                ? *import_name
                : function_display_name(inst.target1);
            const std::string call_expr = std::format("{}({})", callee, args);
            const auto pos = std::pair{it->second, ii};
            if (fold_call_positions.contains(pos)) {
                auto k = fold_call_ssa_key.find(pos);
                if (k != fold_call_ssa_key.end()) fold_return_expr[k->second] = call_expr;
            } else if (auto bk = bound_call_key.find(pos); bk != bound_call_key.end()) {
                out += std::format("{}u64 {} = {};\n", ind,
                                   call_return_names.at(bk->second), call_expr);
            } else {
                out += std::format("{}{};\n", ind, call_expr);
            }
            continue;
        }
        if (inst.op == IrOp::CallIndirect) {
            if (inst.src_count < 1) {
                pending_args.clear();
                have_pending = false;
                out += std::format("{}(*?)();\n", ind);
                continue;
            }
            std::string call_expr;
            if (auto name = import_name_for_indirect_call(inst.srcs[0]); name) {
                // No PLT address here, so user-sig lookup can't key off one.
                auto arity = libc_arity_by_name(*name);
                if (!arity) {
                    if (auto fi = variadic_format_index(*name); fi) {
                        arity = variadic_arity(pending_args, *fi);
                    }
                }
                const std::string args = arity
                    ? format_call_args_with_arity(pending_args, *arity)
                    : format_call_args_fallback(pending_args);
                call_expr = std::format("{}({})", *name, args);
            } else {
                const std::string args = format_call_args_fallback(pending_args);
                call_expr = std::format("(*{})({})", expr(inst.srcs[0]), args);
            }
            pending_args.clear();
            have_pending = false;
            const auto pos = std::pair{it->second, ii};
            if (fold_call_positions.contains(pos)) {
                auto k = fold_call_ssa_key.find(pos);
                if (k != fold_call_ssa_key.end()) fold_return_expr[k->second] = call_expr;
            } else if (auto bk = bound_call_key.find(pos); bk != bound_call_key.end()) {
                out += std::format("{}u64 {} = {};\n", ind,
                                   call_return_names.at(bk->second), call_expr);
            } else {
                out += std::format("{}{};\n", ind, call_expr);
            }
            continue;
        }

        const std::string stmt = format_stmt(inst);
        if (!stmt.empty()) {
            flush_args_as_intrinsics();
            out += std::format("{}{}\n", ind, stmt);
        }
    }

    flush_args_as_intrinsics();
}

void Emitter::emit_region(const Region& r, int depth, std::string& out) const {
    const std::string ind(static_cast<std::size_t>(depth) * 2u, ' ');

    switch (r.kind) {
        case RegionKind::Empty:
            return;

        case RegionKind::Block:
            emit_block(r.block_start, depth, out);
            return;

        case RegionKind::Seq:
            for (const auto& c : r.children) emit_region(*c, depth, out);
            return;

        case RegionKind::IfThen: {
            const std::string cond = render_condition(r.condition, r.invert);
            out += std::format("{}if ({}) {{\n", ind, cond);
            if (!r.children.empty()) emit_region(*r.children[0], depth + 1, out);
            out += std::format("{}}}\n", ind);
            return;
        }

        case RegionKind::IfElse: {
            std::string then_buf;
            if (r.children.size() > 0) emit_region(*r.children[0], depth + 1, then_buf);
            std::string else_buf;
            if (r.children.size() > 1) emit_region(*r.children[1], depth + 1, else_buf);
            // If only the else arm has content, invert the condition and
            // drop the dead then. Reads much cleaner than `if (!x) {} else {…}`.
            const bool then_empty = then_buf.empty();
            const bool else_empty = else_buf.empty();
            bool invert_effective = r.invert;
            if (then_empty && !else_empty) {
                invert_effective = !invert_effective;
                std::swap(then_buf, else_buf);
            }
            const std::string cond = render_condition(r.condition, invert_effective);
            out += std::format("{}if ({}) {{\n", ind, cond);
            out += then_buf;
            if (!else_buf.empty()) {
                out += std::format("{}}} else {{\n", ind);
                out += else_buf;
            }
            out += std::format("{}}}\n", ind);
            return;
        }

        case RegionKind::While: {
            // Render as for-loop so header-defined temps are in scope for the condition.
            //   for (;;) { header; if (!cond) break; body; }
            // invert^true flips the "keep looping" condition into the "break" condition.
            const std::string break_cond = render_condition(r.condition, !r.invert);
            const std::string inner_ind(static_cast<std::size_t>(depth + 1) * 2u, ' ');
            out += std::format("{}for (;;) {{\n", ind);
            if (!r.children.empty()) {
                emit_region(*r.children[0], depth + 1, out);
            }
            out += std::format("{}if ({}) break;\n", inner_ind, break_cond);
            for (std::size_t i = 1; i < r.children.size(); ++i) {
                emit_region(*r.children[i], depth + 1, out);
            }
            out += std::format("{}}}\n", ind);
            return;
        }

        case RegionKind::Loop:
            out += std::format("{}for (;;) {{\n", ind);
            for (const auto& c : r.children) emit_region(*c, depth + 1, out);
            out += std::format("{}}}\n", ind);
            return;

        case RegionKind::Return: {
            if (r.condition.kind != IrValueKind::None) {
                if (auto k = ssa_key(r.condition); k) {
                    auto f = fold_return_expr.find(*k);
                    if (f != fold_return_expr.end()) {
                        out += std::format("{}return {};\n", ind, f->second);
                        return;
                    }
                }
                // Strip a redundant outer widen: in a return context the
                // caller's declared type already coerces, so `return (u64)x;`
                // where `x` has the return type reads as noise.
                IrValue v = r.condition;
                while (true) {
                    const IrInst* d = def_of(v);
                    if (!d || d->src_count < 1) break;
                    if (d->op != IrOp::ZExt && d->op != IrOp::SExt) break;
                    const auto& src = d->srcs[0];
                    if (type_bits(src.type) > type_bits(d->dst.type)) break;
                    v = src;
                    break;  // one hop only — deeper casts are semantically real
                }
                out += std::format("{}return {};\n", ind, expr(v));
            } else {
                out += std::format("{}return;\n", ind);
            }
            return;
        }
        case RegionKind::Unreachable:
            out += std::format("{}__unreachable();\n", ind);
            return;
        case RegionKind::Break:
            out += std::format("{}break;\n", ind);
            return;
        case RegionKind::Continue:
            out += std::format("{}continue;\n", ind);
            return;
        case RegionKind::Goto:
            out += std::format("{}goto bb_{:x};\n", ind, r.target);
            return;

        case RegionKind::Switch: {
            const std::string_view rn = reg_name(r.switch_index);
            out += std::format("{}switch ({}) {{\n", ind,
                               rn.empty() ? std::string("<idx>") : std::string(rn));
            const std::string cind(static_cast<std::size_t>(depth + 1) * 2u, ' ');
            const std::size_t n_cases = r.case_values.size();

            auto ends_in_terminator = [](const Region& body) -> bool {
                const Region* cur = &body;
                while (cur && cur->kind == RegionKind::Seq && !cur->children.empty()) {
                    cur = cur->children.back().get();
                }
                if (!cur) return false;
                switch (cur->kind) {
                    case RegionKind::Return:
                    case RegionKind::Break:
                    case RegionKind::Continue:
                    case RegionKind::Unreachable:
                        return true;
                    default:
                        return false;
                }
            };

            for (std::size_t i = 0; i < n_cases; ++i) {
                out += std::format("{}case {}:", cind, r.case_values[i]);
                const Region* child = i < r.children.size() ? r.children[i].get() : nullptr;
                const bool is_empty_child =
                    !child || child->kind == RegionKind::Empty ||
                    (child->kind == RegionKind::Seq && child->children.empty());
                if (is_empty_child) {
                    out += "\n";
                    continue;
                }
                out += "\n";
                emit_region(*child, depth + 2, out);
                if (!ends_in_terminator(*child)) {
                    out += std::format("{}  break;\n", cind);
                }
            }
            if (r.has_default && r.children.size() > n_cases) {
                out += std::format("{}default:\n", cind);
                const Region& dflt = *r.children.back();
                emit_region(dflt, depth + 2, out);
                if (!ends_in_terminator(dflt)) {
                    out += std::format("{}  break;\n", cind);
                }
            }
            out += std::format("{}}}\n", ind);
            return;
        }
    }
}

}  // anonymous namespace

Result<std::string> PseudoCEmitter::emit(const StructuredFunction& sf,
                                         const Binary* binary,
                                         const Annotations* annotations,
                                         EmitOptions options) const {
    if (!sf.ir) {
        return std::unexpected(Error::invalid_format(
            "pseudo-c: StructuredFunction has no IR"));
    }

    Emitter e;
    e.binary      = binary;
    e.annotations = annotations;
    e.options     = options;
    bool has_user_sig = false;
    if (annotations) {
        if (const FunctionSig* sig = annotations->signature_for(sf.ir->start); sig) {
            e.self_arity = static_cast<u8>(std::min<std::size_t>(sig->params.size(), 6));
            has_user_sig = true;
        }
    }
    if (e.self_arity == 0) {
        e.self_arity = binary ? infer_sysv_arity(*binary, sf.ir->start) : u8{0};
    }
    e.analyze(*sf.ir);
    if (sf.body) {
        e.suppress_canary_regions(*sf.body);
        e.analyze_return_folds(*sf.body);
    }
    if (!has_user_sig) e.bump_arity_from_body_reads();
    if (!has_user_sig) e.infer_charp_args();
    e.bind_call_returns();

    std::string out;
    out += std::format("// {}\n", sf.ir->name.empty()
                                    ? std::string("<unknown>") : sf.ir->name);

    // Infer return type from body: any Return region carrying a non-None
    // condition means the function yields a value. We use the condition's
    // IrType to pick an appropriate C type rather than always saying `u64`.
    auto inferred_return_type = [&](const Emitter&, const StructuredFunction& s) -> std::string {
        if (!s.body) return "void";
        std::optional<IrType> t;
        std::function<void(const Region&)> walk = [&](const Region& r) {
            if (r.kind == RegionKind::Return &&
                r.condition.kind != IrValueKind::None) {
                if (!t) t = r.condition.type;
            }
            for (const auto& c : r.children) if (c) walk(*c);
        };
        walk(*s.body);
        if (!t) return "void";
        switch (*t) {
            case IrType::F32: return "float";
            case IrType::F64: return "double";
            case IrType::I1:  return "bool";
            case IrType::I8:  return "u8";
            case IrType::I16: return "u16";
            case IrType::I32: return "u32";
            case IrType::I64: return "u64";
        }
        return "u64";
    };

    // Pick a display name: user rename beats binary symbol beats the
    // sub_<hex> fallback. Used below for the header so named functions
    // (e.g. `main` from LC_MAIN) don't render as `sub_<entry>`.
    auto display_name = [&]() -> std::string {
        if (annotations) {
            if (const std::string* n = annotations->name_for(sf.ir->start); n)
                return *n;
        }
        if (binary) {
            for (const auto& s : binary->symbols()) {
                if (s.is_import) continue;
                if (s.kind != SymbolKind::Function) continue;
                if (s.addr != sf.ir->start) continue;
                if (s.name.empty()) continue;
                return s.name;
            }
        }
        return std::format("sub_{:x}", sf.ir->start);
    };

    // Build the function header. A declared signature wins outright;
    // otherwise we fall back to arity-inferred u64 params.
    std::string header;
    if (annotations) {
        if (const FunctionSig* sig = annotations->signature_for(sf.ir->start); sig) {
            std::string params;
            if (sig->params.empty()) {
                params = "void";
            } else {
                for (std::size_t i = 0; i < sig->params.size(); ++i) {
                    if (i > 0) params += ", ";
                    params += std::format("{} {}",
                                          sig->params[i].type,
                                          sig->params[i].name);
                }
            }
            const std::string ret = sig->return_type.empty()
                ? inferred_return_type(e, sf)
                : sig->return_type;
            header = std::format("{} {}({}) {{\n", ret, display_name(), params);
        }
    }
    if (header.empty()) {
        // Use the Emitter's bumped self_arity rather than re-inferring: the
        // body may have read live-in regs beyond the conservative inference.
        const u8 arity = e.self_arity;
        std::string params;
        if (arity == 0) {
            params = "void";
        } else {
            for (u8 i = 0; i < arity; ++i) {
                if (i > 0) params += ", ";
                const std::string_view t = (i < e.charp_arg.size() && e.charp_arg[i])
                    ? std::string_view{"char*"}
                    : std::string_view{"u64"};
                params += std::format("{} a{}", t, i + 1);
            }
        }
        header = std::format("{} {}({}) {{\n",
                             inferred_return_type(e, sf),
                             display_name(), params);
    }
    out += header;

    if (sf.body) {
        e.emit_region(*sf.body, 1, out);
    }

    out += "}\n";

    // Dead-temp pass: drop `T tN = ...;` lines whose `tN` doesn't appear
    // anywhere else in the output. visible_use_count can over-count when
    // the sole reader folds the value through a register-assign chain.
    {
        std::vector<std::string> lines;
        {
            std::string buf;
            for (char c : out) {
                if (c == '\n') { lines.push_back(std::move(buf)); buf.clear(); }
                else { buf.push_back(c); }
            }
            if (!buf.empty()) lines.push_back(std::move(buf));
        }
        auto ident_char = [](char c) {
            return std::isalnum(static_cast<unsigned char>(c)) || c == '_';
        };
        auto is_decl = [&](const std::string& line, std::string& name) {
            std::size_t i = 0;
            while (i < line.size() && line[i] == ' ') ++i;
            // Type token (one word like u32, u64, bool, double).
            const std::size_t type_start = i;
            while (i < line.size() && line[i] != ' ') ++i;
            if (i == type_start || i >= line.size()) return false;
            while (i < line.size() && line[i] == ' ') ++i;
            // Identifier token.
            const std::size_t name_start = i;
            if (i >= line.size()) return false;
            const char c0 = line[i];
            if (!(std::isalpha(static_cast<unsigned char>(c0)) || c0 == '_')) return false;
            ++i;
            while (i < line.size() && ident_char(line[i])) ++i;
            const std::size_t name_end = i;
            while (i < line.size() && line[i] == ' ') ++i;
            if (i >= line.size() || line[i] != '=') return false;
            name = line.substr(name_start, name_end - name_start);
            return true;
        };
        auto name_appears_elsewhere = [&](const std::string& name,
                                          std::size_t skip_idx) {
            for (std::size_t li = 0; li < lines.size(); ++li) {
                if (li == skip_idx) continue;
                std::size_t pos = 0;
                const std::string& l = lines[li];
                while ((pos = l.find(name, pos)) != std::string::npos) {
                    const bool left_ok  = pos == 0 ||
                        !(std::isalnum(static_cast<unsigned char>(l[pos-1])) || l[pos-1] == '_');
                    const std::size_t end = pos + name.size();
                    const bool right_ok = end >= l.size() ||
                        !(std::isalnum(static_cast<unsigned char>(l[end])) || l[end] == '_');
                    if (left_ok && right_ok) return true;
                    pos = end;
                }
            }
            return false;
        };

        std::string cleaned;
        cleaned.reserve(out.size());
        for (std::size_t li = 0; li < lines.size(); ++li) {
            std::string name;
            if (is_decl(lines[li], name) &&
                !name_appears_elsewhere(name, li)) {
                continue;  // dead declaration
            }
            cleaned += lines[li];
            cleaned += '\n';
        }
        out = std::move(cleaned);
    }

    return out;
}

}  // namespace ember
