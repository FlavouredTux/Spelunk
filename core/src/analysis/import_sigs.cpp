#include <ember/analysis/import_sigs.hpp>

#include <string>
#include <string_view>

#include <ember/binary/binary.hpp>
#include <ember/binary/symbol.hpp>
#include <ember/disasm/register.hpp>
#include <ember/ir/ir.hpp>
#include <ember/ir/ssa.hpp>

namespace ember {

namespace {

// Type builders. The arena interns by content, so repeat calls return
// the same TypeRef without allocating.
inline TypeRef t_void   (TypeArena& a) { return a.void_t(); }
inline TypeRef t_int    (TypeArena& a, u8 bits, bool signed_)
    { return a.int_t(bits, /*sign_known=*/true, signed_); }
inline TypeRef t_int32s (TypeArena& a) { return t_int(a, 32, true);  }
inline TypeRef t_int32u (TypeArena& a) { return t_int(a, 32, false); }
inline TypeRef t_int64s (TypeArena& a) { return t_int(a, 64, true);  }
inline TypeRef t_size   (TypeArena& a) { return t_int(a, 64, false); }   // size_t (LP64)
inline TypeRef t_ssize  (TypeArena& a) { return t_int(a, 64, true);  }   // ssize_t (LP64)

inline TypeRef t_charp (TypeArena& a) { return a.ptr_t(a.int_t(8)); }
inline TypeRef t_voidp (TypeArena& a) { return a.ptr_t(a.top());    }
inline TypeRef t_intp  (TypeArena& a) { return a.ptr_t(t_int32s(a)); }

// Tag for "this entry's return is the same as void* (FILE*, DIR*, etc.)
// rendered as void* for now — struct types are out of scope until the
// type system grows opaque-struct support".
inline TypeRef t_filep (TypeArena& a) { return t_voidp(a); }

// Build an ImportSigSpec by name. Returning nullopt means "no entry" so
// the caller falls back to its old heuristics; an empty `params` is fine
// for the rare zero-arg imports (`getpid`).
//
// Coverage targets the imports that show up in nearly every binary:
// stdio + string + stdlib + unistd basics + a few syscalls. Adding
// entries is mechanical — keep them grouped by header for readability.
std::optional<ImportSigSpec> build(std::string_view name, TypeArena& a) {
    using SV = std::string_view;
    auto m = [&](TypeRef ret, std::vector<TypeRef> params, bool variadic = false)
        -> std::optional<ImportSigSpec> {
        return ImportSigSpec{ret, std::move(params), variadic};
    };

    // ---- <string.h> --------------------------------------------------------
    if (name == "strlen")    return m(t_size(a),   {t_charp(a)});
    if (name == "strnlen")   return m(t_size(a),   {t_charp(a), t_size(a)});
    if (name == "strcmp")    return m(t_int32s(a), {t_charp(a), t_charp(a)});
    if (name == "strncmp")   return m(t_int32s(a), {t_charp(a), t_charp(a), t_size(a)});
    if (name == "strcasecmp")  return m(t_int32s(a), {t_charp(a), t_charp(a)});
    if (name == "strncasecmp") return m(t_int32s(a), {t_charp(a), t_charp(a), t_size(a)});
    if (name == "strcpy")    return m(t_charp(a),  {t_charp(a), t_charp(a)});
    if (name == "strncpy")   return m(t_charp(a),  {t_charp(a), t_charp(a), t_size(a)});
    if (name == "strcat")    return m(t_charp(a),  {t_charp(a), t_charp(a)});
    if (name == "strncat")   return m(t_charp(a),  {t_charp(a), t_charp(a), t_size(a)});
    if (name == "strchr")    return m(t_charp(a),  {t_charp(a), t_int32s(a)});
    if (name == "strrchr")   return m(t_charp(a),  {t_charp(a), t_int32s(a)});
    if (name == "strstr")    return m(t_charp(a),  {t_charp(a), t_charp(a)});
    if (name == "strdup")    return m(t_charp(a),  {t_charp(a)});
    if (name == "strndup")   return m(t_charp(a),  {t_charp(a), t_size(a)});
    if (name == "strpbrk")   return m(t_charp(a),  {t_charp(a), t_charp(a)});
    if (name == "strspn")    return m(t_size(a),   {t_charp(a), t_charp(a)});
    if (name == "strcspn")   return m(t_size(a),   {t_charp(a), t_charp(a)});
    if (name == "strtok")    return m(t_charp(a),  {t_charp(a), t_charp(a)});
    if (name == "strtok_r")  return m(t_charp(a),  {t_charp(a), t_charp(a), a.ptr_t(t_charp(a))});
    if (name == "strsep")    return m(t_charp(a),  {a.ptr_t(t_charp(a)), t_charp(a)});
    if (name == "strerror")  return m(t_charp(a),  {t_int32s(a)});
    if (name == "memcpy")    return m(t_voidp(a),  {t_voidp(a), t_voidp(a), t_size(a)});
    if (name == "memmove")   return m(t_voidp(a),  {t_voidp(a), t_voidp(a), t_size(a)});
    if (name == "memset")    return m(t_voidp(a),  {t_voidp(a), t_int32s(a), t_size(a)});
    if (name == "memcmp")    return m(t_int32s(a), {t_voidp(a), t_voidp(a), t_size(a)});
    if (name == "memchr")    return m(t_voidp(a),  {t_voidp(a), t_int32s(a), t_size(a)});

    // ---- <stdio.h> ---------------------------------------------------------
    if (name == "fopen")     return m(t_filep(a),  {t_charp(a), t_charp(a)});
    if (name == "freopen")   return m(t_filep(a),  {t_charp(a), t_charp(a), t_filep(a)});
    if (name == "fdopen")    return m(t_filep(a),  {t_int32s(a), t_charp(a)});
    if (name == "fclose")    return m(t_int32s(a), {t_filep(a)});
    if (name == "fread")     return m(t_size(a),   {t_voidp(a), t_size(a), t_size(a), t_filep(a)});
    if (name == "fwrite")    return m(t_size(a),   {t_voidp(a), t_size(a), t_size(a), t_filep(a)});
    if (name == "fseek")     return m(t_int32s(a), {t_filep(a), t_int64s(a), t_int32s(a)});
    if (name == "ftell")     return m(t_int64s(a), {t_filep(a)});
    if (name == "rewind")    return m(t_void(a),   {t_filep(a)});
    if (name == "fflush")    return m(t_int32s(a), {t_filep(a)});
    if (name == "feof")      return m(t_int32s(a), {t_filep(a)});
    if (name == "ferror")    return m(t_int32s(a), {t_filep(a)});
    if (name == "fileno")    return m(t_int32s(a), {t_filep(a)});
    if (name == "fgetc")     return m(t_int32s(a), {t_filep(a)});
    if (name == "fputc")     return m(t_int32s(a), {t_int32s(a), t_filep(a)});
    if (name == "fgets")     return m(t_charp(a),  {t_charp(a), t_int32s(a), t_filep(a)});
    if (name == "fputs")     return m(t_int32s(a), {t_charp(a), t_filep(a)});
    if (name == "puts")      return m(t_int32s(a), {t_charp(a)});
    if (name == "perror")    return m(t_void(a),   {t_charp(a)});
    if (name == "printf")    return m(t_int32s(a), {t_charp(a)},                       /*var*/true);
    if (name == "fprintf")   return m(t_int32s(a), {t_filep(a),  t_charp(a)},          /*var*/true);
    if (name == "sprintf")   return m(t_int32s(a), {t_charp(a),  t_charp(a)},          /*var*/true);
    if (name == "snprintf")  return m(t_int32s(a), {t_charp(a),  t_size(a), t_charp(a)}, /*var*/true);
    if (name == "dprintf")   return m(t_int32s(a), {t_int32s(a), t_charp(a)},          /*var*/true);
    if (name == "scanf")     return m(t_int32s(a), {t_charp(a)},                       /*var*/true);
    if (name == "fscanf")    return m(t_int32s(a), {t_filep(a),  t_charp(a)},          /*var*/true);
    if (name == "sscanf")    return m(t_int32s(a), {t_charp(a),  t_charp(a)},          /*var*/true);
    if (name == "remove")    return m(t_int32s(a), {t_charp(a)});
    if (name == "rename")    return m(t_int32s(a), {t_charp(a),  t_charp(a)});
    if (name == "tmpfile")   return m(t_filep(a),  {});

    // ---- <stdlib.h> --------------------------------------------------------
    if (name == "malloc")        return m(t_voidp(a),  {t_size(a)});
    if (name == "calloc")        return m(t_voidp(a),  {t_size(a), t_size(a)});
    if (name == "realloc")       return m(t_voidp(a),  {t_voidp(a), t_size(a)});
    if (name == "reallocarray")  return m(t_voidp(a),  {t_voidp(a), t_size(a), t_size(a)});
    if (name == "free")          return m(t_void(a),   {t_voidp(a)});
    if (name == "atoi")          return m(t_int32s(a), {t_charp(a)});
    if (name == "atol")          return m(t_int64s(a), {t_charp(a)});
    if (name == "atoll")         return m(t_int64s(a), {t_charp(a)});
    if (name == "strtol")        return m(t_int64s(a), {t_charp(a), a.ptr_t(t_charp(a)), t_int32s(a)});
    if (name == "strtoul")       return m(t_size(a),   {t_charp(a), a.ptr_t(t_charp(a)), t_int32s(a)});
    if (name == "strtoll")       return m(t_int64s(a), {t_charp(a), a.ptr_t(t_charp(a)), t_int32s(a)});
    if (name == "strtoull")      return m(t_size(a),   {t_charp(a), a.ptr_t(t_charp(a)), t_int32s(a)});
    if (name == "getenv")        return m(t_charp(a),  {t_charp(a)});
    if (name == "secure_getenv") return m(t_charp(a),  {t_charp(a)});
    if (name == "setenv")        return m(t_int32s(a), {t_charp(a),  t_charp(a), t_int32s(a)});
    if (name == "unsetenv")      return m(t_int32s(a), {t_charp(a)});
    if (name == "putenv")        return m(t_int32s(a), {t_charp(a)});
    if (name == "system")        return m(t_int32s(a), {t_charp(a)});
    if (name == "exit")          return m(t_void(a),   {t_int32s(a)});
    if (name == "_Exit")         return m(t_void(a),   {t_int32s(a)});
    if (name == "abort")         return m(t_void(a),   {});
    if (name == "atexit")        return m(t_int32s(a), {t_voidp(a)});
    if (name == "abs")           return m(t_int32s(a), {t_int32s(a)});
    if (name == "labs")          return m(t_int64s(a), {t_int64s(a)});
    if (name == "rand")          return m(t_int32s(a), {});
    if (name == "srand")         return m(t_void(a),   {t_int32u(a)});
    if (name == "qsort")         return m(t_void(a),   {t_voidp(a), t_size(a), t_size(a), t_voidp(a)});
    if (name == "bsearch")       return m(t_voidp(a),  {t_voidp(a), t_voidp(a), t_size(a), t_size(a), t_voidp(a)});

    // ---- <unistd.h> --------------------------------------------------------
    if (name == "read")     return m(t_ssize(a),   {t_int32s(a), t_voidp(a), t_size(a)});
    if (name == "write")    return m(t_ssize(a),   {t_int32s(a), t_voidp(a), t_size(a)});
    if (name == "open")     return m(t_int32s(a),  {t_charp(a),  t_int32s(a)},          /*var*/true);
    if (name == "openat")   return m(t_int32s(a),  {t_int32s(a), t_charp(a), t_int32s(a)}, /*var*/true);
    if (name == "creat")    return m(t_int32s(a),  {t_charp(a),  t_int32u(a)});
    if (name == "close")    return m(t_int32s(a),  {t_int32s(a)});
    if (name == "lseek")    return m(t_int64s(a),  {t_int32s(a), t_int64s(a), t_int32s(a)});
    if (name == "dup")      return m(t_int32s(a),  {t_int32s(a)});
    if (name == "dup2")     return m(t_int32s(a),  {t_int32s(a), t_int32s(a)});
    if (name == "pipe")     return m(t_int32s(a),  {t_intp(a)});
    if (name == "access")   return m(t_int32s(a),  {t_charp(a),  t_int32s(a)});
    if (name == "unlink")   return m(t_int32s(a),  {t_charp(a)});
    if (name == "unlinkat") return m(t_int32s(a),  {t_int32s(a), t_charp(a), t_int32s(a)});
    if (name == "mkdir")    return m(t_int32s(a),  {t_charp(a),  t_int32u(a)});
    if (name == "rmdir")    return m(t_int32s(a),  {t_charp(a)});
    if (name == "chdir")    return m(t_int32s(a),  {t_charp(a)});
    if (name == "chmod")    return m(t_int32s(a),  {t_charp(a),  t_int32u(a)});
    if (name == "chown")    return m(t_int32s(a),  {t_charp(a),  t_int32u(a), t_int32u(a)});
    if (name == "fork")     return m(t_int32s(a),  {});
    if (name == "execv")    return m(t_int32s(a),  {t_charp(a),  a.ptr_t(t_charp(a))});
    if (name == "execvp")   return m(t_int32s(a),  {t_charp(a),  a.ptr_t(t_charp(a))});
    if (name == "execve")   return m(t_int32s(a),  {t_charp(a),  a.ptr_t(t_charp(a)), a.ptr_t(t_charp(a))});
    if (name == "getpid")   return m(t_int32s(a),  {});
    if (name == "getppid")  return m(t_int32s(a),  {});
    if (name == "getuid")   return m(t_int32u(a),  {});
    if (name == "geteuid")  return m(t_int32u(a),  {});
    if (name == "getgid")   return m(t_int32u(a),  {});
    if (name == "getegid")  return m(t_int32u(a),  {});
    if (name == "isatty")   return m(t_int32s(a),  {t_int32s(a)});
    if (name == "sleep")    return m(t_int32u(a),  {t_int32u(a)});
    if (name == "usleep")   return m(t_int32s(a),  {t_int32u(a)});

    // ---- <pthread.h> -------------------------------------------------------
    if (name == "pthread_create")        return m(t_int32s(a), {t_voidp(a), t_voidp(a), t_voidp(a), t_voidp(a)});
    if (name == "pthread_join")          return m(t_int32s(a), {t_voidp(a), a.ptr_t(t_voidp(a))});
    if (name == "pthread_detach")        return m(t_int32s(a), {t_voidp(a)});
    if (name == "pthread_mutex_init")    return m(t_int32s(a), {t_voidp(a), t_voidp(a)});
    if (name == "pthread_mutex_destroy") return m(t_int32s(a), {t_voidp(a)});
    if (name == "pthread_mutex_lock")    return m(t_int32s(a), {t_voidp(a)});
    if (name == "pthread_mutex_unlock")  return m(t_int32s(a), {t_voidp(a)});
    if (name == "pthread_mutex_trylock") return m(t_int32s(a), {t_voidp(a)});
    if (name == "pthread_cond_init")     return m(t_int32s(a), {t_voidp(a), t_voidp(a)});
    if (name == "pthread_cond_destroy")  return m(t_int32s(a), {t_voidp(a)});
    if (name == "pthread_cond_signal")   return m(t_int32s(a), {t_voidp(a)});
    if (name == "pthread_cond_broadcast")return m(t_int32s(a), {t_voidp(a)});
    if (name == "pthread_cond_wait")     return m(t_int32s(a), {t_voidp(a), t_voidp(a)});

    // ---- ctype-ish ---------------------------------------------------------
    if (name == "tolower") return m(t_int32s(a), {t_int32s(a)});
    if (name == "toupper") return m(t_int32s(a), {t_int32s(a)});
    if (name == "isalpha") return m(t_int32s(a), {t_int32s(a)});
    if (name == "isdigit") return m(t_int32s(a), {t_int32s(a)});
    if (name == "isspace") return m(t_int32s(a), {t_int32s(a)});
    if (name == "isupper") return m(t_int32s(a), {t_int32s(a)});
    if (name == "islower") return m(t_int32s(a), {t_int32s(a)});
    if (name == "isalnum") return m(t_int32s(a), {t_int32s(a)});
    if (name == "ispunct") return m(t_int32s(a), {t_int32s(a)});
    if (name == "isxdigit")return m(t_int32s(a), {t_int32s(a)});

    // Suppress unused-parameter warning in build configs where the SV
    // alias above is the only mention of <string_view>.
    (void)SV{};
    return std::nullopt;
}

}  // namespace

std::optional<ImportSigSpec>
lookup_import_sig(std::string_view name, TypeArena& arena) {
    return build(name, arena);
}

// Local copy of the symbol-name cleaner (also lives in sig_inference.cpp /
// emitter.cpp). Tiny enough to duplicate; keeping it here means
// import_sigs.cpp doesn't pull in the whole IPA / emitter dependency.
namespace {
[[nodiscard]] std::string clean_import_name_local(std::string_view name) {
    auto at = name.find('@');
    std::string bare(at == std::string_view::npos ? name : name.substr(0, at));
    if (bare.starts_with("__imp_")) bare.erase(0, 6);
    return bare;
}
}  // namespace

namespace {

// Index every SSA def in the function once, used by trace_to_arg_slot
// to follow Assign/Phi chains back to a version-0 int-arg register.
[[nodiscard]] std::map<u64, const IrInst*> index_defs(const IrFunction& fn) {
    std::map<u64, const IrInst*> out;
    for (const auto& bb : fn.blocks) {
        for (const auto& inst : bb.insts) {
            const u64 k = value_type_key(inst.dst);
            if (k != 0) out.emplace(k, &inst);
        }
    }
    return out;
}

// Trace `v` through Assign/Phi chains to a version-0 int-arg register.
// Returns the canonical Reg of that arg slot, or None if the value
// doesn't unambiguously originate from one.
[[nodiscard]] Reg trace_to_arg_reg(
    const std::map<u64, const IrInst*>& defs,
    const IrValue& v, int depth = 0)
{
    if (depth > 8) return Reg::None;
    IrValue cur = v;
    for (int hop = 0; hop < 8; ++hop) {
        if (cur.kind != IrValueKind::Reg) return Reg::None;
        if (cur.version == 0) return canonical_reg(cur.reg);
        const u64 k = value_type_key(cur);
        if (k == 0) return Reg::None;
        auto it = defs.find(k);
        if (it == defs.end()) return Reg::None;
        const IrInst* d = it->second;
        if (d->op == IrOp::Assign && d->src_count == 1) {
            cur = d->srcs[0];
            continue;
        }
        if (d->op == IrOp::Phi && !d->phi_operands.empty()) {
            Reg common = Reg::None;
            for (const auto& op : d->phi_operands) {
                if (value_type_key(op) == k) continue;
                Reg r = trace_to_arg_reg(defs, op, depth + 1);
                if (r == Reg::None) return Reg::None;
                if (common == Reg::None) common = r;
                else if (common != r)    return Reg::None;
            }
            return common;
        }
        return Reg::None;
    }
    return Reg::None;
}

}  // namespace

void seed_call_return_types(const Binary& b, IrFunction& fn) {
    auto refine = [&](const IrValue& v, TypeRef t) {
        if (t.is_top()) return;
        const u64 k = value_type_key(v);
        if (k == 0) return;
        auto it = fn.value_types.find(k);
        if (it == fn.value_types.end()) {
            fn.value_types.emplace(k, t);
        } else {
            it->second = fn.types.meet(it->second, t);
        }
    };

    const auto defs = index_defs(fn);

    for (auto& bb : fn.blocks) {
        // Buffer the call.args.* packing intrinsics so we know which
        // IrValues feed the following Call (mirrors the IPA scan).
        std::vector<IrValue> args;
        args.reserve(6);
        for (std::size_t i = 0; i < bb.insts.size(); ++i) {
            const auto& inst = bb.insts[i];
            if (inst.op == IrOp::Intrinsic && inst.name == "call.args.1") {
                args.clear();
                for (u8 k = 0; k < inst.src_count && k < inst.srcs.size(); ++k)
                    args.push_back(inst.srcs[k]);
                continue;
            }
            if (inst.op == IrOp::Intrinsic &&
                (inst.name == "call.args.2" || inst.name == "call.args.3")) {
                for (u8 k = 0; k < inst.src_count && k < inst.srcs.size(); ++k)
                    args.push_back(inst.srcs[k]);
                continue;
            }
            if (inst.op != IrOp::Call) continue;

            const Symbol* s = b.import_at_plt(inst.target1);
            if (!s) { args.clear(); continue; }
            auto spec = lookup_import_sig(clean_import_name_local(s->name), fn.types);
            if (!spec) { args.clear(); continue; }

            // Return type → post-call Rax via the immediate Clobber.
            if (!spec->ret.is_top()) {
                for (std::size_t j = i + 1; j < bb.insts.size(); ++j) {
                    const auto& cl = bb.insts[j];
                    if (cl.op != IrOp::Clobber) break;
                    if (cl.dst.kind != IrValueKind::Reg) continue;
                    if (canonical_reg(cl.dst.reg) != Reg::Rax) continue;
                    refine(cl.dst, spec->ret);
                    break;
                }
            }

            // Param types → version-0 reads of caller's arg regs that
            // these args trace back to.
            for (std::size_t k = 0; k < args.size() && k < spec->params.size(); ++k) {
                if (spec->params[k].is_top()) continue;
                Reg r = trace_to_arg_reg(defs, args[k]);
                if (r == Reg::None) continue;
                IrValue probe = IrValue::make_reg(r, IrType::I64);
                probe.version = 0;
                refine(probe, spec->params[k]);
            }

            args.clear();
        }
    }
}

}  // namespace ember
