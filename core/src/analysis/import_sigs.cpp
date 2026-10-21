#include <spelunk/analysis/import_sigs.hpp>

#include <cstddef>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <spelunk/binary/binary.hpp>
#include <spelunk/binary/symbol.hpp>
#include <spelunk/common/types.hpp>
#include <spelunk/disasm/register.hpp>
#include <spelunk/ir/abi.hpp>
#include <spelunk/ir/ir.hpp>
#include <spelunk/ir/ssa.hpp>
#include <spelunk/ir/types.hpp>

namespace spelunk {

namespace {

// Type builders. The arena interns by content, so repeat calls return
// the same TypeRef without allocating.
inline TypeRef t_void   (TypeArena& a) { return a.void_t(); }
inline TypeRef t_int    (TypeArena& a, u8 bits, bool signed_)
    { return a.int_t(bits, /*sign_known=*/true, signed_); }
inline TypeRef t_int32s (TypeArena& a) { return t_int(a, 32, true);  }
inline TypeRef t_int32u (TypeArena& a) { return t_int(a, 32, false); }
inline TypeRef t_int16u (TypeArena& a) { return t_int(a, 16, false); }
inline TypeRef t_int8u  (TypeArena& a) { return t_int(a, 8,  false); }
inline TypeRef t_int8s  (TypeArena& a) { return t_int(a, 8,  true);  }
inline TypeRef t_int64s (TypeArena& a) { return t_int(a, 64, true);  }
inline TypeRef t_int64u (TypeArena& a) { return t_int(a, 64, false); }
inline TypeRef t_float32(TypeArena& a) { return a.float_t(32); }
inline TypeRef t_float64(TypeArena& a) { return a.float_t(64); }

inline TypeRef t_charp (TypeArena& a) { return a.ptr_t(a.int_t(8)); }
inline TypeRef t_voidp (TypeArena& a) { return a.ptr_t(a.top());    }
inline TypeRef t_intp  (TypeArena& a) { return a.ptr_t(t_int32s(a)); }
inline TypeRef t_u16p  (TypeArena& a) { return a.ptr_t(t_int16u(a)); }

inline TypeRef t_struct(TypeArena& a, std::string name, u32 size, u32 align) {
    StructInfo info;
    info.name = std::move(name);
    info.size = size;
    info.align = align;
    return a.struct_t(std::move(info));
}

// Tag for "this entry's return is the same as void* (FILE*, DIR*, etc.)
// rendered as void* for now - struct types are out of scope until the
// type system grows opaque-struct support".
inline TypeRef t_filep (TypeArena& a) { return t_voidp(a); }

// Build an ImportSigSpec by name. Returning nullopt means "no entry" so
// the caller falls back to its old heuristics; an empty `params` is fine
// for the rare zero-arg imports (`getpid`).
//
// Coverage targets the imports that show up in nearly every binary:
// stdio + string + stdlib + unistd basics + a few syscalls. Adding
// entries is mechanical - keep them grouped by header for readability.
std::optional<ImportSigSpec> build(std::string_view name, TypeArena& a,
                                   unsigned pointer_bits) {
    using SV = std::string_view;
    // size_t and ssize_t follow the target's pointer width.
    const auto size_bits = static_cast<u8>(pointer_bits);
    const auto t_size = [size_bits](TypeArena& arena) {
        return t_int(arena, size_bits, false);
    };
    const auto t_ssize = [size_bits](TypeArena& arena) {
        return t_int(arena, size_bits, true);
    };
    auto m = [&](TypeRef ret, std::vector<TypeRef> params, bool variadic = false)
        -> std::optional<ImportSigSpec> {
        return ImportSigSpec{ret, std::move(params), variadic};
    };

    // Itanium C++ exception runtime. These fixed prototypes prevent stale
    // argument registers from being printed as extra allocation/throw args.
    if (name == "__cxa_allocate_exception") return m(t_voidp(a), {t_size(a)});
    if (name == "__cxa_free_exception") return m(t_void(a), {t_voidp(a)});
    if (name == "__cxa_throw") return m(t_void(a), {t_voidp(a), t_voidp(a), t_voidp(a)});
    if (name == "__cxa_rethrow" || name == "__cxa_end_catch") return m(t_void(a), {});
    if (name == "__cxa_begin_catch") return m(t_voidp(a), {t_voidp(a)});
    if (name == "_Unwind_Resume") return m(t_void(a), {t_voidp(a)});
    if (name == "__stack_chk_fail") return m(t_void(a), {});
    if (name == "longjmp") return m(t_void(a), {t_voidp(a), t_int32s(a)});

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
    if (name == "strcasestr") return m(t_charp(a), {t_charp(a), t_charp(a)});
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
    if (name == "scanf" || name == "__isoc99_scanf" || name == "__isoc23_scanf")
        return m(t_int32s(a), {t_charp(a)}, /*var*/true);
    if (name == "fscanf" || name == "__isoc99_fscanf" || name == "__isoc23_fscanf")
        return m(t_int32s(a), {t_filep(a), t_charp(a)}, /*var*/true);
    if (name == "sscanf" || name == "__isoc99_sscanf" || name == "__isoc23_sscanf")
        return m(t_int32s(a), {t_charp(a), t_charp(a)}, /*var*/true);
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
    if (name == "atof")          return m(t_float64(a), {t_charp(a)});
    if (name == "strtod")        return m(t_float64(a), {t_charp(a), a.ptr_t(t_charp(a))});
    if (name == "strtof")        return m(t_float32(a), {t_charp(a), a.ptr_t(t_charp(a))});
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

    // ---- MSVCRT / Win32 process startup ---------------------------------
    if (name == "_initterm")
        return m(t_void(a), {a.ptr_t(t_voidp(a)), a.ptr_t(t_voidp(a))});
    if (name == "_initterm_e")
        return m(t_int32s(a), {a.ptr_t(t_voidp(a)), a.ptr_t(t_voidp(a))});
    if (name == "_cexit" || name == "_c_exit") return m(t_void(a), {});
    if (name == "SetUnhandledExceptionFilter")
        return m(t_voidp(a), {t_voidp(a)});
    if (name == "_set_invalid_parameter_handler")
        return m(t_voidp(a), {t_voidp(a)});
    if (name == "Sleep") return m(t_void(a), {t_int32u(a)});
    if (name == "IsDebuggerPresent") return m(t_int32s(a), {});

    // ---- Win32 kernel32 / user32 basics ------------------------------------
    // HANDLE/HMODULE/LPVOID are opaque pointers, DWORD/UINT unsigned, BOOL
    // signed. Exact arity is what x86 needs to know how much a stdcall
    // callee pops.
    if (name == "ExitProcess" || name == "ExitThread" || name == "SetLastError")
        return m(t_void(a), {t_int32u(a)});
    if (name == "TerminateProcess")
        return m(t_int32s(a), {t_voidp(a), t_int32u(a)});
    if (name == "GetCurrentProcess" || name == "GetCurrentThread" ||
        name == "GetProcessHeap")
        return m(t_voidp(a), {});
    if (name == "GetCurrentProcessId" || name == "GetCurrentThreadId" ||
        name == "GetLastError" || name == "GetTickCount")
        return m(t_int32u(a), {});
    if (name == "GetModuleHandleA" || name == "LoadLibraryA")
        return m(t_voidp(a), {t_charp(a)});
    if (name == "GetModuleHandleW" || name == "LoadLibraryW")
        return m(t_voidp(a), {t_u16p(a)});
    if (name == "GetProcAddress") return m(t_voidp(a), {t_voidp(a), t_charp(a)});
    if (name == "FreeLibrary") return m(t_int32s(a), {t_voidp(a)});
    if (name == "VirtualAlloc")
        return m(t_voidp(a), {t_voidp(a), t_size(a), t_int32u(a), t_int32u(a)});
    if (name == "VirtualFree")
        return m(t_int32s(a), {t_voidp(a), t_size(a), t_int32u(a)});
    if (name == "VirtualProtect")
        return m(t_int32s(a), {t_voidp(a), t_size(a), t_int32u(a),
                               a.ptr_t(t_int32u(a))});
    if (name == "HeapAlloc")
        return m(t_voidp(a), {t_voidp(a), t_int32u(a), t_size(a)});
    if (name == "HeapFree")
        return m(t_int32s(a), {t_voidp(a), t_int32u(a), t_voidp(a)});
    if (name == "WaitForSingleObject")
        return m(t_int32u(a), {t_voidp(a), t_int32u(a)});
    if (name == "OutputDebugStringA") return m(t_void(a), {t_charp(a)});
    if (name == "OutputDebugStringW") return m(t_void(a), {t_u16p(a)});
    if (name == "MessageBoxA")
        return m(t_int32s(a), {t_voidp(a), t_charp(a), t_charp(a), t_int32u(a)});
    if (name == "MessageBoxW")
        return m(t_int32s(a), {t_voidp(a), t_u16p(a), t_u16p(a), t_int32u(a)});

    // ---- Win32 process / remote-memory APIs ------------------------------
    // HANDLE/LPVOID stay opaque pointers until named Win32 typedefs become
    // first-class TypeArena nodes. Exact arity and pointer depth are still
    // enough to remove stale Win64 register/home-slot arguments and recover
    // buffers, byte counts, and output pointers correctly.
    if (name == "ReadProcessMemory" || name == "WriteProcessMemory")
        return m(t_int32s(a), {t_voidp(a), t_voidp(a), t_voidp(a),
                               t_size(a), a.ptr_t(t_size(a))});
    if (name == "VirtualQueryEx")
        return m(t_size(a), {t_voidp(a), t_voidp(a), t_voidp(a), t_size(a)});
    if (name == "CreateToolhelp32Snapshot")
        return m(t_voidp(a), {t_int32u(a), t_int32u(a)});
    if (name == "Process32First" || name == "Process32Next" ||
        name == "Module32First" || name == "Module32Next")
        return m(t_int32s(a), {t_voidp(a), t_voidp(a)});
    if (name == "OpenProcess")
        return m(t_voidp(a), {t_int32u(a), t_int32s(a), t_int32u(a)});
    if (name == "CloseHandle") return m(t_int32s(a), {t_voidp(a)});
    if (name == "FindWindowA") return m(t_voidp(a), {t_charp(a), t_charp(a)});
    if (name == "FindWindowW") return m(t_voidp(a), {t_u16p(a), t_u16p(a)});

    // ---- <math.h> ---------------------------------------------------------
    if (name == "fmod")  return m(t_float64(a), {t_float64(a), t_float64(a)});
    if (name == "fmodf") return m(t_float32(a), {t_float32(a), t_float32(a)});
    if (name == "sqrt")  return m(t_float64(a), {t_float64(a)});
    if (name == "sqrtf") return m(t_float32(a), {t_float32(a)});
    if (name == "sin" || name == "cos" || name == "tan" ||
        name == "floor" || name == "ceil" || name == "fabs") {
        return m(t_float64(a), {t_float64(a)});
    }
    if (name == "sinf" || name == "cosf" || name == "tanf" ||
        name == "floorf" || name == "ceilf" || name == "fabsf") {
        return m(t_float32(a), {t_float32(a)});
    }
    if (name == "atan2" || name == "pow") {
        return m(t_float64(a), {t_float64(a), t_float64(a)});
    }
    if (name == "atan2f" || name == "powf") {
        return m(t_float32(a), {t_float32(a), t_float32(a)});
    }

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

    // ---- Nintendo Revolution SDK <revolution/mtx.h> ----------------------
    // Keep vector structures opaque at this layer. Their pointer shape and
    // scalar FP lanes are the ABI details needed by call recovery; named
    // Vec3 fields can be supplied later by debug info or user annotations.
    if (name == "PSVECAdd")
        return m(t_void(a), {t_voidp(a), t_voidp(a), t_voidp(a)});
    if (name == "PSVECSubtract")
        return m(t_void(a), {t_voidp(a), t_voidp(a), t_voidp(a)});
    if (name == "PSVECScale")
        return m(t_void(a), {t_voidp(a), t_voidp(a), t_float32(a)});
    if (name == "PSVECNormalize")
        return m(t_void(a), {t_voidp(a), t_voidp(a)});
    if (name == "PSVecSquareMag" || name == "PSVecMag")
        return m(t_float32(a), {t_voidp(a)});
    if (name == "PSVECDotProduct" || name == "PSVECSquareDistance" ||
        name == "PSVECDistance") {
        return m(t_float32(a), {t_voidp(a), t_voidp(a)});
    }
    if (name == "PSVECCrossProduct")
        return m(t_void(a), {t_voidp(a), t_voidp(a), t_voidp(a)});

    // ---- Nintendo Revolution SDK MTX ------------------------------------
    if (name == "PSMTXIdentity")
        return m(t_void(a), {t_voidp(a)});
    if (name == "PSMTXCopy")
        return m(t_void(a), {t_voidp(a), t_voidp(a)});
    if (name == "PSMTXConcat")
        return m(t_void(a), {t_voidp(a), t_voidp(a), t_voidp(a)});
    if (name == "PSMTXRotRad")
        return m(t_void(a), {t_voidp(a), t_int8s(a), t_float32(a)});
    if (name == "PSMTXRotAxisRad")
        return m(t_void(a), {t_voidp(a), t_voidp(a), t_float32(a)});
    if (name == "PSMTXTrans" || name == "PSMTXScale")
        return m(t_void(a), {t_voidp(a), t_float32(a), t_float32(a),
                             t_float32(a)});
    if (name == "PSMTXTransApply" || name == "PSMTXScaleApply")
        return m(t_void(a), {t_voidp(a), t_voidp(a), t_float32(a),
                             t_float32(a), t_float32(a)});
    if (name == "PSMTXQuat" || name == "QUATMtx")
        return m(t_void(a), {t_voidp(a), t_voidp(a)});
    if (name == "C_MTXPerspective")
        return m(t_void(a), {t_voidp(a), t_float32(a), t_float32(a),
                             t_float32(a), t_float32(a)});
    if (name == "C_MTXOrtho")
        return m(t_void(a), {t_voidp(a), t_float32(a), t_float32(a),
                             t_float32(a), t_float32(a), t_float32(a),
                             t_float32(a)});
    if (name == "PSMTX44MultVec")
        return m(t_void(a), {t_voidp(a), t_voidp(a), t_voidp(a)});

    // ---- Nintendo Revolution SDK GX -------------------------------------
    const TypeRef gx_color = t_struct(a, "GXColor", 4, 1);
    if (name == "GXSetVtxDesc")
        return m(t_void(a), {t_int8u(a), t_int8u(a)});
    if (name == "GXClearVtxDesc" || name == "GXClearBoundingBox")
        return m(t_void(a), {});
    if (name == "GXSetVtxAttrFmt")
        return m(t_void(a), {t_int8u(a), t_int32u(a), t_int32u(a),
                             t_int32u(a), t_int32u(a)});
    if (name == "GXSetNumTexGens" || name == "GXSetCurrentMtx")
        return m(t_void(a), {t_int32u(a)});
    if (name == "GXSetDrawSync")
        return m(t_void(a), {t_int16u(a)});
    if (name == "GXReadDrawSync")
        return m(t_int16u(a), {});
    if (name == "GXBegin")
        return m(t_void(a), {t_int8u(a), t_int8u(a), t_int16u(a)});
    if (name == "GXSetCullMode" || name == "GXSetNumChans" ||
        name == "GXSetNumTevStages" || name == "GXSetZCompLoc") {
        return m(t_void(a), {t_int8u(a)});
    }
    if (name == "GXReadBoundingBox")
        return m(t_void(a), {t_u16p(a), t_u16p(a), t_u16p(a), t_u16p(a)});
    if (name == "GXSetChanMatColor")
        return m(t_void(a), {t_int32s(a), a.ptr_t(gx_color)});
    if (name == "GXSetChanCtrl")
        return m(t_void(a), {t_int32s(a), t_int8u(a), t_int8u(a),
                             t_int8u(a), t_int8u(a), t_int8u(a), t_int8u(a)});
    if (name == "GXInitTexObj")
        return m(t_void(a), {t_voidp(a), t_voidp(a), t_int16u(a),
                             t_int16u(a), t_int32u(a), t_int32u(a),
                             t_int32u(a), t_int32s(a)});
    if (name == "GXInitTexObjLOD")
        return m(t_void(a), {t_voidp(a), t_int32s(a), t_int32s(a),
                             t_float32(a), t_float32(a), t_float32(a),
                             t_int32u(a), t_int32u(a), t_int32u(a)});
    if (name == "GXInitTexObjData")
        return m(t_void(a), {t_voidp(a), t_voidp(a)});
    if (name == "GXSetTevOp")
        return m(t_void(a), {t_int8u(a), t_int8u(a)});
    if (name == "GXSetTevColorIn" || name == "GXSetTevAlphaIn")
        return m(t_void(a), {t_int32s(a), t_int32s(a), t_int32s(a),
                             t_int32s(a), t_int32s(a)});
    if (name == "GXSetTevColorOp" || name == "GXSetTevAlphaOp")
        return m(t_void(a), {t_int32s(a), t_int32s(a), t_int32s(a),
                             t_int32s(a), t_int32s(a), t_int32s(a)});
    if (name == "GXSetTevColor" || name == "GXSetTevKColor")
        return m(t_void(a), {t_int32s(a), gx_color});
    if (name == "GXSetTevKColorSel" || name == "GXSetTevKAlphaSel")
        return m(t_void(a), {t_int32s(a), t_int32s(a)});
    if (name == "GXSetTevSwapMode")
        return m(t_void(a), {t_int8u(a), t_int8u(a), t_int8u(a)});
    if (name == "GXSetAlphaCompare")
        return m(t_void(a), {t_int8u(a), t_int8u(a), t_int8u(a),
                             t_int8u(a), t_int8u(a)});
    if (name == "GXSetTevOrder")
        return m(t_void(a), {t_int32s(a), t_int32s(a), t_int32u(a),
                             t_int32s(a)});
    if (name == "GXSetFog")
        return m(t_void(a), {t_int8u(a), t_float32(a), t_float32(a),
                             t_float32(a), t_float32(a), gx_color});
    if (name == "GXSetBlendMode")
        return m(t_void(a), {t_int8u(a), t_int8u(a), t_int8u(a), t_int8u(a)});
    if (name == "GXSetZMode")
        return m(t_void(a), {t_int8u(a), t_int8u(a), t_int8u(a)});
    if (name == "GXSetProjection" || name == "GXLoadPosMtxImm")
        return m(t_void(a), {t_voidp(a), t_int32u(a)});
    if (name == "GXSetZScaleOffset")
        return m(t_void(a), {t_float32(a), t_float32(a)});
    if (name == "GXProject")
        return m(t_void(a), {t_float32(a), t_float32(a), t_float32(a),
                             t_voidp(a), t_voidp(a), t_voidp(a), t_voidp(a),
                             t_voidp(a), t_voidp(a)});
    if (name == "GXSetViewport")
        return m(t_void(a), {t_float32(a), t_float32(a), t_float32(a),
                             t_float32(a), t_float32(a), t_float32(a)});
    if (name == "GXGetTexBufferSize")
        return m(t_int32u(a), {t_int16u(a), t_int16u(a), t_int32u(a),
                               t_int8u(a), t_int8u(a)});
    if (name == "GXSetTexCopySrc" || name == "GXSetDispCopySrc")
        return m(t_void(a), {t_int16u(a), t_int16u(a), t_int16u(a),
                             t_int16u(a)});
    if (name == "GXSetTexCopyDst")
        return m(t_void(a), {t_int16u(a), t_int16u(a), t_int32u(a),
                             t_int8u(a)});
    if (name == "GXSetDispCopyDst")
        return m(t_void(a), {t_int16u(a), t_int16u(a)});
    if (name == "GXSetScissor")
        return m(t_void(a), {t_int32u(a), t_int32u(a), t_int32u(a),
                             t_int32u(a)});
    if (name == "GXSetScissorBoxOffset")
        return m(t_void(a), {t_int32s(a), t_int32s(a)});
    if (name == "GXLoadTexObj")
        return m(t_void(a), {t_voidp(a), t_int32u(a)});
    if (name == "GXCopyTex" || name == "GXCopyDisp")
        return m(t_void(a), {t_voidp(a), t_int8u(a)});
    if (name == "GXPixModeSync" || name == "GXInvalidateTexAll")
        return m(t_void(a), {});
    if (name == "GXSetDispCopyYScale")
        return m(t_int32u(a), {t_float32(a)});

    // ---- Nintendo Revolution SDK OS -------------------------------------
    if (name == "OSGetMEM1ArenaHi" || name == "OSGetMEM2ArenaHi" ||
        name == "OSGetArenaHi" || name == "OSGetMEM1ArenaLo" ||
        name == "OSGetMEM2ArenaLo" || name == "OSGetArenaLo" ||
        name == "OSGetCurrentThread" || name == "OSGetCurrentContext") {
        return m(t_voidp(a), {});
    }
    if (name == "OSSetMEM1ArenaHi" || name == "OSSetMEM2ArenaHi" ||
        name == "OSSetArenaHi" || name == "OSSetMEM1ArenaLo" ||
        name == "OSSetMEM2ArenaLo" || name == "OSSetArenaLo" ||
        name == "OSInitMutex" || name == "OSLockMutex" ||
        name == "OSUnlockMutex" || name == "OSSetCurrentContext" ||
        name == "OSSaveFPUContext" || name == "OSClearContext" ||
        name == "OSDumpContext" || name == "OSCancelThread" ||
        name == "OSSleepThread" || name == "OSWakeupThread" ||
        name == "OSExitThread") {
        return m(t_void(a), {t_voidp(a)});
    }
    if (name == "OSDisableInterrupts" || name == "OSGetResetCode" ||
        name == "OSGetFontEncode" || name == "OSGetStackPointer" ||
        name == "OSGetTick") {
        return m(t_int32u(a), {});
    }
    if (name == "OSRestoreInterrupts" || name == "OSRestart")
        return m(t_void(a), {t_int32u(a)});
    if (name == "OSGetTime") return m(t_int64u(a), {});
    if (name == "DCFlushRange")
        return m(t_void(a), {t_voidp(a), t_int32u(a)});
    if (name == "ICInvalidateRange")
        return m(t_void(a), {t_voidp(a), t_int32u(a)});
    if (name == "OSLink")
        return m(t_int32u(a), {t_voidp(a), t_voidp(a)});
    if (name == "OSSaveContext" || name == "OSLoadContext" ||
        name == "OSResumeThread" || name == "OSSuspendThread") {
        return m(t_int32s(a), {t_voidp(a)});
    }
    if (name == "OSJoinThread")
        return m(t_int32s(a), {t_voidp(a), a.ptr_t(t_voidp(a))});
    if (name == "OSInitContext")
        return m(t_void(a), {t_voidp(a), t_int32u(a), t_int32u(a)});
    if (name == "OSReport") return m(t_void(a), {t_charp(a)}, true);
    if (name == "OSShutdownSystem" || name == "OSReturnToMenu" ||
        name == "OSYieldThread") {
        return m(t_void(a), {});
    }

    // ---- Nintendo Revolution SDK DVD / controller -----------------------
    if (name == "DVDConvertPathToEntrynum")
        return m(t_int32s(a), {t_charp(a)});
    if (name == "DVDFastOpen")
        return m(t_int32s(a), {t_int32s(a), t_voidp(a)});
    if (name == "DVDClose")
        return m(t_int32s(a), {t_voidp(a)});
    if (name == "DVDReadPrio")
        return m(t_int32s(a), {t_voidp(a), t_voidp(a), t_int32s(a),
                               t_int32s(a), t_int32s(a)});
    if (name == "DVDReadAsyncPrio")
        return m(t_int32s(a), {t_voidp(a), t_voidp(a), t_int32s(a),
                               t_int32s(a), t_voidp(a), t_int32s(a)});
    if (name == "__DVDPushWaitingQueue")
        return m(t_int32s(a), {t_int32s(a), t_voidp(a)});
    if (name == "KPADSetFSStickClamp")
        return m(t_void(a), {t_int8s(a), t_int8s(a)});
    if (name == "KPADSetBtnRepeat" || name == "KPADSetPosParam" ||
        name == "KPADSetHoriParam" || name == "KPADSetDistParam" ||
        name == "KPADSetAccParam") {
        return m(t_void(a), {t_int32s(a), t_float32(a), t_float32(a)});
    }
    if (name == "KPADRead")
        return m(t_int32s(a), {t_int32s(a), t_voidp(a), t_int32u(a)});
    if (name == "KPADCalibrateDPD" || name == "KPADDisableDPD" ||
        name == "KPADEnableDPD") {
        return m(t_void(a), {t_int32s(a)});
    }
    if (name == "KPADInit") return m(t_void(a), {});
    if (name == "WPADRegisterAllocator")
        return m(t_void(a), {t_voidp(a), t_voidp(a)});
    if (name == "WPADSetAutoSleepTime")
        return m(t_void(a), {t_int8u(a)});
    if (name == "WPADControlMotor")
        return m(t_void(a), {t_int32s(a), t_int32u(a)});
    if (name == "WPADIsMotorEnabled") return m(t_int32u(a), {});
    if (name == "WPADIsDpdEnabled")
        return m(t_int32u(a), {t_int32s(a)});

    // ---- Nintendo Revolution SDK CX -------------------------------------
    const TypeRef cx_header = t_struct(a, "CXParsedHeader", 8, 4);
    if (name == "CXGetCompressionHeader")
        return m(cx_header, {t_voidp(a)});
    if (name == "CXGetUncompressedSize")
        return m(t_int32u(a), {t_voidp(a)});
    if (name == "CXUncompressLZ")
        return m(t_void(a), {t_voidp(a), t_voidp(a)});

    // Suppress unused-parameter warning in build configs where the SV
    // alias above is the only mention of <string_view>.
    (void)SV{};
    return std::nullopt;
}

}  // namespace

std::optional<ImportSigSpec>
lookup_import_sig(std::string_view name, TypeArena& arena, unsigned pointer_bits) {
    return build(name, arena, pointer_bits);
}

ImportStringKind import_arg_string_kind(std::string_view name,
                                        u8 arg_index_1based) noexcept {
    struct Entry {
        std::string_view name;
        u8               arg_index_1based;
    };
    static constexpr Entry kNarrowEntries[] = {
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
        {"lstrlenA", 1}, {"OutputDebugStringA", 1},
        {"GetModuleHandleA", 1}, {"LoadLibraryA", 1},
        {"GetProcAddress", 2}, {"CreateFileA", 1}, {"DeleteFileA", 1},
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
    static constexpr Entry kWideEntries[] = {
        {"lstrlenW", 1}, {"OutputDebugStringW", 1},
        {"GetModuleHandleW", 1}, {"LoadLibraryW", 1},
        {"CreateFileW", 1}, {"DeleteFileW", 1},
    };
    for (const auto& entry : kNarrowEntries) {
        if (entry.name == name &&
            entry.arg_index_1based == arg_index_1based) {
            return ImportStringKind::Narrow;
        }
    }
    for (const auto& entry : kWideEntries) {
        if (entry.name == name &&
            entry.arg_index_1based == arg_index_1based) {
            return ImportStringKind::Wide;
        }
    }
    return ImportStringKind::None;
}

namespace {

// Index every SSA def in the function once, used by trace_to_arg_reg
// to follow Assign/Phi chains back to a version-0 ABI argument register.
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

// Trace `v` through Assign/Phi chains to a version-0 argument register.
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
        std::vector<IrValue> int_args;
        std::vector<IrValue> fp_args;
        int_args.reserve(kMaxAbiIntArgs);
        fp_args.reserve(kMaxAbiFpArgs);
        for (std::size_t i = 0; i < bb.insts.size(); ++i) {
            const auto& inst = bb.insts[i];
            if (inst.op == IrOp::Intrinsic && inst.name == "call.args.1") {
                int_args.clear();
                for (u8 k = 0; k < inst.src_count && k < inst.srcs.size(); ++k)
                    int_args.push_back(inst.srcs[k]);
                continue;
            }
            if (inst.op == IrOp::Intrinsic &&
                (inst.name == "call.args.2" || inst.name == "call.args.3")) {
                for (u8 k = 0; k < inst.src_count && k < inst.srcs.size(); ++k)
                    int_args.push_back(inst.srcs[k]);
                continue;
            }
            if (inst.op == IrOp::Intrinsic && inst.name == "call.fp_args.1") {
                fp_args.clear();
                for (u8 k = 0; k < inst.src_count && k < inst.srcs.size(); ++k)
                    fp_args.push_back(inst.srcs[k]);
                continue;
            }
            if (inst.op == IrOp::Intrinsic &&
                (inst.name == "call.fp_args.2" || inst.name == "call.fp_args.3" ||
                 inst.name == "call.fp_args.4" || inst.name == "call.fp_args.5")) {
                for (u8 k = 0; k < inst.src_count && k < inst.srcs.size(); ++k)
                    fp_args.push_back(inst.srcs[k]);
                continue;
            }
            if (inst.op != IrOp::Call) continue;

            const Symbol* s = b.import_at_plt(inst.target1);
            if (!s) {
                const Symbol* defined = b.defined_object_at(inst.target1);
                if (defined && defined->kind == SymbolKind::Function &&
                    defined->addr == inst.target1) {
                    s = defined;
                }
            }
            if (!s) { int_args.clear(); fp_args.clear(); continue; }
            auto spec = lookup_import_sig(
                strip_import_name_decorations(s->name), fn.types,
                b.arch() == Arch::X86 ? 32u : 64u);
            if (!spec) { int_args.clear(); fp_args.clear(); continue; }

            const Abi abi = abi_for(b.format(), b.arch(), b.endian());

            // Return type → the matching post-call ABI lane via its
            // immediate Clobber. Known scalar FP functions on PPC use f1;
            // integer and pointer returns continue to use r3.
            const TypeKind ret_kind = fn.types.kind(spec->ret);
            const Reg ret_reg = ret_kind == TypeKind::Float
                ? fp_return_reg(abi)
                : int_return_reg(abi);
            if (!spec->ret.is_top() && ret_kind != TypeKind::Void &&
                ret_reg != Reg::None) {
                for (std::size_t j = i + 1; j < bb.insts.size(); ++j) {
                    const auto& cl = bb.insts[j];
                    if (cl.op != IrOp::Clobber) break;
                    if (cl.dst.kind != IrValueKind::Reg) continue;
                    if (canonical_reg(cl.dst.reg) != canonical_reg(ret_reg)) continue;
                    refine(cl.dst, spec->ret);
                    break;
                }
            }

            // Param types → version-0 reads of caller arg registers. Integer
            // and FP banks advance independently on SysV/PPC and positionally
            // on Win64, matching the emitter's signature layout.
            std::size_t int_idx = 0;
            std::size_t fp_idx = 0;
            const bool positional = abi_positional_arg_slots(abi);
            for (std::size_t k = 0; k < spec->params.size(); ++k) {
                const TypeRef param = spec->params[k];
                if (param.is_top()) continue;
                const bool is_fp = fn.types.kind(param) == TypeKind::Float;
                const std::size_t idx = positional ? k : (is_fp ? fp_idx : int_idx);
                const auto& bank = is_fp ? fp_args : int_args;
                if (is_fp) ++fp_idx;
                else       ++int_idx;
                if (idx >= bank.size()) continue;
                // Refine the actual value reaching this call even when it is
                // a load or computed expression rather than a direct
                // live-in register. A later local sweep can then propagate
                // `strcmp(..., loaded)` back through Load to prove that the
                // owning argument is char**.
                refine(bank[idx], param);
                Reg r = trace_to_arg_reg(defs, bank[idx]);
                if (r == Reg::None) continue;
                IrValue probe = IrValue::make_reg(r, bank[idx].type);
                probe.version = 0;
                refine(probe, param);
            }

            int_args.clear();
            fp_args.clear();
        }
    }
}

}  // namespace spelunk
