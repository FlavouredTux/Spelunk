#include <ember/analysis/symtable.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <format>
#include <span>
#include <string_view>
#include <unordered_set>

namespace ember::analysis {

namespace {

constexpr std::size_t kHardCap     = 1u << 20;     // 1 MB
constexpr std::size_t kPaddingRun  = 4;            // NUL run that ends the table

[[nodiscard]] constexpr bool is_printable(std::byte b) noexcept {
    const auto v = static_cast<unsigned char>(b);
    return v >= 0x20 && v <= 0x7e;
}

// Built-in keyword list. Order = display order. A symbol can land in
// multiple buckets — `dl_iterate_phdr` is loader and anti-tamper, etc.
struct CategorySpec {
    std::string_view              name;
    std::span<const std::string_view> keywords;
};

constexpr auto kLoader = std::to_array<std::string_view>({
    "dlopen", "dlclose", "dladdr", "dlsym", "dlvsym", "dlmopen",
    "dlinfo", "dl_iterate_phdr", "fexecve", "memfd_create",
});
constexpr auto kEnv = std::to_array<std::string_view>({
    "getenv", "secure_getenv", "setenv", "unsetenv", "putenv",
    "clearenv", "environ",
});
constexpr auto kExec = std::to_array<std::string_view>({
    "execve", "execv", "execvp", "execvpe", "execl", "execlp", "execle",
    "fork", "vfork", "clone", "clone3", "posix_spawn", "posix_spawnp",
});
constexpr auto kMmap = std::to_array<std::string_view>({
    "mmap", "mmap64", "mprotect", "munmap", "mremap", "madvise",
    "shm_open", "shm_unlink",
});
constexpr auto kAntiTamper = std::to_array<std::string_view>({
    "ptrace", "prctl", "dl_iterate_phdr", "getauxval", "personality",
    "process_vm_readv", "process_vm_writev",
});
constexpr auto kSyscall = std::to_array<std::string_view>({
    "syscall", "prctl",
});
constexpr auto kThreading = std::to_array<std::string_view>({
    "pthread_create", "pthread_join", "pthread_detach",
    "pthread_setspecific", "pthread_getspecific", "pthread_key_create",
    "pthread_mutex_lock", "pthread_mutex_unlock", "pthread_cond_wait",
    "pthread_cond_signal", "__tls_get_addr",
});

// Display-order list of categories.
inline std::array<CategorySpec, 7> categories() {
    return {{
        {"loader",      kLoader},
        {"env",         kEnv},
        {"exec",        kExec},
        {"mmap",        kMmap},
        {"anti-tamper", kAntiTamper},
        {"syscall",     kSyscall},
        {"threading",   kThreading},
    }};
}

}  // namespace

Result<SymtableWalk> walk_symtable(const Binary& b, addr_t va) {
    const auto bytes = b.bytes_at(va);
    if (bytes.empty()) {
        return std::unexpected(Error::out_of_bounds(
            std::format("VA {:#x} not in any loadable segment", va)));
    }

    SymtableWalk w{};
    w.base_va       = va;
    w.terminated_by = SymtableTermination::SegmentEnd;

    std::size_t pos = 0;
    while (pos < bytes.size()) {
        if (pos >= kHardCap) {
            w.terminated_by = SymtableTermination::HardCap;
            break;
        }
        // Termination check #1: 4+ NULs in a row at the read cursor.
        // Only counts as padding once the first byte is NUL — a lone
        // empty string is still a valid entry.
        if (bytes[pos] == std::byte{0}) {
            std::size_t run = 0;
            while (run < kPaddingRun && pos + run < bytes.size()
                   && bytes[pos + run] == std::byte{0}) {
                ++run;
            }
            if (run >= kPaddingRun) {
                w.terminated_by = SymtableTermination::PaddingRun;
                break;
            }
        }
        // Termination check #2: non-printable, non-NUL byte at cursor.
        if (bytes[pos] != std::byte{0} && !is_printable(bytes[pos])) {
            w.terminated_by = SymtableTermination::NonPrintable;
            break;
        }

        const std::size_t start = pos;
        while (pos < bytes.size() && bytes[pos] != std::byte{0}) {
            if (!is_printable(bytes[pos])) {
                // Mid-string corruption — stop before the bad byte.
                w.terminated_by = SymtableTermination::NonPrintable;
                pos = start;
                goto done;
            }
            ++pos;
        }
        if (pos >= bytes.size()) {
            // Last string lacks a NUL terminator — treat as walked off
            // readable memory, drop the unterminated tail.
            w.terminated_by = SymtableTermination::SegmentEnd;
            pos = start;
            break;
        }

        SymtableEntry e;
        e.va     = va + start;
        e.offset = start;
        e.length = pos - start;
        e.text.assign(reinterpret_cast<const char*>(bytes.data() + start), e.length);
        w.entries.push_back(std::move(e));

        ++pos;   // skip the NUL terminator
    }
done:
    w.table_size = pos;
    w.end_va     = va + pos;
    return w;
}

std::vector<SymtableCategory> categorize_symtable(const SymtableWalk& walk) {
    std::vector<SymtableCategory> out;
    for (const auto& spec : categories()) {
        SymtableCategory c{spec.name, {}};
        std::unordered_set<std::string_view> seen;
        for (const auto& e : walk.entries) {
            const std::string_view name{e.text};
            if (name.empty()) continue;
            if (seen.contains(name)) continue;
            const bool match = std::ranges::any_of(spec.keywords,
                [&](std::string_view kw) { return name == kw; });
            if (match) {
                c.hits.push_back(name);
                seen.insert(name);
            }
        }
        if (!c.hits.empty()) out.push_back(std::move(c));
    }
    return out;
}

std::string_view symtable_termination_name(SymtableTermination t) noexcept {
    switch (t) {
        case SymtableTermination::PaddingRun:   return "nul-padding";
        case SymtableTermination::NonPrintable: return "non-printable";
        case SymtableTermination::SegmentEnd:   return "segment-end";
        case SymtableTermination::HardCap:      return "hard-cap";
    }
    return "unknown";
}

}  // namespace ember::analysis
