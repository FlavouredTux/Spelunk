#include "proc_utils.hpp"

#include <algorithm>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

#include <unistd.h>

#define CHECK(cond, msg)                                                   \
    do {                                                                   \
        if (!(cond)) {                                                     \
            std::fprintf(stderr, "FAIL: %s (line %d)\n", (msg), __LINE__); \
            return 1;                                                      \
        }                                                                  \
    } while (0)

int main() {
    using ember::debug::linux_detail::OwnedArgv;
    using ember::debug::linux_detail::build_argv;
    using ember::debug::linux_detail::build_envp;

    OwnedArgv argv = build_argv("/bin/program", {"first", "second"});
    CHECK(argv.ptrs.size() == 4, "argv includes program, args, and null");
    CHECK(std::string(argv.ptrs[0]) == "/bin/program", "argv[0]");
    CHECK(std::string(argv.ptrs[1]) == "first", "argv[1]");
    CHECK(std::string(argv.ptrs[2]) == "second", "argv[2]");
    CHECK(argv.ptrs[3] == nullptr, "argv null terminator");

    OwnedArgv moved(std::move(argv));
    CHECK(argv.ptrs.empty(), "move construction clears the source");
    CHECK(moved.ptrs.size() == 4 && moved.ptrs.back() == nullptr,
          "move construction preserves argv");

    OwnedArgv assigned = build_envp({"OLD=value"});
    assigned = std::move(moved);
    CHECK(moved.ptrs.empty(), "move assignment clears the source");
    CHECK(assigned.ptrs.size() == 4 &&
              std::string(assigned.ptrs[1]) == "first",
          "move assignment replaces the destination");

    OwnedArgv empty_env = build_envp({});
    CHECK(empty_env.ptrs.size() == 1 && empty_env.ptrs[0] == nullptr,
          "empty environment is null terminated");

    OwnedArgv env = build_envp({"A=one", "B=two"});
    CHECK(env.ptrs.size() == 3, "explicit environment size");
    CHECK(std::string(env.ptrs[0]) == "A=one", "environment order first");
    CHECK(std::string(env.ptrs[1]) == "B=two", "environment order second");
    CHECK(env.ptrs[2] == nullptr, "environment null terminator");

    const pid_t self = ::getpid();
    const auto images = ember::debug::linux_detail::read_proc_maps(self);
    CHECK(!images.empty(), "/proc/self/maps yields loaded images");
    CHECK(std::ranges::all_of(images, [](const auto& image) {
              return !image.path.empty() && image.base != 0;
          }), "loaded image records are complete");

    const auto tids = ember::debug::linux_detail::read_task_tids(self);
    CHECK(std::ranges::find(tids, self) != tids.end(),
          "/proc/self/task includes the main thread");
    return 0;
}
