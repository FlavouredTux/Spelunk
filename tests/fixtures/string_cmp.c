#include <stdint.h>
#include <stdio.h>

static const char marker[] = "PlatformImpl";

__attribute__((noinline))
int cmp_marker(uintptr_t x) {
    if (x >= (uintptr_t)(marker + 1)) {
        return puts(marker);
    }
    return 0;
}

__attribute__((noinline))
int print_marker(void) {
    return puts(marker);
}

int main(int argc, char** argv) {
    (void)argv;
    return cmp_marker((uintptr_t)argc) + print_marker();
}
