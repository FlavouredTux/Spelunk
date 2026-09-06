#include <stdlib.h>
#include <unistd.h>

volatile unsigned long long watch_slot = 0;

__attribute__((noinline)) void dbg_marker(void) {
    __asm__ volatile("nop");
}

int main(int argc, char** argv) {
    if (argc != 3) return 99;
    const int gate = atoi(argv[1]);
    const int ready = atoi(argv[2]);
    char token = 1;
    if (write(ready, &token, 1) != 1) return 98;
    close(ready);
    // Wait until the parent has armed both events, then keep memory alive
    // until it has consumed the samples and checked the stored value.
    if (read(gate, &token, 1) != 1) return 97;
    dbg_marker();
    watch_slot = 0xdeadbeefcafebabeULL;
    if (read(gate, &token, 1) != 1) return 96;
    close(gate);
    return 42;
}
