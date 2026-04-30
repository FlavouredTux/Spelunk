// Tiny target for the debugger smoke test. Has a non-inlined
// `dbg_marker` symbol so the test can set a software breakpoint at a
// known address, continue, and assert it hits before the program
// exits with status 42.

__attribute__((noinline))
void dbg_marker(void) {
    __asm__ volatile("nop");
}

// Global the watchpoint smoke test arms a DR slot against. After
// dbg_marker fires, the test sets a write-watch on this slot and
// resumes; the upcoming store should trip the watchpoint.
volatile unsigned long long watch_slot = 0;

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;
    dbg_marker();
    watch_slot = 0xdeadbeefcafebabeULL;
    return 42;
}
