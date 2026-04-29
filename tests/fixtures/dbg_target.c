// Tiny target for the debugger smoke test. Has a non-inlined
// `dbg_marker` symbol so the test can set a software breakpoint at a
// known address, continue, and assert it hits before the program
// exits with status 42.

__attribute__((noinline))
void dbg_marker(void) {
    __asm__ volatile("nop");
}

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;
    dbg_marker();
    return 42;
}
