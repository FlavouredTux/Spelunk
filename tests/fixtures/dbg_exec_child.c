#include <unistd.h>

volatile unsigned long marker = 0xbbbbbbbbbbbbbbbbULL;

__attribute__((noinline))
void postexec_marker(void) { __asm__ volatile("nop"); }

__attribute__((noinline))
void child_writer(void) {
    marker = 0xdeadbeefcafebabeULL;
}

int main(void) {
    postexec_marker();
    // Explicit write(2) so the persistent-syscall-catch test sees a
    // deterministic event from the child regardless of stdio buffering.
    (void)write(STDOUT_FILENO, "before\n", 7);
    child_writer();
    (void)write(STDOUT_FILENO, "after\n", 6);
    return 0;
}
