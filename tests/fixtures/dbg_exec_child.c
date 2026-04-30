#include <stdio.h>

volatile unsigned long marker = 0xbbbbbbbbbbbbbbbbULL;

__attribute__((noinline))
void postexec_marker(void) { __asm__ volatile("nop"); }

__attribute__((noinline))
void child_writer(void) {
    marker = 0xdeadbeefcafebabeULL;
}

int main(void) {
    postexec_marker();
    printf("child: marker before write = %lx\n", marker);
    child_writer();
    printf("child: marker after write  = %lx\n", marker);
    return 0;
}
