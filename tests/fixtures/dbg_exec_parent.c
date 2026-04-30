// Parent process for the exec-persistence smoke test. Sets up a
// known global, then execve's argv[1] (the child fixture path).
// The smoke test arms a watchpoint on `marker` here and expects
// it to re-arm against the child's same-named global after exec —
// the runtime address differs, but symbol re-resolution lands the
// watch on the right slot in the new image.
#include <stdio.h>
#include <unistd.h>

volatile unsigned long marker = 0xaaaaaaaaaaaaaaaaULL;

__attribute__((noinline))
void preexec_marker(void) { __asm__ volatile("nop"); }

int main(int argc, char** argv) {
    preexec_marker();
    (void)marker;  // keep alive at -O2
    if (argc < 2) {
        fprintf(stderr, "usage: %s <child-path>\n", argv[0]);
        return 2;
    }
    char* args[] = { argv[1], NULL };
    execve(argv[1], args, NULL);
    perror("execve");
    return 1;
}
