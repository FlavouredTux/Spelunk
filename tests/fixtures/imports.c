/* Verifies that ELF PLT/GOT resolution produces named calls in pseudo-C.
 * `use_imports` directly invokes libc imports; without the import-resolution
 * pipeline these would render as `sub_1020(...)` / `(**(u64*)(0x...))(...)`. */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

volatile unsigned long g_count;

void use_imports(const char* a, const char* b) {
    if (a) {
        g_count += strlen(a);
        puts(a);
    }
    if (b) {
        fputs(b, stdout);
    }
    if (getenv("HOME")) {
        g_count += 1;
    }
}

int main(int argc, char** argv) {
    use_imports(argv[0], argc > 1 ? argv[1] : NULL);
    return (int)g_count;
}
