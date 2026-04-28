/* Verifies that ELF PLT/GOT resolution produces named calls in pseudo-C.
 * `use_imports` directly invokes libc imports; without the import-resolution
 * pipeline these would render as `sub_1020(...)` / `(**(u64*)(0x...))(...)`.
 *
 * Built with `-nostartfiles -Wl,-e,main` so glibc's CRT stubs (_init,
 * _start, _dl_*, *_tm_clones, frame_dummy, __do_global_dtors_aux,
 * _fini) are not linked in. Those stubs come from versioned crt*.o
 * files and shift in subtle ways across gcc point releases (instruction
 * length, peephole choices, function ordering); pinning them out is the
 * cheapest way to keep the goldens stable across local vs. CI
 * toolchains. The binary is unrunnable (libc doesn't get initialised),
 * but ember only ever parses it. */

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

/* Two trivial helpers that compile to identical code so the
 * imports_collisions golden has something to match. Without these we'd
 * be relying on accidental tm_clones / _dl_* / _fini collisions that
 * change shape between gcc versions. `noinline` keeps the compiler
 * from folding them into main; `volatile` reads keep them live. */
__attribute__((noinline)) int twin_a(void) { return (int)g_count; }
__attribute__((noinline)) int twin_b(void) { return (int)g_count; }

int main(int argc, char** argv) {
    use_imports(argv[0], argc > 1 ? argv[1] : NULL);
    return (int)g_count + twin_a() + twin_b();
}
