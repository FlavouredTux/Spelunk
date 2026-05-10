/* Mimics a runtime symbol resolver of the kind seen in obfuscated
 * loaders: a packed NUL-terminated string table (g_names), a writable
 * fnptr table (g_fns), a resolver function that emits straight-line
 * stride-8 constant writes to fill the table, and dispatchers that
 * call through specific slots. `--symresolve` is supposed to pair the
 * two, identify the resolver, and surface per-slot callsites.
 *
 * Built with `-nostartfiles -Wl,-e,main` so CRT glue doesn't pollute
 * the search space. The constants stored into g_fns are nonsense as
 * far as runtime behaviour goes — the binary is parsed by ember, not
 * executed. */

#include <stddef.h>

__attribute__((used))
const char g_names[] =
    "\0"
    "alpha\0"
    "bravo\0"
    "charlie\0"
    "delta\0"
    "echo";

void* g_fns[5];

__attribute__((noinline))
void resolver(void) {
    g_fns[0] = (void*)(unsigned long)0x1100;
    g_fns[1] = (void*)(unsigned long)0x1200;
    g_fns[2] = (void*)(unsigned long)0x1300;
    g_fns[3] = (void*)(unsigned long)0x1400;
    g_fns[4] = (void*)(unsigned long)0x1500;
}

typedef void (*fp_t)(void);

__attribute__((noinline)) void use_alpha(void)     { ((fp_t)g_fns[0])(); }
__attribute__((noinline)) void use_charlie_a(void) { ((fp_t)g_fns[2])(); }
__attribute__((noinline)) void use_charlie_b(void) { ((fp_t)g_fns[2])(); }

/* String-table xref anchors. Each one's `lea rax, [rip+g_names+N]`
 * lets --symuses see a function-to-string-entry edge without any
 * resolver / fnptr-table involvement. `g_seen` is volatile so the
 * compiler can't constant-fold the assignment away; -O0 plus the
 * volatile sink is enough to defeat both DCE and any folding of the
 * offset into the LEA base. */
volatile const char* g_seen;

__attribute__((noinline)) void touch_alpha(void)     { g_seen = &g_names[1];  }
__attribute__((noinline)) void touch_bravo(void)     { g_seen = &g_names[7];  }
__attribute__((noinline)) void touch_charlie_a(void) { g_seen = &g_names[13]; }
__attribute__((noinline)) void touch_charlie_b(void) { g_seen = &g_names[13]; }
__attribute__((noinline)) void touch_alpha_and_delta(void) {
    g_seen = &g_names[1];   /* alpha */
    g_seen = &g_names[21];  /* delta */
}
__attribute__((noinline)) void walks_table(void)     { g_seen = &g_names[0]; }

int main(int argc, char** argv) {
    (void)argv;
    if (argc > 1) resolver();
    if (argc > 2) use_alpha();
    if (argc > 3) use_charlie_a();
    if (argc > 4) use_charlie_b();
    if (argc > 5) touch_alpha();
    if (argc > 6) touch_bravo();
    if (argc > 7) touch_charlie_a();
    if (argc > 8) touch_charlie_b();
    if (argc > 9) touch_alpha_and_delta();
    if (argc > 10) walks_table();
    return (int)(unsigned long)g_names[0];
}
