/* Multi-emit lea-form access pattern. The table base is loaded once
 * via an imm64-stored slot (g_base_ptr); each consumer then uses
 * `lea reg, [tainted_base + disp]` once per offset within the same
 * basic block. This is the shape sober's actual consumers use — base
 * stays in a register across multiple offset computations.
 *
 * Distinguishes from symuses_imm64 which exercises the
 * `add tainted_reg, IMM` form (single-emit per fn). */

#include <stddef.h>

__attribute__((used))
const char g_str_table[] =
    "\0"
    "alpha\0"        /* offset 0x01 */
    "bravo\0"        /* offset 0x07 */
    "charlie\0"      /* offset 0x0d */
    "delta\0"        /* offset 0x15 */
    "echo";          /* offset 0x1b */

const char* volatile g_base_ptr = g_str_table;

volatile const char* g_seen_a;
volatile const char* g_seen_b;
volatile const char* g_seen_c;
volatile const char* g_seen_d;

__attribute__((noinline))
void uses_alpha_and_delta(void) {
    const char* p = g_base_ptr;      /* mov rax, [rip+g_base_ptr]; taint rax */
    g_seen_a = p + 0x01;             /* lea rdx, [rax+0x01]; emit alpha */
    g_seen_d = p + 0x15;             /* lea rdx, [rax+0x15]; emit delta */
}

__attribute__((noinline))
void uses_bravo(void) {
    const char* p = g_base_ptr;
    g_seen_b = p + 0x07;             /* one-shot — emit bravo via add or lea */
}

__attribute__((noinline))
void uses_charlie(void) {
    const char* p = g_base_ptr;
    g_seen_c = p + 0x0d;
}

int main(int argc, char** argv) {
    (void)argv;
    if (argc > 1) uses_alpha_and_delta();
    if (argc > 2) uses_bravo();
    if (argc > 3) uses_charlie();
    return (int)(unsigned long)g_str_table[0];
}
