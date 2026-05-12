/* Taint-walker FP-suppression fixture. The function legitimately uses
 * the table base via the imm64-stored slot, but its body also
 * contains unrelated arithmetic on a separate counter where the
 * constants happen to land on entry offsets (0x1 = "alpha", 0x7 =
 * "bravo", 0xd = "charlie", 0x15 = "delta"). Without taint every
 * `add reg, IMM` that matches an offset gets emitted; with taint
 * only the tainted-register operation produces a hit.
 *
 * Used to lock the FP-suppression behaviour: default --symuses must
 * surface exactly one row (the legit consumer) with one entry; the
 * --no-taint diagnostic mode surfaces the noise too. */

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

volatile unsigned long g_counter_a;
volatile unsigned long g_counter_b;
volatile unsigned long g_counter_c;
volatile const char*   g_seen_charlie;

__attribute__((noinline))
void noisy_consumer(void) {
    /* Legitimate use: base-load then offset add. With taint, this is
     * the ONLY thing that should emit a hit (charlie). */
    const char* p = g_base_ptr;
    g_seen_charlie = p + 0x0d;

    /* Decoy noise: read-modify-write on three separate volatile
     * counters using the same constants as alpha / bravo / delta
     * offsets. The volatile reads/writes can't be fused - each
     * `add reg, IMM` ends up in the disasm. Without taint each is
     * a false-positive entry hit. */
    g_counter_a += 0x01;          /* alpha-shaped noise */
    g_counter_b += 0x07;          /* bravo-shaped noise */
    g_counter_c += 0x15;          /* delta-shaped noise */
}

int main(int argc, char** argv) {
    (void)argv;
    if (argc > 1) noisy_consumer();
    return (int)(unsigned long)g_str_table[0];
}
