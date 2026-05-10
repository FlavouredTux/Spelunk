/* imm64-stored access pattern: the table base is stashed in a global
 * qword (`g_table_ptr`) that resolves to `&g_str_table` at link time.
 * Consumers load the base via `mov rax, [rip+g_table_ptr]` rather
 * than directly via `lea rax, [rip+g_str_table]`, so the strict
 * data_xref scan returns zero hits for the table-base VA. The
 * loose-scope path has to follow the imm64-stored slot
 * (`g_table_ptr` itself) and admit functions that read it. */

#include <stddef.h>

__attribute__((used))
const char g_str_table[] =
    "\0"
    "alpha\0"        /* offset 0x01 */
    "bravo\0"        /* offset 0x07 */
    "charlie\0"      /* offset 0x0d */
    "delta\0"        /* offset 0x15 */
    "echo";          /* offset 0x1b */

/* Static-init pointer to the table. Volatile so the compiler can't
 * see through the indirection and constant-fold `g_table_ptr + N`
 * back to a direct `lea` against g_str_table. The on-disk qword
 * still contains the absolute VA of g_str_table — exactly the
 * imm64-stored shape --refs-to-loose scans for. */
const char* volatile g_table_ptr = g_str_table;

volatile const char* g_seen_alpha;
volatile const char* g_seen_charlie_a;
volatile const char* g_seen_charlie_b;

__attribute__((noinline))
void uses_alpha_via_slot(void) {
    const char* p = g_table_ptr;   /* mov rax, [rip+disp_to_g_table_ptr] */
    g_seen_alpha = p + 0x01;       /* add rax, 0x01; ... */
}

__attribute__((noinline))
void uses_charlie_via_slot(void) {
    const char* p = g_table_ptr;
    g_seen_charlie_a = p + 0x0d;
}

__attribute__((noinline))
void uses_charlie_again_via_slot(void) {
    const char* p = g_table_ptr;
    g_seen_charlie_b = p + 0x0d;
}

int main(int argc, char** argv) {
    (void)argv;
    if (argc > 1) uses_alpha_via_slot();
    if (argc > 2) uses_charlie_via_slot();
    if (argc > 3) uses_charlie_again_via_slot();
    return (int)(unsigned long)g_str_table[0];
}
