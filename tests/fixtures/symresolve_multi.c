/* Multi-resolver case: a single fnptr table populated by two distinct
 * resolver functions covering disjoint slot ranges. Mirrors the
 * weak-symbol-stub + bulk-resolver split seen in real obfuscated
 * loaders, where one tiny initialiser fills the first few slots and a
 * separate function fills the rest. --symresolve's iterative detector
 * should pick both up and merge their coverage. */

#include <stddef.h>

__attribute__((used))
const char m_names[] =
    "\0"
    "one\0"
    "two\0"
    "three\0"
    "four\0"
    "five\0"
    "six\0"
    "seven\0"
    "eight";

void* m_fns[8];

/* Covers slots 0..2 — short, runs first in the binary's init path. */
__attribute__((noinline))
void resolver_head(void) {
    m_fns[0] = (void*)(unsigned long)0x1100;
    m_fns[1] = (void*)(unsigned long)0x1200;
    m_fns[2] = (void*)(unsigned long)0x1300;
}

/* Covers slots 3..7 — the larger of the two, populates the bulk of
 * the table. */
__attribute__((noinline))
void resolver_tail(void) {
    m_fns[3] = (void*)(unsigned long)0x1400;
    m_fns[4] = (void*)(unsigned long)0x1500;
    m_fns[5] = (void*)(unsigned long)0x1600;
    m_fns[6] = (void*)(unsigned long)0x1700;
    m_fns[7] = (void*)(unsigned long)0x1800;
}

typedef void (*fp_t)(void);

__attribute__((noinline)) void use_one(void)   { ((fp_t)m_fns[0])(); }
__attribute__((noinline)) void use_seven(void) { ((fp_t)m_fns[6])(); }

int main(int argc, char** argv) {
    (void)argv;
    if (argc > 1) resolver_head();
    if (argc > 2) resolver_tail();
    if (argc > 3) use_one();
    if (argc > 4) use_seven();
    return (int)(unsigned long)m_names[0];
}
