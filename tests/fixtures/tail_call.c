/* Two shapes the compiler reliably turns into a `jmp <target>` tail call:
 *   - wrap_strlen: last statement is a bare call to another function;
 *     -O2 emits `jmp strlen@PLT`.
 *   - double_wrap: same but calling another defined function in the same
 *     binary — exercises the non-import tail-call path. */

#include <string.h>

__attribute__((noinline))
long inner(long a, long b) {
    return a * b + 1;
}

size_t wrap_strlen(const char* s) {
    return strlen(s);     /* tail call to imported strlen (PLT) */
}

long double_wrap(long a, long b) {
    return inner(a, b);   /* tail call to defined inner() */
}

int main(int argc, char** argv) {
    return (int)wrap_strlen(argv[0]) + (int)double_wrap(argc, argc);
}
