/* Exercises decoder coverage for opcodes that used to be unimplemented:
 *   - SetCC via a comparison that returns bool
 *   - REP MOVSQ via a block copy (compiler emits this for fixed-size memcpy)
 *   - BSWAP via __builtin_bswap64
 *   - CMov via a ternary the compiler hoists into a conditional move
 */

#include <string.h>
#include <stdint.h>

volatile int  g_flag;
volatile long g_swap;
volatile long g_max;

void set_and_swap(long x, long y) {
    g_flag = (x > y);                      /* setcc */
    g_swap = (long)__builtin_bswap64(x);   /* bswap */
    g_max  = (x > y) ? x : y;              /* cmovcc */
}

char buf[256];

/* Use explicit inline asm so we're not at the mercy of the compiler
 * choosing SSE over rep-movs to inline a short memcpy. */
void block_copy(const char* src) {
    void*  d = buf;
    size_t n = 8;  /* 8 qwords = 64 bytes */
    __asm__ volatile(
        "rep movsq"
        : "+D"(d), "+S"(src), "+c"(n)
        :
        : "memory"
    );
}

/* SSE: force the compiler into an xmm-based memcpy/memset path with a
 * big fixed-size transfer. Lets us lock in that the decoder advances
 * through mandatory-prefix SSE instructions without erroring. */
char big_dst[4096];
void sse_memclr(void) {
    for (int i = 0; i < 4096; ++i) big_dst[i] = 0;
}

int main(int argc, char** argv) {
    set_and_swap(argc, argc * 2);
    block_copy(argv[0]);
    sse_memclr();
    return g_flag + (int)g_swap + (int)g_max + (int)big_dst[0];
}
