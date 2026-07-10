/* Exercises decoder coverage for opcodes that used to be unimplemented:
 *   - SetCC via a comparison that returns bool
 *   - REP MOVSQ via a block copy (compiler emits this for fixed-size memcpy)
 *   - BSWAP via __builtin_bswap64
 *   - CMov via a ternary the compiler hoists into a conditional move
 *   - ROL/ROR as real value-producing bit rotations
 *   - STC/CLC carry-flag control feeding ADC
 *   - LAHF/SAHF flag snapshot/restore through AH
 *   - PUSHFQ/POPFQ flag save/restore through the stack
 *   - MOVD scalar GPR-to-XMM and XMM-to-GPR transfers
 *   - PINSRW/PEXTRW scalar-to-XMM and XMM-to-scalar lane transfers
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

/* MOVD crosses between GPR and XMM register classes. The lifter needs normal
 * GPR partial-register semantics on the scalar side, not raw XMM assign. */
int movd_gpr_roundtrip(int x) {
    unsigned int out;
    __asm__ volatile(
        "movd %1, %%xmm0\n\t"
        "movd %%xmm0, %0"
        : "=r"(out)
        : "r"(x)
        : "xmm0"
    );
    return (int)(out + 7);
}

int movd_extract_high_word(int x) {
    unsigned int out;
    __asm__ volatile(
        "movd %1, %%xmm0\n\t"
        "pextrw $3, %%xmm0, %0"
        : "=r"(out)
        : "r"(x)
        : "xmm0"
    );
    return (int)out;
}

/* Exact inline asm keeps this on the legacy SSE2 PINSRW/PEXTRW form. The
 * lifter must not treat the GPR source/destination as a vector operand. */
int vector_word_roundtrip(int x) {
    unsigned int out;
    __asm__ volatile(
        "pxor %%xmm0, %%xmm0\n\t"
        "pinsrw $3, %1, %%xmm0\n\t"
        "pextrw $3, %%xmm0, %0"
        : "=r"(out)
        : "r"(x)
        : "xmm0"
    );
    return (int)out;
}

unsigned long movq_gpr_roundtrip(unsigned long x) {
    unsigned long out;
    __asm__ volatile(
        "movq %1, %%xmm0\n\t"
        "movq %%xmm0, %0"
        : "=r"(out)
        : "r"(x)
        : "xmm0"
    );
    return out + 9;
}

unsigned int rotate_mix(unsigned int x) {
    __asm__ volatile(
        "roll $5, %0\n\t"
        "rorl $3, %0"
        : "+r"(x)
        :
        : "cc"
    );
    return x ^ 0x13579bdfu;
}

unsigned int carry_seed_add(unsigned int x) {
    __asm__ volatile(
        "stc\n\t"
        "adcl $0, %0\n\t"
        "clc"
        : "+r"(x)
        :
        : "cc"
    );
    return x;
}

unsigned int carry_rotate_one(unsigned int x) {
    __asm__ volatile(
        "stc\n\t"
        "rcll $1, %0"
        : "+r"(x)
        :
        : "cc"
    );
    return x ^ 0x2468ace0u;
}

unsigned int carry_rotate_mix(unsigned int x) {
    __asm__ volatile(
        "stc\n\t"
        "rcll $2, %0"
        : "+r"(x)
        :
        : "cc"
    );
    return x ^ 0x13572468u;
}

unsigned int lahf_snapshot(void) {
    unsigned int out;
    __asm__ volatile(
        "xorl %%eax, %%eax\n\t"
        "lahf\n\t"
        "movzbl %%ah, %%eax"
        : "=a"(out)
        :
        : "cc"
    );
    return out;
}

unsigned int sahf_parity_select(void) {
    unsigned int out;
    __asm__ volatile(
        "xorl %%eax, %%eax\n\t"
        "movb $4, %%ah\n\t"
        "sahf\n\t"
        "setp %%al\n\t"
        "movzbl %%al, %%eax"
        : "=a"(out)
        :
        : "cc"
    );
    return out;
}

unsigned int pushf_popf_carry(unsigned int x) {
    __asm__ volatile(
        "stc\n\t"
        "pushfq\n\t"
        "clc\n\t"
        "popfq\n\t"
        "adcl $0, %0"
        : "+r"(x)
        :
        : "cc", "memory"
    );
    return x;
}

int main(int argc, char** argv) {
    set_and_swap(argc, argc * 2);
    block_copy(argv[0]);
    sse_memclr();
    return g_flag + (int)g_swap + (int)g_max + (int)big_dst[0]
        + movd_gpr_roundtrip(argc)
        + movd_extract_high_word(argc)
        + vector_word_roundtrip(argc)
        + (int)movq_gpr_roundtrip((unsigned long)argc << 33)
        + (int)rotate_mix((unsigned int)argc)
        + (int)carry_seed_add((unsigned int)argc)
        + (int)carry_rotate_one((unsigned int)argc)
        + (int)carry_rotate_mix((unsigned int)argc)
        + (int)lahf_snapshot()
        + (int)sahf_parity_select()
        + (int)pushf_popf_carry((unsigned int)argc);
}
