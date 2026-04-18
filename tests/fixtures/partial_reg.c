/* Exercise partial-register lifting paths. The 32-bit writes must zero-extend
 * to 64 bits; the 8-bit writes must preserve upper bits. Sinks go through
 * volatile globals so DCE can't delete the arithmetic. */

volatile unsigned long sink_u64;
volatile unsigned char sink_u8;

void zero_extend_via_eax(unsigned long x) {
    /* compiler keeps result in eax; x64 zero-extends to rax. */
    unsigned int lo = (unsigned int)x + 1u;
    sink_u64 = lo;
}

void preserve_upper_via_al(unsigned long x, unsigned char b) {
    /* Writing the low byte must preserve the upper 56 bits of x. */
    unsigned long y = x;
    *((unsigned char*)&y) = b;
    sink_u64 = y;
}

int main(int argc, char** argv) {
    (void)argv;
    zero_extend_via_eax((unsigned long)argc);
    preserve_upper_via_al((unsigned long)argc, (unsigned char)argc);
    return (int)sink_u64 + sink_u8;
}
