/* Pure computational functions. Without modeling the SysV return register
 * (rax) as a use of the Ret terminator, DCE delete the whole computation
 * and the pseudo-C renders as an empty body - which is wrong. */

int add32(int a, int b) {
    return a + b;
}

int compound(int x) {
    return x * 3 + 7;
}

unsigned long big(unsigned long a, unsigned long b, unsigned long c) {
    return (a ^ b) + (c << 2);
}

__attribute__((noinline))
int branch32(int x) {
    unsigned int out;
    __asm__ volatile(
        "cmpl $5, %1\n\t"
        "ja 1f\n\t"
        "leal 100(%1), %0\n\t"
        "jmp 2f\n"
        "1:\n\t"
        "movl $0xffffffff, %0\n"
        "2:"
        : "=r"(out)
        : "r"(x)
        : "cc"
    );
    return (int)out;
}

int main(int argc, char** argv) {
    (void)argv;
    return add32(argc, argc)
         + compound(argc)
         + (int)big((unsigned long)argc, (unsigned long)argc, (unsigned long)argc)
         + branch32(argc);
}
