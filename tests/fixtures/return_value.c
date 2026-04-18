/* Pure computational functions. Without modeling the SysV return register
 * (rax) as a use of the Ret terminator, DCE delete the whole computation
 * and the pseudo-C renders as an empty body — which is wrong. */

int add32(int a, int b) {
    return a + b;
}

int compound(int x) {
    return x * 3 + 7;
}

unsigned long big(unsigned long a, unsigned long b, unsigned long c) {
    return (a ^ b) + (c << 2);
}

int main(int argc, char** argv) {
    (void)argv;
    return add32(argc, argc)
         + compound(argc)
         + (int)big((unsigned long)argc, (unsigned long)argc, (unsigned long)argc);
}
