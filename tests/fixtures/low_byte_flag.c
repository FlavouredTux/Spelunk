#include <stdint.h>

volatile uint8_t g_flag = 1;
volatile uint64_t g_sink;

uint64_t low_byte_flag_merge(uint64_t prior) {
    asm volatile(
        "andq $-256, %[prior]\n\t"
        "movzbl g_flag(%%rip), %%eax\n\t"
        "orq %%rax, %[prior]\n\t"
        : [prior] "+r"(prior)
        :
        : "rax", "cc");

    if (((uint8_t)prior & 1) != 0) {
        g_sink = 7;
        return g_sink;
    }
    g_sink = 3;
    return g_sink;
}

int main(void) {
    return (int)low_byte_flag_merge(0x1234);
}
