#include <stdint.h>

__asm__(
    ".data\n"
    ".globl g_unsized\n"
    ".type g_unsized, @object\n"
    "g_unsized:\n"
    ".quad 0x1111111122222222\n"
    ".quad 0x3333333344444444\n"
    ".globl g_after\n"
    ".type g_after, @object\n"
    "g_after:\n"
    ".quad 0x5555555566666666\n"
    ".size g_after, 8\n"
    ".text\n");

extern uint64_t g_unsized[];
extern uint64_t g_after;

uint64_t read_unsized_head(void) {
    return g_unsized[0];
}

uint64_t read_unsized_tail(void) {
    return g_unsized[1];
}

uintptr_t addr_unsized_tail(void) {
    return (uintptr_t)&g_unsized[1];
}

uint64_t read_after(void) {
    return g_after;
}

int main(void) {
    return (int)(read_unsized_head() + read_unsized_tail() + read_after());
}
