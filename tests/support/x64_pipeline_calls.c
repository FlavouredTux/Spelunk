#include <stdarg.h>
#include <stdint.h>

static uint64_t call_count;
void pipeline_reset_calls(void) { call_count = 0; }
uint64_t pipeline_get_calls(void) { return call_count; }

__attribute__((noinline)) uint64_t call_step(uint64_t x, uint64_t y) {
    ++call_count;
    return (x * 3) ^ y;
}
__attribute__((noinline)) uint64_t call_mutate(uint64_t* p, uint64_t value) {
    ++call_count;
    uint64_t old = *p;
    *p = old + value;
    return old ^ value;
}
__attribute__((noinline)) uint64_t call_clobber(uint64_t x) {
    ++call_count;
    uint64_t result = x ^ 0x55;
    __asm__ volatile(
        "mov $0x11, %%rdi; mov $0x22, %%rsi; mov $0x33, %%rdx;"
        "mov $0x44, %%rcx; mov $0x55, %%r8; mov $0x66, %%r9;"
        "mov $0x77, %%r10; mov $0x88, %%r11"
        : : : "rdi", "rsi", "rdx", "rcx", "r8", "r9", "r10", "r11");
    return result;
}
/* Variadic, so callers keep the general (non explicit-copy) lowering. */
__attribute__((noinline)) uint64_t call_note(uint64_t tag, ...) {
    ++call_count;
    va_list args;
    va_start(args, tag);
    const uint64_t value = va_arg(args, uint64_t);
    va_end(args);
    return tag * 7 + value;
}
