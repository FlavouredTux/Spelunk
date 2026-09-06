#include <stdint.h>
uint64_t logical_from_signed(int64_t x) { return (uint64_t)x >> 1; }
int64_t arithmetic_from_unsigned(uint64_t x) { return (int64_t)x >> 1; }
uint32_t logical32_from_signed(int32_t x) { return (uint32_t)x >> 1; }
int32_t arithmetic32_from_unsigned(uint32_t x) { return (int32_t)x >> 1; }
int cpu_bmi(void) { return (__builtin_cpu_supports("bmi") ? 1 : 0) | (__builtin_cpu_supports("bmi2") ? 2 : 0); }
