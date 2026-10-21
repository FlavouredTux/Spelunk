// Build with i686-w64-mingw32-gcc -O2 -fno-inline -fno-stack-protector
// -nostdlib -Wl,--entry,_mainCRTStartup -Wl,--no-insert-timestamp
// -o win32.prebuilt win32.c -lkernel32
#include <windows.h>

#define EXPORTED __attribute__((dllexport, noinline))

EXPORTED int __cdecl cdecl_sum(int a, int b) { return a + b; }
EXPORTED int __stdcall stdcall_sum(int a, int b) { return a + b; }
EXPORTED int __fastcall fastcall_sum(int a, int b, int c) { return a + b + c; }
EXPORTED int __attribute__((thiscall)) thiscall_sum(const int* self, int b) {
    return *self + b;
}
EXPORTED int __cdecl loop_sum(const int* values, int count) {
    int result = 0;
    for (int i = 0; i < count; ++i) result += values[i];
    return result;
}
EXPORTED int __cdecl invoke(int a) {
    int value = cdecl_sum(a, 7);
    value += stdcall_sum(a, 11);
    value += fastcall_sum(a, 13, 17);
    value += thiscall_sum(&a, 19);
    return value;
}
EXPORTED unsigned __cdecl imported(void) { return GetTickCount(); }

void mainCRTStartup(void) { ExitProcess((unsigned)invoke(3)); }
