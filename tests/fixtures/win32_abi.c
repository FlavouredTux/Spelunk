// Build with i686-w64-mingw32-gcc -O2 -fno-inline -fno-stack-protector
// -nostdlib -Wl,--entry,_mainCRTStartup -Wl,--no-insert-timestamp
// -o win32_abi.prebuilt win32_abi.c -lkernel32
#include <windows.h>

#define EXPORTED __attribute__((dllexport, noinline))

// x87: int/double conversion, compare-and-branch, fldcw truncation.
EXPORTED double __cdecl scale(int a, double b) { return a * b; }
EXPORTED double __cdecl magnitude(double x) { return x < 0 ? -x : x; }
EXPORTED int __cdecl pick(double a, double b, int x, int y) { return a > b ? x : y; }
EXPORTED int __cdecl truncate(double d, int i, int j) { return (int)d + i * j; }

// An 8-byte stack argument ahead of two words, through a realigned frame.
EXPORTED int __cdecl forward(double x, int k) { return truncate(x * 2.0, k, 7) + 1; }

// Stdcall imports pop their own arguments; the caller's offsets follow.
EXPORTED int __cdecl after_calls(int a, int b) {
    int start = GetTickCount();
    Sleep(a);
    SetLastError(5);
    return start + b + a;
}

void mainCRTStartup(void) { ExitProcess((unsigned)forward(1.5, 3)); }
