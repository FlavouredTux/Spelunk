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

// Two calls merge before the return: st0 is a phi of call clobbers, which
// says nothing about the return type.
EXPORTED int __cdecl merged_calls(int a) {
    int r;
    switch (a) {
        case 0: r = (int)GetTickCount(); break;
        case 1: r = (int)GetLastError(); break;
        default: r = (int)GetCurrentProcessId(); break;
    }
    return r * 3 + a * 5 - (r >> 2);
}

// A rotated loop: the guard reads the list head that also seeds the loop's
// pointer, so that pointer must be assigned before the first iteration.
struct node { int key; void (*fn)(int); struct node* next; };
static struct node list_tail;
__attribute__((dllexport)) struct node* list_head = &list_tail;
EXPORTED void __cdecl walk(void) {
    for (struct node* p = list_head; p; p = p->next)
        if (p->key) p->fn(p->key);
}

// MSVC shapes gcc does not emit, written out as MSVC's code generator does.
// An SEH frame: the EXCEPTION_REGISTRATION it links into fs:[0] is plumbing,
// its try level marks the __try block.
EXPORTED int __cdecl except_handler(void) { return 1; }
__attribute__((used)) static const int scope_table[3] = {-1, 0, 0};
__attribute__((dllexport, naked)) int __cdecl guarded(int a) { __asm__(
    "push %ebp\n mov %esp, %ebp\n"
    "push $-1\n push $_scope_table\n push $_except_handler\n"
    "mov %fs:0, %eax\n push %eax\n mov %esp, %fs:0\n"
    "sub $8, %esp\n push %ebx\n push %esi\n push %edi\n mov %esp, -0x18(%ebp)\n"
    "movl $0, -4(%ebp)\n"
    "push 8(%ebp)\n call _merged_calls\n add $4, %esp\n"
    "movl $-1, -4(%ebp)\n"
    "mov -0x10(%ebp), %ecx\n mov %ecx, %fs:0\n"
    "pop %edi\n pop %esi\n pop %ebx\n mov %ebp, %esp\n pop %ebp\n ret"); }

// The same frame built by shared helpers, as VS2005+ does it:
// `push size; push scope_table; call __SEH_prolog4` sets up ebp, the
// locals, the saved registers and the registration; __SEH_epilog4 tears
// them down. Both keep eax, the return value.
__attribute__((used)) static unsigned security_cookie = 0xbb40e64e;
__asm__(
    "seh_prolog4:\n"
    "  push $_except_handler\n  pushl %fs:0\n"
    "  mov 0x10(%esp), %eax\n  mov %ebp, 0x10(%esp)\n  lea 0x10(%esp), %ebp\n"
    "  sub %eax, %esp\n  push %ebx\n  push %esi\n  push %edi\n"
    "  mov _security_cookie, %eax\n  xor %eax, -4(%ebp)\n  xor %ebp, %eax\n  push %eax\n"
    "  mov %esp, -0x18(%ebp)\n  pushl -8(%ebp)\n"
    "  mov -4(%ebp), %eax\n  movl $-2, -4(%ebp)\n  mov %eax, -8(%ebp)\n"
    "  lea -0x10(%ebp), %eax\n  mov %eax, %fs:0\n  ret\n"
    "seh_epilog4:\n"
    "  mov -0x10(%ebp), %ecx\n  mov %ecx, %fs:0\n  pop %ecx\n"
    "  pop %edi\n  pop %edi\n  pop %esi\n  pop %ebx\n"
    "  mov %ebp, %esp\n  pop %ebp\n  push %ecx\n  ret\n");
__attribute__((dllexport, naked)) int __cdecl guarded_by_helpers(int a) { __asm__(
    "push $8\n push $_scope_table\n call seh_prolog4\n"
    "movl $0, -4(%ebp)\n"
    "push 8(%ebp)\n call _merged_calls\n add $4, %esp\n"
    "movl $-2, -4(%ebp)\n"
    "call seh_epilog4\n ret"); }

// An import called repeatedly through a register: each `call esi` pops
// the argument pushed for it.
__attribute__((dllexport, naked)) int __cdecl naps(void) { __asm__(
    "push %esi\n mov __imp__Sleep@4, %esi\n"
    "push $1\n call *%esi\n push $2\n call *%esi\n"
    "xor %eax, %eax\n pop %esi\n ret"); }

// Inline memcpy: `rep movsd` of n >> 2 dwords, then `rep movsb` of the rest.
__attribute__((dllexport, naked)) void __cdecl copy(void* dst, const void* src, unsigned n) { __asm__(
    "push %esi\n push %edi\n"
    "mov 12(%esp), %edi\n mov 16(%esp), %esi\n mov 20(%esp), %ecx\n"
    "mov %ecx, %edx\n shr $2, %ecx\n rep movsl\n"
    "mov %edx, %ecx\n and $3, %ecx\n rep movsb\n"
    "pop %edi\n pop %esi\n ret"); }

// Returns nothing: the st0 it leaves is whatever its caller had there.
EXPORTED void __cdecl nothing(void) {}

void mainCRTStartup(void) { ExitProcess((unsigned)forward(1.5, 3)); }
