// Build with i686-w64-mingw32-gcc -nostdlib -s -Wl,--entry,_start
// -Wl,--no-insert-timestamp -o win32_discovery.prebuilt win32_discovery.c
// -lkernel32
//
// MSVC's x86 code layout, stripped of symbols: functions packed at 16-byte
// boundaries behind single-byte nop or int3 padding (`.fill`, since gas
// would pad with multi-byte nops), frameless starts with no prologue
// shape (two reached only through a pointer table), argument pushes mid-body
// that look like a frameless prologue, and a loop head aligned with nops
// after a jump, which is not a function.
__asm__(
    ".text\n"
    ".globl _start\n"
    "_start:\n"
    "  push %ebp\n  mov %esp, %ebp\n"
    "  call frameless\n"
    "  push %esi\n  push %edi\n"             // arguments, not a prologue
    "  call takes_two\n  add $8, %esp\n"
    "  mov table, %eax\n  call *%eax\n"
    "  mov table+4, %eax\n  call *%eax\n"
    "  push $3\n  call loops\n  add $4, %esp\n"
    "  push $0\n  call *__imp__ExitProcess@4\n"
    "  ret\n"
    "  .fill (16 - (. - _start) % 16) % 16, 1, 0x90\n"
    "frameless:\n"                           // no prologue shape at all
    "  mov global, %eax\n  movl $0, (%eax)\n  ret\n"
    "  .fill (16 - (. - _start) % 16) % 16, 1, 0x90\n"
    "takes_two:\n"
    "  push %esi\n  mov 8(%esp), %esi\n  mov 12(%esp), %eax\n"
    "  add %esi, %eax\n  pop %esi\n  ret\n"
    "  .fill (16 - (. - _start) % 16) % 16, 1, 0x90\n"
    "only_in_table:\n"                       // reached through `table`
    "  mov global, %eax\n  ret\n"
    "  .fill (16 - (. - _start) % 16) % 16, 1, 0xcc\n"
    "after_int3:\n"
    "  xor %eax, %eax\n  ret\n"
    "  .fill (16 - (. - _start) % 16) % 16, 1, 0xcc\n"
    "loops:\n"
    "  mov 4(%esp), %ecx\n  xor %eax, %eax\n  jmp 2f\n"
    "  .fill (16 - (. - _start) % 16) % 16, 1, 0x90\n"
    "1:\n  add %ecx, %eax\n  dec %ecx\n"     // aligned loop head, not a start
    "2:\n  test %ecx, %ecx\n  jne 1b\n  ret\n"
    ".data\n"
    "global: .long global_cell\n"
    "global_cell: .long 0\n"
    "table: .long only_in_table, after_int3\n");
