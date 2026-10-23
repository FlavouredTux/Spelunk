.text
.globl scoped_function
.type scoped_function,@function
scoped_function:
    push %rbp
    mov %rsp, %rbp
    mov %edi, %eax
    pop %rbp
    ret
.size scoped_function,.-scoped_function

.globl callees_complete
.type callees_complete,@function
callees_complete:
    call reachable_call
    ret
.Llanding:
    call landing_call
    call *%rax
    ret
.size callees_complete,.-callees_complete

.globl tail_unnamed
.type tail_unnamed,@function
tail_unnamed:
    jmp .Lunnamed_body
.size tail_unnamed,.-tail_unnamed

// No symbol, only an FDE: a stripped image's discovered function.
.Lunnamed_body:
    .cfi_startproc
    call reachable_call
    ret
    .cfi_endproc

.globl reachable_call
.type reachable_call,@function
reachable_call:
    ret
.size reachable_call,.-reachable_call

.globl landing_call
.type landing_call,@function
landing_call:
    ret
.size landing_call,.-landing_call

.globl string_ref
.type string_ref,@function
string_ref:
    lea hidden_string(%rip), %rax
    ret
.size string_ref,.-string_ref

.section .rodata.str1.1,"aMS",@progbits,1
.globl misleading_string_owner
.type misleading_string_owner,@object
misleading_string_owner:
    .asciz "first unrelated literal"
hidden_string:
    .asciz "varint decode read past end"
.section .note.GNU-stack,"",@progbits
