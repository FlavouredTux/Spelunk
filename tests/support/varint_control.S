.text
.globl decode_induction
.type decode_induction,@function
.hidden control_read_byte
.hidden control_error_env
decode_induction:
    push %rbp
    push %rbx
    push %r12
    push %r13
    push %r14
    push %r15
    sub $8, %rsp
    mov %rdi, %rbx
    mov %rsi, %r12
    mov 8(%rsi), %r13
    xor %ebp, %ebp
    xor %r14d, %r14d
    xor %r15d, %r15d
.Lread:
    movb $0, (%rsp)
    cmp %r13, %r14
    je .Lunderflow
    mov %r12, %rdi
    mov %rsp, %rsi
    call control_read_byte
    movzbl (%rsp), %eax
    mov %eax, %edx
    and $127, %edx
    mov %r15d, %ecx
    shl %cl, %rdx
    or %rdx, %rbp
    cmp $8, %r14
    ja .Lcomplete
    inc %r14
    add $7, %r15
    test %al, %al
    js .Lread
.Lcomplete:
    test %al, %al
    js .Loverflow
    mov %rbp, (%rbx)
    mov %rbx, %rax
    add $8, %rsp
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbx
    pop %rbp
    ret
.Lunderflow:
    lea control_error_env(%rip), %rdi
    mov $1, %esi
    call longjmp@PLT
    ud2
.Loverflow:
    lea control_error_env(%rip), %rdi
    mov $2, %esi
    call longjmp@PLT
    ud2
.size decode_induction,.-decode_induction
.section .note.GNU-stack,"",@progbits
