.text
.globl export_copy
.type export_copy, @function
export_copy:
    movdqu (%rsi), %xmm0
    movdqu %xmm0, (%rdi)
    xor %eax, %eax
    ret
.size export_copy, .-export_copy

.globl export_quotient
.type export_quotient, @function
export_quotient:
    mov %rdx, %rcx
    mov %rdi, %rdx
    mov %rsi, %rax
    div %rcx
    ret
.size export_quotient, .-export_quotient

.globl export_remainder
.type export_remainder, @function
export_remainder:
    mov %rdx, %rcx
    mov %rdi, %rdx
    mov %rsi, %rax
    div %rcx
    mov %rdx, %rax
    ret
.size export_remainder, .-export_remainder

.globl export_choose
.type export_choose, @function
export_choose:
    test %esi, %esi
    jnz .Lindirect
    lea 8(%rdi), %rax
    jmp .Lchosen
.Lindirect:
    mov (%rdi), %rax
.Lchosen:
    mov (%rax), %rax
    ret
.size export_choose, .-export_choose

.globl export_choose_call
.type export_choose_call, @function
export_choose_call:
    push %rbp
    mov %rsp, %rbp
    test %esi, %esi
    jz .Linline_args
    mov 8(%rdi), %rsi
    mov (%rdi), %rdi
    jmp .Lcall_chosen
.Linline_args:
    lea 16(%rdi), %rdi
    mov $3, %esi
.Lcall_chosen:
    call *%rdx
    pop %rbp
    ret
.size export_choose_call, .-export_choose_call

.globl export_scratch
.type export_scratch, @function
export_scratch:
    test %edx, %edx
    jnz .Lcall_noop
    movdqu (%rsi), %xmm0
    movdqu %xmm0, (%rdi)
    ret
.Lcall_noop:
    sub $8, %rsp
    call export_noop
    add $8, %rsp
    ret
.size export_scratch, .-export_scratch
.globl export_noop
.hidden export_noop
.type export_noop, @function
export_noop:
    ret
.size export_noop, .-export_noop

.globl export_stale
.type export_stale, @function
export_stale:
    push %rbx
    push %r12
    sub $8, %rsp
    mov %rdi, %rbx
    mov %rdx, %r12
    test %esi, %esi
    jz .Lset_scratch
    call export_noop
    jmp .Lstale_join
.Lset_scratch:
    mov $123, %ecx
.Lstale_join:
    mov %rbx, %rdi
    call *%r12
    add $8, %rsp
    pop %r12
    pop %rbx
    ret
.size export_stale, .-export_stale

.globl export_vprintf
.type export_vprintf, @function
export_vprintf:
    mov %rdi, %rsi
    lea .Lformat(%rip), %rdi
    xor %eax, %eax
    jmp vprintf@PLT
.size export_vprintf, .-export_vprintf

.globl export_rdtsc
.type export_rdtsc, @function
export_rdtsc:
    rdtsc
    xor %eax, %eax
    ret
.size export_rdtsc, .-export_rdtsc

.globl export_undecoded
.type export_undecoded, @function
export_undecoded:
    xor %eax, %eax
    .byte 0x0f, 0x38, 0xff, 0xc0
    ret
.size export_undecoded, .-export_undecoded

.section .rodata
.Lformat: .string "%d\n"
.section .note.GNU-stack,"",@progbits
