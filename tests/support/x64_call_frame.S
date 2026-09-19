.text
.macro begin name
.globl \name
.type \name, @function
\name:
.endm
.macro end name
.size \name, .-\name
.endm

begin virtual_stale
    push %rbp
    mov %rsp, %rbp
    mov %rsi, %rdi
    mov (%rdi), %rax
    call *24(%rax)
    pop %rbp
    ret
end virtual_stale

begin virtual_duplicate
    push %rbp
    mov %rsp, %rbp
    mov %rsi, %rdi
    mov %rdi, %rsi
    mov (%rdi), %rax
    call *24(%rax)
    pop %rbp
    ret
end virtual_duplicate

begin virtual_prepared_before_branch
    push %rbp
    mov %rsp, %rbp
    mov %rsi, %rdi
    mov %rdi, %rsi
    jmp .Ldispatch
.Ldispatch:
    mov (%rdi), %rax
    call *24(%rax)
    pop %rbp
    ret
end virtual_prepared_before_branch

begin virtual_other_argument
    push %rbp
    mov %rsp, %rbp
    mov %rsi, %rdi
    mov $7, %esi
    mov (%rdi), %rax
    call *24(%rax)
    pop %rbp
    ret
end virtual_other_argument

begin reserve_marker
    push %rax
    mov %edi, 4(%rsp)
    lea 4(%rsp), %rdi
    call capture_marker
    add $8, %rsp
    ret
end reserve_marker

begin reserve_full_word
    push %rax
    mov %rdi, (%rsp)
    mov %rsp, %rdi
    call capture_word
    add $8, %rsp
    ret
end reserve_full_word

begin capture_word
    mov (%rdi), %rax
    ret
end capture_word

begin capture_marker
    mov (%rdi), %eax
    ret
end capture_marker

begin pushed_value
    mov %edi, %eax
    push %rax
    xor %eax, %eax
    mov (%rsp), %rax
    add $8, %rsp
    ret
end pushed_value

begin read_entry_push
    push %rax
    mov (%rsp), %rax
    mov %rax, (%rdi)
    xor %eax, %eax
    add $8, %rsp
    ret
end read_entry_push

begin partial_overwrite
    push %rax
    mov %edi, 4(%rsp)
    mov (%rsp), %rax
    add $8, %rsp
    ret
end partial_overwrite

begin escape_uninitialized
    push %rax
    mov %rsp, %rdi
    call capture_marker
    add $8, %rsp
    ret
end escape_uninitialized

begin segment_store_is_not_frame
    push %rax
    mov %edi, %fs:4(%rsp)
    mov 4(%rsp), %eax
    add $8, %rsp
    ret
end segment_store_is_not_frame
.section .note.GNU-stack,"",@progbits
