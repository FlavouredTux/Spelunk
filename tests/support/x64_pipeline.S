.intel_syntax noprefix
.text

.macro begin name
.global \name
.type \name,@function
\name:
.endm
.macro end name
.size \name,.-\name
.endm

// Value probes cover zero and architecturally masked counts.
.irp op,shld,shrd
begin \op\()_zero
mov rax,rdi
mov rcx,rdx
\op rax,rsi,cl
ret
end \op\()_zero
begin \op\()32_zero
mov eax,edi
mov ecx,edx
\op eax,esi,cl
ret
end \op\()32_zero
.endr

// Flag-consuming probes initialize every flag they observe.
.irp flag,zf,cf,sf,of
begin andn_\flag
mov eax,0x7fffffff
add eax,1
stc
andn rax,rdi,rsi
.ifc \flag,zf
sete al
.endif
.ifc \flag,cf
setc al
.endif
.ifc \flag,sf
sets al
.endif
.ifc \flag,of
seto al
.endif
movzx eax,al
ret
end andn_\flag
.endr

begin shift_pf
mov eax,1
test eax,eax
mov eax,3
shl eax,1
setp al
movzx eax,al
ret
end shift_pf

begin ror_zero_cf
stc
mov eax,0
ror rax,0
setc al
movzx eax,al
ret
end ror_zero_cf

.macro multiply name, op, src
begin \name
mov rax,rdi
\op \src
mov rax,rdx
ret
end \name
.endm
multiply mul_high,mul,rsi
multiply mul_signed_high,imul,rsi
multiply mul_square_high,mul,rax

.macro multiply_extended name, high, low, retreg
begin \name
mov rdx,rdi
mulx \high,\low,rsi
mov rax,\retreg
ret
end \name
.endm
multiply_extended mulx_high,rax,rcx,rax
multiply_extended mulx_low,rcx,rax,rax
multiply_extended mulx_alias,rdx,rax,rdx
begin mulx32_high
mov edx,edi
mulx eax,ecx,esi
ret
end mulx32_high

begin xchg_pair
mov rax,rdi
xchg rax,rsi
sub rax,rsi
ret
end xchg_pair
begin xchg_address
mov rax,rdi
xchg rax,[rax]
ret
end xchg_address

.macro rotate_flags name, op, reg, flag
begin \name
mov eax,0x7fffffff
add eax,1
stc
mov rax,rdi
mov rcx,rdx
\op \reg,cl
set\flag al
movzx eax,al
ret
end \name
.endm
.macro shift_flags name, op, reg, source
begin \name
.ifc \source,pf
mov eax,1
test eax,eax
.else
mov eax,0x400
sahf
.endif
mov rax,rdi
mov rcx,rdx
\op \reg,cl
setp al
movzx eax,al
ret
end \name
.endm
rotate_flags rol8_c,rol,al,c
rotate_flags rol8_o,rol,al,o
rotate_flags ror8_c,ror,al,c
rotate_flags ror8_o,ror,al,o
rotate_flags rol16_c,rol,ax,c
rotate_flags rol16_o,rol,ax,o
rotate_flags ror16_c,ror,ax,c
rotate_flags ror16_o,ror,ax,o
rotate_flags rol32_c,rol,eax,c
rotate_flags rol32_o,rol,eax,o
rotate_flags ror32_c,ror,eax,c
rotate_flags ror32_o,ror,eax,o
rotate_flags rol64_c,rol,rax,c
rotate_flags rol64_o,rol,rax,o
rotate_flags ror64_c,ror,rax,c
rotate_flags ror64_o,ror,rax,o
shift_flags shl8_pf,shl,al,pf
shift_flags shl8_sahf_pf,shl,al,sahf_pf
shift_flags shr8_pf,shr,al,pf
shift_flags shr8_sahf_pf,shr,al,sahf_pf
shift_flags sar8_pf,sar,al,pf
shift_flags sar8_sahf_pf,sar,al,sahf_pf
shift_flags shl16_pf,shl,ax,pf
shift_flags shl16_sahf_pf,shl,ax,sahf_pf
shift_flags shr16_pf,shr,ax,pf
shift_flags shr16_sahf_pf,shr,ax,sahf_pf
shift_flags sar16_pf,sar,ax,pf
shift_flags sar16_sahf_pf,sar,ax,sahf_pf
shift_flags shl32_pf,shl,eax,pf
shift_flags shl32_sahf_pf,shl,eax,sahf_pf
shift_flags shr32_pf,shr,eax,pf
shift_flags shr32_sahf_pf,shr,eax,sahf_pf
shift_flags sar32_pf,sar,eax,pf
shift_flags sar32_sahf_pf,sar,eax,sahf_pf
shift_flags shl64_pf,shl,rax,pf
shift_flags shl64_sahf_pf,shl,rax,sahf_pf
shift_flags shr64_pf,shr,rax,pf
shift_flags shr64_sahf_pf,shr,rax,sahf_pf
shift_flags sar64_pf,sar,rax,pf
shift_flags sar64_sahf_pf,sar,rax,sahf_pf

.irp op,shld,shrd
.irp flag,c,o,z,s,p
begin \op\()_\flag
mov eax,0x7fffffff
add eax,1
stc
mov rax,rdi
mov rcx,rdx
\op rax,rsi,cl
set\flag al
movzx eax,al
ret
end \op\()_\flag
.endr
.endr

// Force a genuine diamond and a phi at the join, independent of compiler
// if-conversion of the C fixtures.
begin branch_phi
mov rax,rdi
test rdx,rdx
jz .Lphi_else
add rax,rsi
jmp .Lphi_merge
.Lphi_else:
sub rax,rsi
.Lphi_merge:
xor rax,0x55
ret
end branch_phi

.section .note.GNU-stack,"",@progbits
