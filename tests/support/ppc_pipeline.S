/* Synthetic PPC32 big-endian programs. No game code or external SDK. */
.text
.macro begin name
.globl \name
.type \name,@function
\name:
.endm
.macro end name
.size \name,.-\name
.endm
.macro frame
 stwu 1,-32(1)
 mflr 0
 stw 0,36(1)
 stw 31,28(1)
.endm
.macro unframe
 lwz 31,28(1)
 lwz 0,36(1)
 mtlr 0
 addi 1,1,32
 blr
.endm

begin add_xor
 add 3,3,4
 xor 3,3,5
 blr
end add_xor

begin branch_value
 cmpwi 3,0
 beq 1f
 addi 3,4,7
 blr
1:
 addi 3,4,-5
 blr
end branch_value

begin counted_sum
 li 5,0
 cmpwi 3,0
 beq 2f
 mtctr 3
1:
 add 5,5,4
 bdnz 1b
2:
 mr 3,5
 blr
end counted_sum

begin memory_overlap
 stw 4,0(3)
 sth 5,2(3)
 lwz 3,0(3)
 blr
end memory_overlap

begin call_before_branch
 frame
 mr 31,4
 bl observe
 cmpwi 31,0
 beq 1f
 li 3,7
1:
 unframe
end call_before_branch

begin call_before_store
 frame
 bl observe
 lis 4,1
 li 5,9
 stw 5,0(4)
 unframe
end call_before_store

begin two_calls
 frame
 mr 31,3
 bl observe
 mr 3,31
 bl mutate
 unframe
end two_calls

begin carry_sum
 addc 3,3,4
 addze 3,3
 blr
end carry_sum
