ENTRY(add_xor)
SECTIONS {
    . = 0x100000;
    .text : { *(.text*) }
    .rodata : { *(.rodata*) }
    .data : { *(.data*) *(.sdata*) }
    .bss : { *(.bss*) *(.sbss*) *(COMMON) }
    /DISCARD/ : { *(.eh_frame*) *(.comment*) }
}
observe = 0x110000;
mutate = 0x110010;
