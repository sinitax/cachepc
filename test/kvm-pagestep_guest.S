#include "cachepc/const.h"

#define TARGET_SET 15

.text
.align(16)
.code16gcc

guest:
.rept L1_SIZE
    nop
.endr

    mov $0x01, %bx
    cmp $0x00, %bx

    je skip
.rept L1_LINESIZE * L1_SETS * 2
    nop
.endr
skip:

    jmp guest

