#include "cachepc/const.h"

#define TARGET_SET 15

.text
.align(16)
.code16gcc

guest:
.rept L1_SIZE
    nop
.endr

# instruction on page boundary test
    nop
.rept 2
.rept L1_LINESIZE * L1_SETS - 2
    nop
.endr
    rdtsc # two byte instruction
.endr
# ---------------------------------

# speculation on conditional jump test
    mov $0x01, %bx
    cmp $0x00, %bx

    je skip
.rept L1_LINESIZE * L1_SETS * 2
    nop
.endr
skip:
# -----------------------------------

    jmp guest

