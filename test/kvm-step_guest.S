#include "cachepc/const.h"

#define TARGET_SET 15

.text
.align(16)
.code16gcc

guest:
    mov $(L1_LINESIZE * (L1_SETS + 11)), %bx
    movb (%bx), %bl
    hlt

    mov $(L1_LINESIZE * (L1_SETS + 13)), %bx
    movb (%bx), %bl
    hlt

    mov $(L1_LINESIZE * (L1_SETS + 15)), %bx
    movb (%bx), %bl
    hlt

    jmp guest

