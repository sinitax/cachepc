#include "test/kvm-eviction.h"
#include "cachepc/const.h"

.text
.align(16)
.code16gcc

guest:
    mov $(L1_LINESIZE * (L1_SETS + TARGET_SET)), %bx
    movb (%bx), %bl
    hlt

    jmp guest

