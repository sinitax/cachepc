#include "cachepc/const.h"

#define TARGET_SET 15

.text
.align(16)
.code16gcc

guest:
.rept L1_LINESIZE * L1_SETS * 2
    nop
.endr

    mov $0, %cx
    mov $CPC_GUEST_START_TRACK, %bx
    mov $KVM_HC_CPC_VMMCALL_SIGNAL, %ax
    vmmcall

    mov $(L1_LINESIZE * (L1_SETS + 11)), %bx
    movb (%bx), %bl

    mov $(L1_LINESIZE * (L1_SETS + 13)), %bx
    movb (%bx), %bl

    mov $(L1_LINESIZE * (L1_SETS + 15)), %bx
    movb (%bx), %bl

    # this should only be partially single-stepped if
    # single-stepping is limited to the first page
.rept L1_LINESIZE * L1_SETS * 2
    nop
.endr

    mov $0, %cx
    mov $CPC_GUEST_STOP_TRACK, %bx
    mov $KVM_HC_CPC_VMMCALL_SIGNAL, %ax
    vmmcall

    jmp guest

