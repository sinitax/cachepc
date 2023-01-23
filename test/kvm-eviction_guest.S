#include "test/kvm-eviction.h"
#include "cachepc/const.h"

.global guest_with_start
.global guest_with_stop

.global guest_without_start
.global guest_without_stop

.align(16)
.code16gcc

guest_with_start:
	mov $(L1_LINESIZE * (L1_SETS + TARGET_SET)), %bx
    movb (%bx), %bl
	hlt

    mov $0x00, %ax
	jmp *%ax
guest_with_stop:

guest_without_start:
	hlt
	mov $0x00, %ax
    jmp *%ax
guest_without_stop:
