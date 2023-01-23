#include "cachepc/const.h"

#define TARGET_SET 15

.global guest_start
.global guest_stop

.align(16)
.code16gcc

guest_start:
	mov $(L1_LINESIZE * (L1_SETS + 11)), %bx
	movb (%bx), %bl
	hlt

	mov $(L1_LINESIZE * (L1_SETS + 13)), %bx
	movb (%bx), %bl
	hlt

	mov $(L1_LINESIZE * (L1_SETS + 15)), %bx
	movb (%bx), %bl
	hlt

	mov $0x00, %ax
	jmp *%ax
guest_stop:

