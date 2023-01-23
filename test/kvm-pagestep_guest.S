#include "cachepc/const.h"

#define TARGET_SET 15

.global guest_start
.global guest_stop

.align(16)
.code16gcc

guest_start:
.rept L1_SIZE
	nop
.endr

	mov $0x00, %ax
	jmp *%ax
guest_stop:

