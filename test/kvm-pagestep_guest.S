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

	mov $0x01, %bx
	cmp $0x00, %bx

	# NOTE: this needs to be a relative jmp
	je skip
.rept L1_LINESIZE * L1_SETS * 2
	nop
.endr
skip:

	mov $0x00, %ax
	jmp *%ax
guest_stop:

