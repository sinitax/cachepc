#include "cachepc/const.h"

#define TARGET_SET 15

.global guest_start
.global guest_stop

guest_start:
	mov $(L1_LINESIZE * (L1_SETS + TARGET_SET)), %rbx
	mov $(L1_LINESIZE * (L1_SETS + TARGET_SET)), %rbx
	mov $(L1_LINESIZE * (L1_SETS + TARGET_SET)), %rbx
	mov $(L1_LINESIZE * (L1_SETS + TARGET_SET)), %rbx
	mov $(L1_LINESIZE * (L1_SETS + TARGET_SET)), %rbx
	mov $(L1_LINESIZE * (L1_SETS + TARGET_SET)), %rbx
	mov $(L1_LINESIZE * (L1_SETS + TARGET_SET)), %rbx
	jmp guest_start
guest_stop:

