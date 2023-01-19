#include "cachepc/const.h"

#define TARGET_SET 15

.global guest_start
.global guest_stop

guest_start:
	mov $(L1_LINESIZE * (L1_SETS + 9)), %rbx
#	hlt
#	mov $(L1_LINESIZE * (L1_SETS + 10)), %rbx
	mov $(L1_LINESIZE * (L1_SETS + 11)), %rbx
#	hlt
#	mov $(L1_LINESIZE * (L1_SETS + 12)), %rbx
	mov $(L1_LINESIZE * (L1_SETS + 13)), %rbx
#	hlt
#	mov $(L1_LINESIZE * (L1_SETS + 14)), %rbx
	mov $(L1_LINESIZE * (L1_SETS + 15)), %rbx
	hlt
	jmp guest_start
guest_stop:

