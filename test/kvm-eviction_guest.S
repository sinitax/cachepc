#include "test/kvm-eviction.h"
#include "cachepc/const.h"

.global guest_with_start
.global guest_with_stop

.global guest_without_start
.global guest_without_stop

guest_with_start:
	movq (L1_LINESIZE * (TARGET_SET + L1_SETS)), %rbx
	hlt
	jmp guest_with_start
guest_with_stop:

guest_without_start:
	hlt
	jmp guest_without_start
guest_without_stop:
