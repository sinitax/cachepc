#include "test/kvm-eviction.h"
#include "cachepc/const.h"

.text
.align(16)
.code16gcc

guest:
    hlt

    jmp guest

