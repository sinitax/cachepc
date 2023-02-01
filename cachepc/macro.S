#include "const.h"

# clobbers rax, rbx, rcx, rdx
.macro barrier
    mfence # memory barrier
    rdtsc # serializing
    # mov $0x80000005, %rax
    # cpuid # serializing (cpuid alone does not work)
.endm

# clobbers rax, rbx, rcx, rdx, (out)
.macro readpmc event out
    barrier

    mov $0, %rax
    mov $0, %rdx
    mov $0xc0010201, %rbx
    mov \event, %rcx
    shl $1, %rcx
    add %rbx, %rcx
    mov $0, %rbx
    rdmsr
    shl $32, %rdx
    or %rax, %rdx
    mov %rdx, \out

    barrier
.endm

# clobbers rax, rbx, rcx, rdx, cl_tmp, (cl_out)
.macro prime name cl_in cl_tmp cl_out
    barrier

    mov \cl_in, \cl_tmp
prime_loop_\name:
    mov \cl_tmp, \cl_out
    mov CPC_CL_NEXT_OFFSET(\cl_tmp), \cl_tmp
    cmp \cl_tmp, \cl_in
    jne prime_loop_\name

    barrier
.endm

# clobbers rax, rbx, rcx, rdx, cl_tmp1, cl_tmp2, pmc_tmp, pmc_tmp2
.macro probe name cl_in cl_tmp1 cl_tmp2 pmc_tmp1 pmc_tmp2
    barrier

    mov \cl_in, \cl_tmp1

probe_loop_\name:
    readpmc $CPC_L1MISS_PMC \pmc_tmp1

.rept L1_ASSOC-1
    mov CPC_CL_PREV_OFFSET(\cl_tmp1), \cl_tmp1
.endr
    mov CPC_CL_PREV_OFFSET(\cl_tmp1), \cl_tmp2

    readpmc $CPC_L1MISS_PMC \pmc_tmp2

    sub \pmc_tmp1, \pmc_tmp2
    mov \pmc_tmp2, CPC_CL_COUNT_OFFSET(\cl_tmp1)

    mov \cl_tmp2, \cl_tmp1
    cmp \cl_in, \cl_tmp1
    jne probe_loop_\name

    barrier
.endm
