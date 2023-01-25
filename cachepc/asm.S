#include "macro.S"

#include <linux/linkage.h>

.global cachepc_read_pmc
.global cachepc_prime_probe_test_asm
.global cachepc_stream_hwpf_test_asm
.global cachepc_single_eviction_test_asm

SYM_FUNC_START(cachepc_read_pmc)
    push %rbx
    push %rcx
    push %rdx
    push %r8

    readpmc %rdi %r8
    mov %r8, %rax

    pop %r8
    pop %rdx
    pop %rcx
    pop %rbx

    ret
SYM_FUNC_END(cachepc_read_pmc)

SYM_FUNC_START(cachepc_prime_probe_test_asm)
    push %rbx
    push %rcx
    push %rdx
    push %r8
    push %r9
    push %r10
    push %r11
    push %r12

    wbinvd

    mov cachepc_ds, %r9
    prime prime_probe_test %r9 %r10 %r8
    prime prime_probe_test1 %r9 %r10 %r8
    prime prime_probe_test2 %r9 %r10 %r8
    probe prime_probe_test %r8 %r9 %r10 %r11 %r12

    pop %r12
    pop %r11
    pop %r10
    pop %r9
    pop %r8
    pop %rdx
    pop %rcx
    pop %rbx

    ret
SYM_FUNC_END(cachepc_prime_probe_test_asm)

SYM_FUNC_START(cachepc_stream_hwpf_test_asm)
    push %rbx
    push %rcx
    push %rdx
    push %r8
    push %r9

    wbinvd

    readpmc $CPC_L1MISS_PMC %r8

    mov 0x000(%rdi), %rax
    mov 0x040(%rdi), %rax
    mov 0x080(%rdi), %rax
    mov 0x0c0(%rdi), %rax
    mov 0x100(%rdi), %rax
    mov 0x140(%rdi), %rax
    mov 0x180(%rdi), %rax
    mov 0x1c0(%rdi), %rax
    mov 0x200(%rdi), %rax
    mov 0x240(%rdi), %rax

    readpmc $CPC_L1MISS_PMC %r9

    mov %r9, %rax
    sub %r8, %rax

    pop %r9
    pop %r8
    pop %rdx
    pop %rcx
    pop %rbx

    ret
SYM_FUNC_END(cachepc_stream_hwpf_test_asm)

SYM_FUNC_START(cachepc_single_eviction_test_asm)
    push %rbx
    push %rcx
    push %rdx
    push %r8
    push %r9
    push %r10
    push %r11
    push %r12

    wbinvd

    mov cachepc_ds, %r9
    prime single_eviction_test %r9 %r10 %r8
    prime single_eviction_test2 %r9 %r10 %r8
    prime single_eviction_test3 %r9 %r10 %r8
    mov (%rdi), %rax
    probe single_eviction_test %r8 %r9 %r10 %r11 %r12

    pop %r12
    pop %r11
    pop %r10
    pop %r9
    pop %r8
    pop %rdx
    pop %rcx
    pop %rbx

    ret
SYM_FUNC_END(cachepc_single_eviction_test_asm)

