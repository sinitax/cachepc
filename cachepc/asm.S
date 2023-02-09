#include "macro.S"

#include <linux/linkage.h>

.global cpc_read_pmc
.global cpc_eviction_prio_test_asm
.global cpc_prime_test1_asm
.global cpc_prime_test2_asm
.global cpc_prime_test3_asm
.global cpc_prime_probe_test_asm
.global cpc_stream_hwpf_test_asm
.global cpc_single_eviction_test_asm

# x86-64 calling convention specifies only these register need to be saved
# rbx, r12, r13, r14, r15, rbp and rsp need

SYM_FUNC_START(cpc_read_pmc)
    push %rbx

    readpmc %rdi %r8
    mov %r8, %rax

    pop %rbx

    ret
SYM_FUNC_END(cpc_read_pmc)

SYM_FUNC_START(cpc_stream_hwpf_test_asm)
    push %rbx

    wbinvd

    readpmc $0 %r8

    mov cpc_ds, %rdi
    prime stream_hwpf_test %rdi %rsi %r15

    readpmc $0 %r9

    mov %r9, %rax
    sub %r8, %rax

    pop %rbx

    ret
SYM_FUNC_END(cpc_stream_hwpf_test_asm)

SYM_FUNC_START(cpc_prime_test1_asm)
    push %rbx
    push %r12

    # this test checks wether the correct amount of cache lines
    # were evicted by prime, however it does not guarantee that the
    # L1 is filled completely with only our cache lines

    mov cpc_ds, %r10

    wbinvd

    readpmc $0 %r8
    prime_pass prime_test1_2 %r10 %r11 %r12
    readpmc $0 %r9

    mov %r9, %rax
    sub %r8, %rax

    pop %r12
    pop %rbx

    ret
SYM_FUNC_END(cpc_prime_test1_asm)

SYM_FUNC_START(cpc_prime_test2_asm)
    push %rbx
    push %r12

    # this test checks wether the L1 is filled *completely* with our cache
    # lines by prime, it does not however guarantee that the eviction
    # preference of the cachelines is in line-order (0 first, 7 last)

    mov cpc_ds, %r10

    wbinvd

    # try to convince replacement policy to
    # keep this line in
    mov (%rdi), %rax
    mov (%rdi), %rax
    mov (%rdi), %rax
    mov (%rdi), %rax
    mov (%rdi), %rax
    mov (%rdi), %rax
    mov (%rdi), %rax

    prime_pass prime_test2_1 %r10 %r11 %r12

    readpmc $0 %r8
    prime_pass prime_test2_2 %r12 %r11 %r10
    readpmc $0 %r9

    mov %r9, %rax
    sub %r8, %rax

    pop %r12
    pop %rbx

    ret
SYM_FUNC_END(cpc_prime_test2_asm)

SYM_FUNC_START(cpc_prime_test3_asm)
    push %rbx
    push %r12

    # this test is similar to test2 in that it checks wether
    # the cache is completely filled with our cache lines after prime,
    # this time just one prime+evict at a time

    mov cpc_ds, %r10

    wbinvd
    barrier

    mov (%rsi), %rax
    mov (%rsi), %rax
    mov (%rsi), %rax
    mov (%rsi), %rax
    mov (%rsi), %rax
    mov (%rsi), %rax
    mov (%rsi), %rax
    mov (%rsi), %rax

    prime_pass prime_test3 %r10 %r11 %r12

    readpmc $0 %r8
.rept L1_ASSOC
    mov CPC_CL_NEXT_OFFSET(%rdi), %rdi
.endr
    readpmc $0 %r9

    mov %r9, %rax
    sub %r8, %rax

    pop %r12
    pop %rbx

    ret
SYM_FUNC_END(cpc_prime_test3_asm)

SYM_FUNC_START(cpc_eviction_prio_test_asm)
    push %rbx
    push %r12

    mov cpc_ds, %r10

    wbinvd

    prime eviction_prio_test %r10 %r11 %r12

    mov (%rdi), %rax

    readpmc $0 %r8
    mov (%rsi), %rax
    readpmc $0 %r9

    mov %r9, %rax
    sub %r8, %rax

    pop %r12
    pop %rbx

    ret
SYM_FUNC_END(cpc_eviction_prio_test_asm)

SYM_FUNC_START(cpc_prime_probe_test_asm)
    push %rbx
    push %r12

    mov cpc_ds, %r9
    prime prime_probe_test %r9 %r10 %r8
    probe prime_probe_test $0 %r8 %r9 %r10 %r11 %r12

    pop %r12
    pop %rbx

    ret
SYM_FUNC_END(cpc_prime_probe_test_asm)

SYM_FUNC_START(cpc_single_eviction_test_asm)
    push %rbx
    push %r12
    push %r13

    readpmc $1 %r13

    mov cpc_ds, %r9
    prime single_eviction_test %r9 %r10 %r8
    mov (%rdi), %rax
    probe single_eviction_test $0 %r8 %r9 %r10 %r11 %r12

    readpmc $1 %r12
    mov %r12, %rax
    sub %r13, %rax

    pop %r13
    pop %r12
    pop %rbx

    ret
SYM_FUNC_END(cpc_single_eviction_test_asm)

