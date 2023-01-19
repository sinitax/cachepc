.global stream_hwpf_test

stream_hwpf_test:
    push %rbx
    push %rcx
    push %rdx
    push %r10
    push %r11

    wbinvd

    mfence
    mov $0x80000005,%eax
    cpuid

    mov $0, %rax
    mov $0, %rdx
    mov $0xc0010201,%rcx
    rdmsr
    shl $32, %rdx
    or %rax, %rdx

    mov %rdx, %r10

    mfence
    mov $0x80000005,%eax
    cpuid

    # mov 0x00(%rdi), %rax
    # mov 0x48(%rdi), %rax
    # mov 0x20(%rdi), %rax
    # mov 0x38(%rdi), %rax
    # mov 0x18(%rdi), %rax
    # mov 0x48(%rdi), %rax
    # mov 0x50(%rdi), %rax
    # mov 0x58(%rdi), %rax
    # mov 0x60(%rdi), %rax

    mfence
    mov $0x80000005,%eax
    cpuid

    mov $0, %rax
    mov $0, %rdx
    mov $0xc0010201,%rcx
    rdmsr
    shl $32, %rdx
    or %rax, %rdx

    mov %rdx, %r11

    mfence
    mov $0x80000005,%eax
    cpuid

    mov %r11, %rax
    sub %r10, %rax

    pop %r11
    pop %r10
    pop %rdx
    pop %rcx
    pop %rbx

    ret
