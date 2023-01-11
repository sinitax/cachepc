#include "kvm-eviction.h"
#include "cachepc/const.h"

#define TARGET_SET 15

.global start_guest_with
.global stop_guest_with

.global start_guest_without
.global stop_guest_without

start_guest_with:
    mov $(L1_LINESIZE * TARGET_SET), %rbx
    mov (%rbx), %bl
    mov $KVM_HC_CPC_VMMCALL_EXIT, %rax
    vmmcall
    jmp start_guest_with
stop_guest_with:

start_guest_without:
    mov $KVM_HC_CPC_VMMCALL_EXIT, %rax
    vmmcall
    jmp start_guest_without
stop_guest_without:
