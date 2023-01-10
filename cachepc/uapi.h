#pragma once

#include <linux/kvm.h>
#include <linux/types.h>
#include <linux/ioctl.h>

#define CPC_ISOLCPU 2

#define CPC_L1MISS_PMC 0
#define CPC_RETINST_PMC 1

#define L1_ASSOC 8
#define L1_LINESIZE 64
#define L1_SETS 64
#define L1_SIZE (L1_SETS * L1_ASSOC * L1_LINESIZE)

#define L2_ASSOC 8
#define L2_LINESIZE 64
#define L2_SETS 1024
#define L2_SIZE (L2_SETS * L2_ASSOC * L2_LINESIZE)

#define CPC_VMSA_MAGIC_ADDR ((void *) 0xC0FFEE)

#define KVM_HC_CPC_VMMCALL_SIGNAL 0xC0FFEE00
#define KVM_HC_CPC_VMMCALL_EXIT 0xC0FFEE01
#define CPC_DO_VMMCALL(action, type, val) \
	asm volatile("vmmcall" : : "a" (KVM_HC_CPC_VMMCALL_ ## action), \
		"b"(type), "c" (val) : "rdx")

#define KVM_CPC_RESET _IOWR(KVMIO, 0x20, __u32)
#define KVM_CPC_DEBUG _IOW(KVMIO, 0x21, __u32)

#define KVM_CPC_TEST_EVICTION _IOWR(KVMIO, 0x22, __u32)

#define KVM_CPC_READ_COUNTS _IOR(KVMIO, 0x25, __u64)

#define KVM_CPC_RESET_BASELINE _IO(KVMIO, 0x26)
#define KVM_CPC_READ_BASELINE _IOR(KVMIO, 0x27, __u64)
#define KVM_CPC_CALC_BASELINE _IOR(KVMIO, 0x28, __u32)
#define KVM_CPC_APPLY_BASELINE _IOR(KVMIO, 0x29, __u32)

#define KVM_CPC_SINGLE_STEP _IO(KVMIO, 0x2A)

#define KVM_CPC_VMSA_READ _IOR(KVMIO, 0x2C, __u64)
#define KVM_CPC_SVME_READ _IOR(KVMIO, 0x2D, __u32)

#define KVM_CPC_TRACK_MODE _IOWR(KVMIO, 0x40, __u32)
#define KVM_CPC_TRACK_PAGE _IOWR(KVMIO, 0x41, struct cpc_track_config)
#define KVM_CPC_TRACK_ALL _IOWR(KVMIO, 0x42, __u32)
#define KVM_CPC_UNTRACK_ALL _IOWR(KVMIO, 0x43, __u32)
#define KVM_CPC_RESET_TRACKING _IO(KVMIO, 0x44)
#define KVM_CPC_TRACK_RANGE_START _IOWR(KVMIO, 0x45, __u64)
#define KVM_CPC_TRACK_RANGE_END _IOWR(KVMIO, 0x46, __u64)
#define KVM_CPC_TRACK_EXEC_CUR _IOWR(KVMIO, 0x47, __u64)

#define KVM_CPC_POLL_EVENT _IOWR(KVMIO, 0x48, struct cpc_event)
#define KVM_CPC_ACK_EVENT _IOWR(KVMIO, 0x49, __u64)


enum {
	CPC_EVENT_NONE,
	CPC_EVENT_TRACK_STEP,
	CPC_EVENT_TRACK_PAGE,
	CPC_EVENT_CPUID,
};

enum {
	CPC_GUEST_START_TRACK,
	CPC_GUEST_STOP_TRACK,
};

enum {
	CPC_TRACK_NONE,
	CPC_TRACK_STUB,
	CPC_TRACK_EXEC,
	CPC_TRACK_FULL,
};

enum kvm_page_track_mode {
	KVM_PAGE_TRACK_WRITE,
	KVM_PAGE_TRACK_ACCESS,
	KVM_PAGE_TRACK_RESET_ACCESS,
	KVM_PAGE_TRACK_EXEC,
	KVM_PAGE_TRACK_RESET_EXEC,
	KVM_PAGE_TRACK_MAX,
};

struct cpc_track_config {
	__u64 gfn;
	__s32 mode;
};

struct cpc_track_step_event {
	__u64 fault_gfns[16];
	__u32 fault_errs[16];
	__u64 fault_count;
	__u64 timestamp_ns;
	__u64 retinst;
};

struct cpc_track_page_event {
	__u64 inst_gfn_prev;
	__u64 inst_gfn;
	__u64 timestamp_ns;
	__u64 retinst;
};

struct cpc_guest_event {
	__u64 type;
	__u64 val;
};

struct cpc_event {
	__u32 type;
	__u64 id;
	union {
		struct cpc_track_step_event step;
		struct cpc_track_page_event page;
		struct cpc_guest_event guest;
	};
};
