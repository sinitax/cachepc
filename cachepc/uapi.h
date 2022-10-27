#pragma once

#include <linux/kvm.h>
#include <linux/types.h>
#include <linux/ioctl.h>

#define CPC_ISOLCPU 2

#define CPC_L1MISS_PMC 0
#define CPC_RETINST_PMC 1

#define CPC_MSRMT_MAX (~((cpc_msrmt_t) 0))

#define KVM_CPC_TEST_ACCESS _IOWR(KVMIO, 0x20, __u32)
#define KVM_CPC_TEST_EVICTION _IOWR(KVMIO, 0x21, __u32)
#define KVM_CPC_INIT_PMC _IOW(KVMIO, 0x22, __u32)
#define KVM_CPC_READ_PMC _IOWR(KVMIO, 0x23, __u32)
#define KVM_CPC_READ_COUNTS _IOR(KVMIO, 0x24, __u64)
#define KVM_CPC_SETUP_PMC _IO(KVMIO, 0x25)
#define KVM_CPC_MEASURE_BASELINE _IOW(KVMIO, 0x26, __u32)
#define KVM_CPC_READ_BASELINE _IOR(KVMIO, 0x27, __u64)
#define KVM_CPC_SUB_BASELINE _IOR(KVMIO, 0x28, __u32)

#define KVM_CPC_TRACK_PAGE _IOWR(KVMIO, 0x30, struct cpc_track_config)
#define KVM_CPC_TRACK_ALL _IOWR(KVMIO, 0x31, __u64)
#define KVM_CPC_UNTRACK_ALL _IOWR(KVMIO, 0x32, __u64)
#define KVM_CPC_RESET_TRACKING _IO(KVMIO, 0x33)
#define KVM_CPC_POLL_EVENT _IOWR(KVMIO, 0x34, struct cpc_track_event)
#define KVM_CPC_ACK_EVENT _IOWR(KVMIO, 0x35, __u64)

#define CPC_USPT_POLL_EVENT_NO_EVENT 1000
#define CPC_USPT_POLL_EVENT_GOT_EVENT 0

enum kvm_page_track_mode {
	KVM_PAGE_TRACK_WRITE,
	KVM_PAGE_TRACK_ACCESS,
	KVM_PAGE_TRACK_RESET_ACCESSED,
	KVM_PAGE_TRACK_EXEC,
	KVM_PAGE_TRACK_RESET_EXEC,
	KVM_PAGE_TRACK_MAX,
};

struct cpc_track_config {
	__u64 gpa;
	__s32 track_mode;
};

struct cpc_track_event {
	__u64 id; /* filled automatically */
	__u64 faulted_gpa;
	__u32 error_code;
	__u8 have_rip_info;
	__u64 rip;
	__u64 ns_timestamp;
	__u8 have_retired_instructions;
	__u64 retired_instructions;
};

typedef __u64 cpc_msrmt_t;
