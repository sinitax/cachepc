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

#define CPC_MSRMT_MAX (~((cpc_msrmt_t) 0))

#define CPC_RETINST_KERNEL 4327

#define CPC_CPUID_SIGNAL(type, val) \
	asm volatile("cpuid" : : "a" (CPC_CPUID_MAGIC(type)), "c" (val) \
		: "ebx", "edx")
#define CPC_CPUID_MAGIC(type) (CPC_CPUID_MAGIC_VAL | (type & CPC_CPUID_TYPE_MASK))
#define CPC_CPUID_MAGIC_VAL  ((__u32) 0xC0FFEE00)
#define CPC_CPUID_MAGIC_MASK ((__u32) 0xFFFFFF00)
#define CPC_CPUID_TYPE_MASK  ((__u32) 0x000000FF)

#define CPC_VMSA_MAGIC_ADDR ((void *) 0xC0FFEE)

#define KVM_CPC_TEST_ACCESS _IOWR(KVMIO, 0x20, __u32)
#define KVM_CPC_TEST_EVICTION _IOWR(KVMIO, 0x21, __u32)
#define KVM_CPC_INIT_PMC _IOW(KVMIO, 0x22, __u32)
#define KVM_CPC_READ_PMC _IOWR(KVMIO, 0x23, __u32)
#define KVM_CPC_READ_COUNTS _IOR(KVMIO, 0x24, __u64)
#define KVM_CPC_SETUP_PMC _IO(KVMIO, 0x25)
#define KVM_CPC_MEASURE_BASELINE _IOW(KVMIO, 0x26, __u32)
#define KVM_CPC_READ_BASELINE _IOR(KVMIO, 0x27, __u64)
#define KVM_CPC_SUB_BASELINE _IOR(KVMIO, 0x28, __u32)
#define KVM_CPC_SINGLE_STEP _IO(KVMIO, 0x29)
#define KVM_CPC_TRACK_MODE _IOWR(KVMIO, 0x2A, __u32)
#define KVM_CPC_VMSA_READ _IOR(KVMIO, 0x2B, __u64)

#define KVM_CPC_TRACK_PAGE _IOWR(KVMIO, 0x30, struct cpc_track_config)
#define KVM_CPC_TRACK_ALL _IOWR(KVMIO, 0x31, __u64)
#define KVM_CPC_UNTRACK_ALL _IOWR(KVMIO, 0x32, __u64)
#define KVM_CPC_RESET_TRACKING _IO(KVMIO, 0x33)
#define KVM_CPC_POLL_EVENT _IOWR(KVMIO, 0x34, struct cpc_track_event)
#define KVM_CPC_ACK_EVENT _IOWR(KVMIO, 0x35, __u64)

enum {
	CPC_EVENT_NONE,
	CPC_EVENT_TRACK,
	CPC_EVENT_CPUID
};

enum {
	CPC_CPUID_START_TRACK,
	CPC_CPUID_STOP_TRACK,	
};

enum {
	CPC_TRACK_NONE,
	CPC_TRACK_ACCESS,
	CPC_TRACK_DATA_ACCESS,
	CPC_TRACK_EXEC_PAGES
};

enum {
	CPC_TRACK_AWAIT_INST_FAULT,
	CPC_TRACK_AWAIT_DATA_FAULT,
	CPC_TRACK_AWAIT_STEP_INTR
};

enum kvm_page_track_mode {
	KVM_PAGE_TRACK_WRITE,
	KVM_PAGE_TRACK_ACCESS,
	KVM_PAGE_TRACK_RESET_ACCESSED,
	KVM_PAGE_TRACK_EXEC,
	KVM_PAGE_TRACK_RESET_EXEC,
	KVM_PAGE_TRACK_MAX,
};

struct cpc_track_config {
	__u64 gfn;
	__s32 mode;
};

struct cpc_track_event {
	__u64 inst_fault_gfn;
	__u64 inst_fault_err;
	__u32 data_fault_avail;
	__u64 data_fault_gfn;
	__u32 data_fault_err;
	__u64 timestamp_ns;
	__u64 retinst;
};

struct cpc_cpuid_event {
	__u8 type;
	__u32 val;
};

struct cpc_event {
	__u32 type;
	__u64 id;
	union {
		struct cpc_track_event track;
		struct cpc_cpuid_event cpuid;
	};
};

typedef __u64 cpc_msrmt_t;
