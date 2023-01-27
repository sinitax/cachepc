#pragma once

#include "const.h"

#include <linux/kvm.h>
#include <linux/types.h>
#include <linux/ioctl.h>

#define CPC_DO_VMMCALL(action, type, val) \
	asm volatile("vmmcall" : : "a" (action), "b"(type), "c" (val) : "rdx")

#define KVM_CPC_RESET _IOWR(KVMIO, 0x20, __u32)
#define KVM_CPC_DEBUG _IOW(KVMIO, 0x21, __u32)

#define KVM_CPC_MEMORY_ENCRYPT_OP _IOWR(KVMIO, 0x22, struct kvm_sev_cmd)

#define KVM_CPC_TEST_EVICTION _IOWR(KVMIO, 0x24, __u32)

#define KVM_CPC_READ_COUNTS _IOR(KVMIO, 0x25, __u64)

#define KVM_CPC_RESET_BASELINE _IO(KVMIO, 0x26)
#define KVM_CPC_READ_BASELINE _IOR(KVMIO, 0x27, __u64)
#define KVM_CPC_CALC_BASELINE _IOR(KVMIO, 0x28, __u32)
#define KVM_CPC_APPLY_BASELINE _IOR(KVMIO, 0x29, __u32)

#define KVM_CPC_LONG_STEP _IO(KVMIO, 0x2A)

#define KVM_CPC_TRACK_MODE _IOWR(KVMIO, 0x40, __u32)
#define KVM_CPC_RESET_TRACKING _IO(KVMIO, 0x44)

#define KVM_CPC_POLL_EVENT _IOWR(KVMIO, 0x48, struct cpc_event)
#define KVM_CPC_ACK_EVENT _IOWR(KVMIO, 0x49, __u64)

#define KVM_CPC_VM_REQ_PAUSE _IO(KVMIO, 0x50)

#define KVM_SEV_CACHEPC 0xd0

enum {
	CPC_EVENT_NONE,
	CPC_EVENT_TRACK_STEP,
	CPC_EVENT_TRACK_PAGE,
	CPC_EVENT_PAUSE,
	CPC_EVENT_GUEST,
};

enum {
	CPC_GUEST_START_TRACK,
	CPC_GUEST_STOP_TRACK,
};

enum {
	CPC_TRACK_NONE,
	CPC_TRACK_FAULT_NO_RUN,
	CPC_TRACK_EXIT_EVICTIONS,
	CPC_TRACK_PAGES,
	CPC_TRACK_PAGES_RESOLVE,
	CPC_TRACK_STEPS,
	CPC_TRACK_STEPS_AND_FAULTS,
	CPC_TRACK_STEPS_SIGNALLED,
};

enum {
	SEV_CPC_GET_RIP
};

struct cpc_track_config {
	__u64 gfn;
	__s32 mode;
};

struct cpc_track_step_event {
	__u64 fault_gfns[16];
	__u32 fault_errs[16];
	__u64 fault_count;
	__u64 inst_gfn;
	__u64 retinst;
};

struct cpc_track_page_event {
	__u64 inst_gfn_prev;
	__u64 inst_gfn;
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

struct cpc_sev_cmd {
	__u32 id;
	__u64 data;
};
