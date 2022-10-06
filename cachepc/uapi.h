#pragma once

#include <linux/kvm.h>
#include <linux/types.h>
#include <linux/ioctl.h>

#define KVM_CPC_TEST_ACCESS _IOWR(KVMIO, 0x20, __u32)
#define KVM_CPC_TEST_EVICTION _IOWR(KVMIO, 0x21, __u32)
#define KVM_CPC_INIT_PMC _IOW(KVMIO, 0x22, __u32)
#define KVM_CPC_READ_PMC _IOWR(KVMIO, 0x23, __u32)
#define KVM_CPC_READ_COUNTS _IOR(KVMIO, 0x24, __u64)

#define KVM_TRACK_PAGE _IOWR(KVMIO, 0x30, track_page_param_t)
#define KVM_USPT_REGISTER_PID _IOWR(KVMIO, 0x31, userspace_ctx_t)
#define KVM_USPT_WAIT_AND_SEND _IO(KVMIO, 0x32)
#define KVM_USPT_POLL_EVENT _IOWR(KVMIO, 0x33, page_fault_event_t)
#define KVM_USPT_ACK_EVENT _IOWR(KVMIO, 0x34, ack_event_t)
#define KVM_READ_GUEST_MEMORY _IOWR(KVMIO, 0x35, read_guest_memory_t)
#define KVM_USPT_RESET _IO(KVMIO, 0x36)
#define KVM_USPT_TRACK_ALL _IOWR(KVMIO, 0x37, track_all_pages_t)
#define KVM_USPT_UNTRACK_ALL _IOWR(KVMIO, 0x38, track_all_pages_t)
#define KVM_USPT_SETUP_RETINSTR_PERF _IOWR(KVMIO, 0x39, retired_instr_perf_config_t)
#define KVM_USPT_READ_RETINSTR_PERF _IOWR(KVMIO, 0x3A, retired_instr_perf_t)
#define KVM_USPT_BATCH_TRACK_START _IOWR(KVMIO, 0x3B, batch_track_config_t)
#define KVM_USPT_BATCH_TRACK_STOP _IOWR(KVMIO, 0x3C, batch_track_stop_and_get_t)
#define KVM_USPT_BATCH_TRACK_EVENT_COUNT _IOWR(KVMIO, 0x3D, batch_track_event_count_t)

#define KVM_USPT_POLL_EVENT_NO_EVENT 1000
#define KVM_USPT_POLL_EVENT_GOT_EVENT 0

enum kvm_page_track_mode {
	KVM_PAGE_TRACK_WRITE,
	KVM_PAGE_TRACK_ACCESS,
	KVM_PAGE_TRACK_RESET_ACCESSED,
	KVM_PAGE_TRACK_EXEC,
	KVM_PAGE_TRACK_RESET_EXEC,
	KVM_PAGE_TRACK_MAX,
};

typedef struct {
	__u64 id; // filled automatically
	__u64 faulted_gpa;
	__u32 error_code;
	__u8 have_rip_info;
	__u64 rip;
	__u64 ns_timestamp;
	__u8 have_retired_instructions;
	__u64 retired_instructions;
} page_fault_event_t;

typedef struct {
	__s32 tracking_type;
	__u64 expected_events;
	__s32 perf_cpu;
	__u8 retrack;
} batch_track_config_t;

typedef struct {
	__u64 event_count;
} batch_track_event_count_t;

typedef struct {
	page_fault_event_t* out_buf;
	__u64 len;
	__u8 error_during_batch;
} batch_track_stop_and_get_t;

typedef struct {
	__s32 cpu; // cpu on which we want to read the counter
	__u64 retired_instruction_count; // result param
} retired_instr_perf_t;

typedef struct {
	__s32 cpu; // cpu on which counter should be programmed
} retired_instr_perf_config_t;

typedef struct {
	__u64 gpa;
	__u64 len;
	__u8 decrypt_with_host_key;
	__s32 wbinvd_cpu; // -1: do not flush; else logical cpu on which we flush
	void *output_buffer;
} read_guest_memory_t;

typedef struct {
	__s32 pid;
	__u8 get_rip;
} userspace_ctx_t;

typedef struct {
	__u64 id;
} ack_event_t;

typedef struct {
	__u64 gpa;
	__s32 track_mode;
} track_page_param_t;

typedef struct {
	__s32 track_mode;
} track_all_pages_t;

