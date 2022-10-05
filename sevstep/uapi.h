#pragma once

#include <linux/ioctl.h>
#include <linux/types.h>

#define KVM_TRACK_PAGE _IOWR(KVMIO, 0x20, track_page_param_t)
#define KVM_USPT_REGISTER_PID _IOWR(KVMIO, 0x21, userspace_ctx_t)
#define KVM_USPT_WAIT_AND_SEND _IO(KVMIO, 0x22)
#define KVM_USPT_POLL_EVENT _IOWR(KVMIO, 0x23, page_fault_event_t)
#define KVM_USPT_ACK_EVENT _IOWR(KVMIO, 0x24, ack_event_t)
#define KVM_READ_GUEST_MEMORY _IOWR(KVMIO, 0x25, read_guest_memory_t)
#define KVM_USPT_RESET _IO(KVMIO, 0x26)
#define KVM_USPT_TRACK_ALL _IOWR(KVMIO, 0x27, track_all_pages_t)
#define KVM_USPT_UNTRACK_ALL _IOWR(KVMIO, 0x28, track_all_pages_t)
#define KVM_USPT_SETUP_RETINSTR_PERF _IOWR(KVMIO, 0x30,retired_instr_perf_config_t)
#define KVM_USPT_READ_RETINSTR_PERF _IOWR(KVMIO,0x31, retired_instr_perf_t)
#define KVM_USPT_BATCH_TRACK_START _IOWR(KVMIO,0x32,batch_track_config_t)
#define KVM_USPT_BATCH_TRACK_STOP _IOWR(KVMIO,0x33,batch_track_stop_and_get_t)
#define KVM_USPT_BATCH_TRACK_EVENT_COUNT _IOWR(KVMIO,0x34,batch_track_event_count_t)

#define KVM_USPT_POLL_EVENT_NO_EVENT 1000
#define KVM_USPT_POLL_EVENT_GOT_EVENT 0

typedef struct {
	uint64_t id; // filled automatically
	uint64_t faulted_gpa;
	uint32_t error_code;
	bool have_rip_info;
	uint64_t rip;
	uint64_t ns_timestamp;
	bool have_retired_instructions;
	uint64_t retired_instructions;
} page_fault_event_t;

typedef struct {
	int tracking_type;
	uint64_t expected_events;
	int perf_cpu;
	bool retrack;
} batch_track_config_t;

typedef struct {
	uint64_t event_count;
} batch_track_event_count_t;

typedef struct {
	page_fault_event_t* out_buf;
	uint64_t len;
	bool error_during_batch;
} batch_track_stop_and_get_t;

typedef struct {
	int cpu; // cpu on which we want to read the counter
	uint64_t retired_instruction_count; // result param
} retired_instr_perf_t;

typedef struct {
	int cpu; // cpu on which counter should be programmed
} retired_instr_perf_config_t;

typedef struct {
	uint64_t gpa;
	uint64_t len;
	bool decrypt_with_host_key;
	int wbinvd_cpu; // -1: do not flush; else logical cpu on which we flush
	void* output_buffer;
} read_guest_memory_t;

typedef struct {
    int pid;
	bool get_rip;
} userspace_ctx_t;

typedef struct {
	uint64_t id;
} ack_event_t;

typedef struct {
	uint64_t gpa;
	int track_mode;
} track_page_param_t;

typedef struct {
	int track_mode;
} track_all_pages_t;

