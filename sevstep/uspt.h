#pragma once

#include "uapi.h"

#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/types.h>


int uspt_initialize(int pid,bool should_get_rip);
int uspt_is_initialiized(void);
void uspt_clear(void);

bool uspt_should_get_rip(void);

int uspt_send_and_block(uint64_t faulted_gpa, uint32_t error_code,
	bool have_rip, uint64_t rip);

int uspt_is_event_done(uint64_t id);

/* prepare next event based on faulted_gpa and error_code. Notify process
 * behind pid_number. Event must be polled id is result param with the id
 * used for the event. Can be used to call uspt_is_event_done */
int uspt_send_notification(int pid_number, uint64_t faulted_gpa,
	uint32_t error_code, uint64_t *id);

/* copy next event to userpace_mem */
int uspt_handle_poll_event(page_fault_event_t* userpace_mem);

/* acknowledge receival of event to event handling logic */
int uspt_handle_ack_event_ioctl(ack_event_t event);

/* should be called after "uspt_batch_tracking_save",
 * "uspt_batch_tracking_handle_retrack" and any future custom logic
 * for an event is processed */
void uspt_batch_tracking_inc_event_idx(void);
int uspt_batch_tracking_start(int tracking_type, uint64_t expected_events, int perf_cpu, bool retrack);
int uspt_batch_tracking_save(uint64_t faulted_gpa, uint32_t error_code, bool have_rip, uint64_t rip);
uint64_t uspt_batch_tracking_get_events_count(void);

/* Stops batch tracking on copies the first @len events into @result.
 * If an error occured at some point during the batch tracking,
 * error_occured is set(there should also be a dmesg, but this allows programatic access);
 * Caller can use uspt_batch_tracking_get_events_count() to determine the amount
 * of memory they should allocate for @results */
int uspt_batch_tracking_stop(page_fault_event_t *results, uint64_t len, bool *error_occured);
void uspt_batch_tracking_handle_retrack(struct kvm_vcpu *vcpu, uint64_t current_fault_gfn);
void uspt_batch_tracking_get_retrack_gfns(uint64_t **gfns, uint64_t *len, int *tracking_type);
bool uspt_batch_tracking_in_progress(void);
