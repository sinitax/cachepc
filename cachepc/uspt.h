#pragma once

#include "uapi.h"

#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/types.h>

extern uint64_t last_sent_eventid;
extern uint64_t last_acked_eventid;
extern rwlock_t event_lock;

extern struct cpc_track_event sent_event;
extern bool have_event;

extern bool uspt_init;

bool sevstep_uspt_is_initialized(void);
void sevstep_uspt_clear(void);

int sevstep_uspt_send_and_block(uint64_t inst_fault_gfn, uint32_t inst_fault_err,
	uint64_t data_fault_gfn, uint32_t data_fault_err);
int sevstep_uspt_is_event_done(uint64_t id);

int sevstep_uspt_handle_poll_event(struct cpc_track_event *userpace_mem);
int sevstep_uspt_handle_ack_event_ioctl(uint64_t eventid);
