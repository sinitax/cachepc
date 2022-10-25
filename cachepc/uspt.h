#pragma once

#include "uapi.h"

#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/types.h>


bool sevstep_uspt_is_initialiized(void);
void sevstep_uspt_clear(void);

bool sevstep_uspt_should_get_rip(void);

int sevstep_uspt_send_and_block(uint64_t faulted_gpa, uint32_t error_code,
	bool have_rip, uint64_t rip);
int sevstep_uspt_is_event_done(uint64_t id);

int sevstep_uspt_handle_poll_event(struct cpc_track_event *userpace_mem);

int sevstep_uspt_handle_ack_event_ioctl(uint64_t eventid);
