#pragma once

#include "uapi.h"

#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/types.h>

extern uint64_t cachepc_last_event_sent;
extern uint64_t cachepc_last_event_acked;
extern rwlock_t cachepc_event_lock;

extern struct cpc_event cachepc_event;
extern bool cachepc_event_avail;

extern bool cachepc_events_init;

void cachepc_events_reset(void);

int cachepc_send_guest_event(uint64_t type, uint64_t val);
int cachepc_send_track_event(uint64_t inst_fault_gfn, uint32_t inst_fault_err,
	uint64_t data_fault_gfn, uint32_t data_fault_err);
bool cachepc_event_is_done(uint64_t id);

int cachepc_handle_poll_event_ioctl(struct cpc_event *user);
int cachepc_handle_ack_event_ioctl(uint64_t eventid);
