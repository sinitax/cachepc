#pragma once

#include "uapi.h"

#include <linux/swait.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/types.h>

void cachepc_events_reset(void);

int cachepc_send_guest_event(uint64_t type, uint64_t val);
int cachepc_send_pause_event(void);
int cachepc_send_track_step_event(struct list_head *list);
int cachepc_send_track_step_event_single(uint64_t gfn, uint32_t err, uint64_t retinst);
int cachepc_send_track_page_event(uint64_t gfn_prev, uint64_t gfn, uint64_t retinst);

bool cachepc_event_is_done(uint64_t id);

int cachepc_handle_poll_event_ioctl(struct cpc_event *user);
int cachepc_handle_ack_event_ioctl(uint64_t eventid);
