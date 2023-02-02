#pragma once

#include "uapi.h"

#include <linux/swait.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/types.h>

extern struct cpc_event *cpc_eventbuf;
extern size_t cpc_eventbuf_len;
extern bool cpc_event_batching;

void cpc_events_init(void);
void cpc_events_deinit(void);
void cpc_events_reset(void);

int cpc_send_guest_event(uint64_t type, uint64_t val);
int cpc_send_pause_event(void);
int cpc_send_track_step_event(struct list_head *list);
int cpc_send_track_step_event_single(uint64_t gfn, uint32_t err, uint64_t retinst);
int cpc_send_track_page_event(uint64_t gfn_prev, uint64_t gfn, uint64_t retinst);

bool cpc_event_is_done(void);

int cpc_poll_event_ioctl(void __user *arg_user);
int cpc_ack_event_ioctl(void __user *arg_user);
int cpc_batch_events_ioctl(void __user *arg_user);
int cpc_read_batch_ioctl(void __user *arg_user);
