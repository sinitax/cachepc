#include "events.h"
#include "tracking.h"
#include "cachepc.h"
#include "uapi.h"

#include <linux/kvm.h>
#include <linux/timekeeping.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/vmalloc.h>
#include <linux/printk.h>
#include <linux/ratelimit.h>

#define ARRLEN(x) (sizeof(x)/sizeof((x)[0]))

void
cachepc_events_reset(void)
{
	write_lock(&cachepc_event_lock);
	cachepc_events_init = true;
	cachepc_last_event_sent = 1;
	cachepc_last_event_acked = 1;
	cachepc_event_avail = false;
	write_unlock(&cachepc_event_lock);
}

int
cachepc_send_tracking_event(uint64_t inst_fault_gfn, uint32_t inst_fault_err,
	uint64_t data_fault_gfn, uint32_t data_fault_err)
{
	struct cpc_track_event event;
	ktime_t deadline;

	read_lock(&cachepc_event_lock);
	if (!cachepc_events_init) {
		pr_warn("CachePC: events ctx not initialized!\n");
		read_unlock(&cachepc_event_lock);
		return 1;
	}
	read_unlock(&cachepc_event_lock);

	write_lock(&cachepc_event_lock);
	 if (cachepc_last_event_sent != cachepc_last_event_acked) {
		pr_warn("CachePC: event IDs out of sync\n");
		write_unlock(&cachepc_event_lock);
		return 1;
	} else {
		cachepc_last_event_sent++;
	}
	event.id = cachepc_last_event_sent;
	event.inst_fault_gfn = inst_fault_gfn;
	event.inst_fault_err = inst_fault_err;
	event.data_fault_avail = (data_fault_err != 0);
	event.data_fault_gfn = data_fault_gfn;
	event.data_fault_err = data_fault_err;
	event.timestamp_ns = ktime_get_real_ns();
	event.retinst = cachepc_retinst;

	cachepc_event_avail = true;
	cachepc_event = event;
	write_unlock(&cachepc_event_lock);

	/* wait for ack with timeout */
	deadline = ktime_get_ns() + 2000000000ULL; /* 2s in ns */
	while (!cachepc_event_is_done(cachepc_event.id)) {
		if (ktime_get_ns() > deadline) {
			pr_warn("CachePC: Timeout waiting for ack of event %llu\n",
				cachepc_event.id);
			return 3;
		}
	}

	return 0;
}

bool
cachepc_event_is_done(uint64_t id)
{
	bool done;

	read_lock(&cachepc_event_lock);
	done = cachepc_last_event_acked >= id;
	read_unlock(&cachepc_event_lock);

	return done;
}

int
cachepc_handle_poll_event_ioctl(struct cpc_track_event __user *event)
{
	int err;

	read_lock(&cachepc_event_lock);
	if (!cachepc_event_avail) {
		read_unlock(&cachepc_event_lock);
		return -EAGAIN;
	}
	read_unlock(&cachepc_event_lock);

	write_lock(&cachepc_event_lock);
	if (cachepc_event_avail) {
		err = copy_to_user(event, &cachepc_event,
			sizeof(struct cpc_track_event));
		cachepc_event_avail = false;
	} else {
		err = -EAGAIN;
	}
	write_unlock(&cachepc_event_lock);

	return err;
}

int
cachepc_handle_ack_event_ioctl(uint64_t eventid)
{
	int err;

	write_lock(&cachepc_event_lock);
	if (eventid == cachepc_last_event_sent) {
		err = 0;
		cachepc_last_event_acked = cachepc_last_event_sent;
	} else {
		err = 1;
		pr_warn("CachePC: Acked event does not match sent: %llu %llu\n",
			cachepc_last_event_sent, eventid);
	}
	write_unlock(&cachepc_event_lock);

	return err;
}

