#include "event.h"
#include "track.h"
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
cachepc_send_event(struct cpc_event event)
{
	ktime_t deadline;

	read_lock(&cachepc_event_lock);
	if (!cachepc_events_init) {
		CPC_WARN("events ctx not initialized!\n");
		read_unlock(&cachepc_event_lock);
		return 1;
	}
	read_unlock(&cachepc_event_lock);

	write_lock(&cachepc_event_lock);
	 if (cachepc_last_event_sent != cachepc_last_event_acked) {
		CPC_WARN("event IDs out of sync\n");
		write_unlock(&cachepc_event_lock);
		return 1;
	} else {
		cachepc_last_event_sent++;
	}

	event.id = cachepc_last_event_sent;
	cachepc_event_avail = true;
	cachepc_event = event;
	write_unlock(&cachepc_event_lock);

	/* wait for ack with timeout */
	deadline = ktime_get_ns() + 20000000000ULL; /* 20s in ns */
	while (!cachepc_event_is_done(cachepc_event.id)) {
		if (ktime_get_ns() > deadline) {
			CPC_WARN("Timeout waiting for ack of event %llu\n",
				cachepc_event.id);
			return 3;
		}
	}

	return 0;
}

int
cachepc_send_guest_event(uint64_t type, uint64_t val)
{
	struct cpc_event event;

	event.type = CPC_EVENT_CPUID;
	event.guest.type = type;
	event.guest.val = val;

	return cachepc_send_event(event);
}

int
cachepc_send_track_step_event(struct list_head *list)
{
	struct cpc_event event = { 0 };
	struct cpc_fault *fault;
	uint64_t count;

	count = 0;
	event.type = CPC_EVENT_TRACK_STEP;
	list_for_each_entry(fault, list, list) {
		if (count >= 16)
			break;
		event.step.fault_gfns[count] = fault->gfn;
		event.step.fault_errs[count] = fault->err;
		count += 1;
	}
	event.step.fault_count = count;
	event.step.timestamp_ns = ktime_get_real_ns();
	event.step.retinst = cachepc_retinst;

	return cachepc_send_event(event);
}

int
cachepc_send_track_page_event(uint64_t gfn_prev, uint64_t gfn, uint64_t retinst)
{
	struct cpc_event event = { 0 };

	event.type = CPC_EVENT_TRACK_PAGE;
	event.page.inst_gfn_prev = gfn_prev;
	event.page.inst_gfn = gfn;
	event.page.timestamp_ns = ktime_get_real_ns();
	event.page.retinst = retinst;

	return cachepc_send_event(event);
}

int
cachepc_send_track_step_event_single(uint64_t gfn, uint32_t err, uint64_t retinst)
{
	struct cpc_event event = { 0 };

	event.type = CPC_EVENT_TRACK_STEP;
	event.step.fault_count = 1;
	event.step.fault_gfns[0] = gfn;
	event.step.fault_errs[0] = err;
	event.step.timestamp_ns = ktime_get_real_ns();
	event.step.retinst = retinst;

	return cachepc_send_event(event);
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
cachepc_handle_poll_event_ioctl(struct cpc_event __user *event)
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
		err = copy_to_user(event, &cachepc_event, sizeof(struct cpc_event));
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
	if (!eventid || eventid == cachepc_last_event_sent) {
		err = 0;
		cachepc_last_event_acked = cachepc_last_event_sent;
	} else {
		err = 1;
		CPC_WARN("Acked event (%llu) does not match sent (%llu)\n",
			eventid, cachepc_last_event_sent);
	}
	write_unlock(&cachepc_event_lock);

	return err;
}

