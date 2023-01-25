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

uint64_t cachepc_last_event_sent;
uint64_t cachepc_last_event_acked;
rwlock_t cachepc_event_lock;

struct cpc_event cachepc_event;
bool cachepc_event_avail;

bool cachepc_events_init;

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

	CPC_DBG("Sent Event: id %llu\n", event.id);
	write_unlock(&cachepc_event_lock);

	/* wait for ack with timeout */
	deadline = ktime_get_ns() + 10000000000ULL; /* 10s in ns */
	while (!cachepc_event_is_done(cachepc_event.id)) {
		if (ktime_get_ns() > deadline) {
			CPC_WARN("Timeout waiting for ack of event %llu\n",
				cachepc_event.id);
			return 1;
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
EXPORT_SYMBOL(cachepc_send_guest_event);

int
cachepc_send_pause_event(void)
{
	struct cpc_event event;

	event.type = CPC_EVENT_PAUSE;

	return cachepc_send_event(event);
}
EXPORT_SYMBOL(cachepc_send_pause_event);

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
EXPORT_SYMBOL(cachepc_send_track_step_event);

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
EXPORT_SYMBOL(cachepc_send_track_page_event);

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
EXPORT_SYMBOL(cachepc_send_track_step_event_single);

bool
cachepc_event_is_done(uint64_t id)
{
	bool done;

	read_lock(&cachepc_event_lock);
	CPC_DBG("Event Send: Event not done %llu %llu\n",
		cachepc_last_event_acked, id);
	done = cachepc_last_event_acked == id;
	read_unlock(&cachepc_event_lock);

	return done;
}

int
cachepc_poll_event_ioctl(void __user *arg_user)
{
	int err;

	read_lock(&cachepc_event_lock);
	if (!cachepc_event_avail) {
		CPC_DBG("Event Poll: No event avail %llu %llu\n",
			cachepc_last_event_sent, cachepc_last_event_acked);
		read_unlock(&cachepc_event_lock);
		return -EAGAIN;
	}
	read_unlock(&cachepc_event_lock);

	err = 0;
	write_lock(&cachepc_event_lock);
	if (cachepc_event_avail) {
		CPC_DBG("Event Poll: Event is avail %px %llu %llu\n", arg_user,
			cachepc_last_event_sent, cachepc_last_event_acked);
		err = copy_to_user(arg_user, &cachepc_event, sizeof(cachepc_event));
		if (err != 0) {
			CPC_ERR("copy_to_user %i %lu\n", err, sizeof(cachepc_event));
			err = -EFAULT;
		}
	} else {
		CPC_DBG("Event Poll: Event was avail %llu %llu\n",
			cachepc_last_event_sent, cachepc_last_event_acked);
		err = -EAGAIN;
	}
	if (!err) cachepc_event_avail = false;
	write_unlock(&cachepc_event_lock);

	return err;
}

int
cachepc_ack_event_ioctl(void __user *arg_user)
{
	uint64_t eventid;
	int err;

	if (!arg_user) return -EINVAL;

	if (copy_from_user(&eventid, arg_user, sizeof(eventid)))
		return -EFAULT;

	err = 0;
	write_lock(&cachepc_event_lock);
	if (!eventid || eventid == cachepc_last_event_sent) {
		if (cachepc_event.type == CPC_EVENT_PAUSE)
			cachepc_pause_vm = false;
		cachepc_last_event_acked = cachepc_last_event_sent;
	} else {
		err = -EFAULT;
		CPC_WARN("Acked event (%llu) does not match sent (%llu)\n",
			eventid, cachepc_last_event_sent);
	}
	write_unlock(&cachepc_event_lock);

	return err;
}

