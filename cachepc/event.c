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

uint64_t cpc_last_event_sent;
uint64_t cpc_last_event_acked;
rwlock_t cpc_event_lock;

struct cpc_event cpc_event;
bool cpc_event_avail;

bool cpc_events_init;

void
cpc_events_reset(void)
{
	write_lock(&cpc_event_lock);
	cpc_events_init = true;
	cpc_last_event_sent = 1;
	cpc_last_event_acked = 1;
	cpc_event_avail = false;
	write_unlock(&cpc_event_lock);
}

int
cpc_send_event(struct cpc_event event)
{
	ktime_t deadline;

	read_lock(&cpc_event_lock);
	if (!cpc_events_init) {
		CPC_WARN("events ctx not initialized!\n");
		read_unlock(&cpc_event_lock);
		return 1;
	}
	read_unlock(&cpc_event_lock);

	write_lock(&cpc_event_lock);
	 if (cpc_last_event_sent != cpc_last_event_acked) {
		CPC_WARN("event IDs out of sync\n");
		write_unlock(&cpc_event_lock);
		return 1;
	} else {
		cpc_last_event_sent++;
	}

	event.id = cpc_last_event_sent;
	cpc_event_avail = true;
	cpc_event = event;

	//CPC_DBG("Sent Event: id %llu\n", event.id);
	write_unlock(&cpc_event_lock);

	/* wait for ack with timeout */
	deadline = ktime_get_ns() + 10000000000ULL; /* 10s in ns */
	while (!cpc_event_is_done()) {
		if (ktime_get_ns() > deadline) {
			CPC_WARN("Timeout waiting for ack of event %llu\n",
				cpc_event.id);
			return 1;
		}
	}

	return 0;
}

int
cpc_send_guest_event(uint64_t type, uint64_t val)
{
	struct cpc_event event;

	event.type = CPC_EVENT_GUEST;
	event.guest.type = type;
	event.guest.val = val;

	return cpc_send_event(event);
}
EXPORT_SYMBOL(cpc_send_guest_event);

int
cpc_send_pause_event(void)
{
	struct cpc_event event;

	event.type = CPC_EVENT_PAUSE;

	return cpc_send_event(event);
}
EXPORT_SYMBOL(cpc_send_pause_event);

int
cpc_send_track_step_event(struct list_head *list)
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
		if (fault->err & PFERR_FETCH_MASK)
			event.step.inst_gfn = fault->gfn;
		count += 1;
	}
	event.step.fault_count = count;
	event.step.retinst = cpc_retinst;

	return cpc_send_event(event);
}
EXPORT_SYMBOL(cpc_send_track_step_event);

int
cpc_send_track_page_event(uint64_t gfn_prev, uint64_t gfn, uint64_t retinst)
{
	struct cpc_event event = { 0 };

	event.type = CPC_EVENT_TRACK_PAGE;
	event.page.inst_gfn_prev = gfn_prev;
	event.page.inst_gfn = gfn;
	event.page.retinst = retinst;

	return cpc_send_event(event);
}
EXPORT_SYMBOL(cpc_send_track_page_event);

int
cpc_send_track_step_event_single(uint64_t gfn, uint32_t err, uint64_t retinst)
{
	struct cpc_event event = { 0 };

	event.type = CPC_EVENT_TRACK_STEP;
	event.step.fault_count = 1;
	event.step.fault_gfns[0] = gfn;
	event.step.fault_errs[0] = err;
	event.step.inst_gfn = gfn;
	event.step.retinst = retinst;

	return cpc_send_event(event);
}
EXPORT_SYMBOL(cpc_send_track_step_event_single);

bool
cpc_event_is_done(void)
{
	bool done;

	read_lock(&cpc_event_lock);
	done = cpc_last_event_acked == cpc_last_event_sent;
	read_unlock(&cpc_event_lock);

	return done;
}

int
cpc_poll_event_ioctl(void __user *arg_user)
{
	int err;

	read_lock(&cpc_event_lock);
	if (!cpc_event_avail) {
		read_unlock(&cpc_event_lock);
		return -EAGAIN;
	}
	read_unlock(&cpc_event_lock);

	err = 0;
	write_lock(&cpc_event_lock);
	if (cpc_event_avail) {
		if (copy_to_user(arg_user, &cpc_event, sizeof(cpc_event)))
			err = -EFAULT;
		else
			cpc_event_avail = false;
	} else {
		err = -EAGAIN;
	}
	write_unlock(&cpc_event_lock);

	return err;
}

int
cpc_ack_event_ioctl(void __user *arg_user)
{
	uint64_t eventid;
	int err;

	if (!arg_user) return -EINVAL;

	if (copy_from_user(&eventid, arg_user, sizeof(eventid)))
		return -EFAULT;

	err = 0;
	write_lock(&cpc_event_lock);
	if (!eventid || eventid == cpc_last_event_sent) {
		if (cpc_event.type == CPC_EVENT_PAUSE)
			cpc_pause_vm = false;
		cpc_last_event_acked = cpc_last_event_sent;
	} else {
		err = -EFAULT;
		CPC_WARN("Acked event (%llu) does not match sent (%llu)\n",
			eventid, cpc_last_event_sent);
	}
	write_unlock(&cpc_event_lock);

	return err;
}

