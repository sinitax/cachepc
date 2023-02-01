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

struct cpc_event *cpc_eventbuf;
size_t cpc_eventbuf_len;
bool cpc_event_batching;

uint64_t cpc_last_event_sent;
uint64_t cpc_last_event_acked;
rwlock_t cpc_event_lock;

struct cpc_event cpc_event;
bool cpc_event_avail;

EXPORT_SYMBOL(cpc_send_guest_event);
EXPORT_SYMBOL(cpc_send_pause_event);
EXPORT_SYMBOL(cpc_send_track_step_event);
EXPORT_SYMBOL(cpc_send_track_step_event_single);
EXPORT_SYMBOL(cpc_send_track_page_event);

void
cpc_events_init(void)
{
	cpc_eventbuf = NULL;
	cpc_eventbuf_len = 0;
	cpc_event_batching = false;
	rwlock_init(&cpc_event_lock);
	cpc_events_reset();
}

void
cpc_events_deinit(void)
{
	kfree(cpc_eventbuf);
	cpc_eventbuf = NULL;
}

void
cpc_events_reset(void)
{
	write_lock(&cpc_event_lock);
	cpc_last_event_sent = 1;
	cpc_last_event_acked = 1;
	cpc_event_avail = false;
	write_unlock(&cpc_event_lock);
}

int
cpc_send_event(struct cpc_event event)
{
	ktime_t deadline;

	write_lock(&cpc_event_lock);
	 if (cpc_last_event_sent != cpc_last_event_acked) {
		CPC_WARN("event IDs out of sync\n");
		write_unlock(&cpc_event_lock);
		return 1;
	}

	if (cpc_event_batching) {
		if (cpc_eventbuf_len < CPC_EVENTBUF_CAP) {
			event.id = 0;
			memcpy(&cpc_eventbuf[cpc_eventbuf_len], &event,
				sizeof(struct cpc_event));
			cpc_eventbuf_len++;
			write_unlock(&cpc_event_lock);
			return 0;
		} else {
			cpc_event.type = CPC_EVENT_BATCH;
		}
	} else {
		cpc_event = event;
	}

	cpc_last_event_sent++;
	cpc_event.id = cpc_last_event_sent;
	cpc_event_avail = true;

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

int
cpc_send_pause_event(void)
{
	struct cpc_event event;

	event.type = CPC_EVENT_PAUSE;

	return cpc_send_event(event);
}

int
cpc_send_track_step_event(struct list_head *list)
{
	struct cpc_event event = { 0 };
	struct cpc_fault *fault;
	uint64_t count;

	count = 0;
	event.type = CPC_EVENT_TRACK_STEP;
	list_for_each_entry(fault, list, list) {
		if (count >= 8)
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

	write_lock(&cpc_event_lock);
	if (!cpc_event_avail) {
		write_unlock(&cpc_event_lock);
		return -EAGAIN;
	}

	err = 0;
	if (copy_to_user(arg_user, &cpc_event, sizeof(cpc_event)))
		err = -EFAULT;
	else
		cpc_event_avail = false;
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

int
cpc_read_events_ioctl(void __user *arg_user)
{
	struct cpc_batch_event batch;
	size_t n;

	if (!arg_user) return -EINVAL;

	if (copy_from_user(&batch, arg_user, sizeof(batch)))
		return -EFAULT;

	if (!batch.buf || !batch.maxcnt) return -EINVAL;

	write_lock(&cpc_event_lock);
	if (!cpc_eventbuf_len) {
		write_unlock(&cpc_event_lock);
		return -EAGAIN;
	}

	n = cpc_eventbuf_len;
	if (batch.maxcnt < n)
		n = batch.maxcnt;

	if (copy_to_user(batch.buf, cpc_eventbuf, sizeof(struct cpc_event) * n)) {
		write_unlock(&cpc_event_lock);
		return -EFAULT;
	}
	write_unlock(&cpc_event_lock);

	return 0;
}
