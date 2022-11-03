#include "uspt.h"
#include "sevstep.h"
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
sevstep_uspt_clear(void)
{
	write_lock(&event_lock);
	uspt_init = true;
	last_sent_eventid = 1;
	last_acked_eventid = 1;
	have_event = false;
	write_unlock(&event_lock);
}

bool
sevstep_uspt_is_initialiized()
{
	return uspt_init;
}

int
sevstep_uspt_send_and_block(uint64_t fault_gfn, uint32_t error_code)
{
	struct cpc_track_event event;
	ktime_t deadline;

	read_lock(&event_lock);
	if (!sevstep_uspt_is_initialiized()) {
		pr_warn("Sevstep: uspt_send_and_block: ctx not initialized!\n");
		read_unlock(&event_lock);
		return 1;
	}
	read_unlock(&event_lock);

	write_lock(&event_lock);
	 if (last_sent_eventid != last_acked_eventid) {
		pr_warn("Sevstep: uspt_send_and_block: "
			"event id_s out of sync, aborting. Fix this later\n");
		write_unlock(&event_lock);
		return 1;
	} else {
		last_sent_eventid++;
	}
	event.id = last_sent_eventid;
	event.fault_gfn = fault_gfn;
	event.fault_err = error_code;
	event.timestamp_ns = ktime_get_real_ns();
	event.retinst = cachepc_retinst;

	have_event = true;
	sent_event = event;
	write_unlock(&event_lock);

	/* wait for ack with timeout */
	pr_warn("Sevstep: uspt_send_and_block: Begin wait for event ack");
	deadline = ktime_get_ns() + 2000000000ULL; /* 1s in ns */
	while (!sevstep_uspt_is_event_done(sent_event.id)) {
		if (ktime_get_ns() > deadline) {
			pr_warn("Sevstep: uspt_send_and_block: "
				"Waiting for ack of event %llu timed out",
				sent_event.id);
			return 3;
		}
	}

	return 0;
}

int
sevstep_uspt_is_event_done(uint64_t id)
{
	bool done;

	read_lock(&event_lock);
	done = last_acked_eventid >= id;
	read_unlock(&event_lock);

	return done;
}

int
sevstep_uspt_handle_poll_event(struct cpc_track_event __user *event)
{
	int err;

	read_lock(&event_lock);
	if (!have_event) {
		read_unlock(&event_lock);
		return -EAGAIN;
	}
	read_unlock(&event_lock);

	write_lock(&event_lock);
	if (have_event) {
		err = copy_to_user(event, &sent_event,
			sizeof(struct cpc_track_event));
		have_event = false;
	} else {
		err = -EAGAIN;
	}
	write_unlock(&event_lock);

	return err;
}

int
sevstep_uspt_handle_ack_event_ioctl(uint64_t eventid)
{
	int err;

	write_lock(&event_lock);
	if (eventid == last_sent_eventid) {
		err = 0;
		last_acked_eventid = last_sent_eventid;
	} else {
		err = 1;
		pr_warn("Sevstep: ack'd event does not match sent: %llu %llu\n",
			last_sent_eventid, eventid);
	}
	write_unlock(&event_lock);

	return err;
}

