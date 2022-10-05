#include "uspt.h"
#include "sevstep.h"

#include "svm/cachepc/cachepc.h"

#include <linux/kvm.h>
#include <linux/timekeeping.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/vmalloc.h>
#include <linux/printk.h>
#include <linux/ratelimit.h>

#define ARRLEN(x) (sizeof(x)/sizeof((x)[0]))

typedef struct {
	bool is_active;
	int tracking_type;
	bool retrack;

	int perf_cpu;

	uint64_t gfn_retrack_backlog[10];
	int gfn_retrack_backlog_next_idx;

	page_fault_event_t * events;
	uint64_t event_next_idx;
	uint64_t events_size;

	bool error_occured;
} batch_track_state_t;

// crude sync mechanism. don't know a good way to act on errors yet.
uint64_t last_sent_event_id = 1;
uint64_t last_acked_event_id = 1;
DEFINE_RWLOCK(event_lock);

page_fault_event_t sent_event;
static int have_event = 0;

static bool get_rip = true;

static int inited = 0;

DEFINE_SPINLOCK(batch_track_state_lock);
static batch_track_state_t batch_track_state;

typedef struct {
	uint64_t idx_for_last_perf_reading;
	uint64_t last_perf_reading;
	uint64_t delta_valid_idx;
	uint64_t delta;
} perf_state_t;

perf_state_t perf_state;

static uint64_t perf_state_update_and_get_delta(uint64_t current_event_idx);

void
sevstep_uspt_clear(void)
{
	write_lock(&event_lock);
	inited = 0;
	last_sent_event_id = 1;
	last_acked_event_id = 1;
	have_event = 0;
	get_rip = false;
	write_unlock(&event_lock);
}

int
sevstep_uspt_initialize(int pid,bool should_get_rip)
{
	write_lock(&event_lock);
	inited = 1;
	last_sent_event_id = 1;
	last_acked_event_id = 1;
	have_event = 0;
	get_rip = should_get_rip;
	write_unlock(&event_lock);

	return 0;
}

int
sevstep_uspt_is_initialiized()
{
	return inited;
}

bool
sevstep_uspt_should_get_rip()
{
	bool tmp;

	read_lock(&event_lock);
	tmp = get_rip;
	read_unlock(&event_lock);

	return tmp;
}

int
sevstep_uspt_send_and_block(uint64_t faulted_gpa, uint32_t error_code,
	bool have_rip, uint64_t rip)
{
	ktime_t abort_after;
	page_fault_event_t message_for_user;

	read_lock(&event_lock);
	if (!sevstep_uspt_is_initialiized()) {
		printk("userspace_page_track_signals: "
			"sevstep_uspt_send_and_block : ctx not initialized!\n");
		read_unlock(&event_lock);
		return 1;
	}
	read_unlock(&event_lock);

	write_lock(&event_lock);
	 if (last_sent_event_id != last_acked_event_id) {
		printk("event id_s out of sync, aborting. Fix this later\n");
		write_unlock(&event_lock);
		return 1;
	} else {
		// TODO: handle overflow
		last_sent_event_id++;
	}
	message_for_user.id = last_sent_event_id;
	message_for_user.faulted_gpa = faulted_gpa;
	message_for_user.error_code = error_code;
	message_for_user.have_rip_info = have_rip;
	message_for_user.rip = rip;
	message_for_user.ns_timestamp = ktime_get_real_ns();
	message_for_user.have_retired_instructions = false;

	// for poll based system;
	have_event = 1;
	sent_event = message_for_user;
	// printk("sevstep_uspt_send_and_block sending event %llu\n",sent_event.id);

	write_unlock(&event_lock);

	// wait for ack, but with timeout. Otherwise small bugs in userland
	// easily lead to a kernel hang
	abort_after = ktime_get() + 1000000000ULL; // 1 sec in nanosecond
	while (!sevstep_uspt_is_event_done(sent_event.id)) {
		if (ktime_get() > abort_after) {
			printk("Waiting for ack of event %llu timed out, continuing\n",sent_event.id);
			return 3;
		}
	}

	return 0;
}

int
sevstep_uspt_is_event_done(uint64_t id)
{
	int res;

	read_lock(&event_lock);
	res = last_acked_event_id >= id;
	read_unlock(&event_lock);

	return res;
}

int
sevstep_uspt_handle_poll_event(page_fault_event_t* userpace_mem)
{
	int err;

	// most of the time we won't have an event
	read_lock(&event_lock);
	if (!have_event) {
		read_unlock(&event_lock);
		return KVM_USPT_POLL_EVENT_NO_EVENT;
	}
	read_unlock(&event_lock);

	write_lock(&event_lock);
	if (have_event) {
		err = copy_to_user(userpace_mem,
			&sent_event, sizeof(page_fault_event_t));
		have_event = 0;
	} else {
		err = KVM_USPT_POLL_EVENT_NO_EVENT;
	}
	write_unlock(&event_lock);

	return err;
}

int
sevstep_uspt_handle_ack_event_ioctl(ack_event_t event)
{
	int err = 0;

	write_lock(&event_lock);
	if (event.id == last_sent_event_id) {
		last_acked_event_id = last_sent_event_id;
	} else {
		err = 1;
		printk("last sent event id is %llu but received ack for %llu\n",
			last_sent_event_id, event.id);
	}
	write_unlock(&event_lock);

	return err;
}

// get retired instructions between current_event_idx-1 and current_event_idx
// value is cached for multiple calls to the same current_event_idx
uint64_t
perf_state_update_and_get_delta(uint64_t current_event_idx)
{
	uint64_t current_value;

	/* check if value is "cached" */
	if (perf_state.delta_valid_idx == current_event_idx) {
		if (current_event_idx == 0) {
			perf_state.idx_for_last_perf_reading = current_event_idx;
			perf_state.last_perf_reading = cachepc_read_pmc(0);
		}
		return perf_state.delta;
	}

	/* otherwise update, but logic is only valid for two consecutive events */
	if (current_event_idx != perf_state.idx_for_last_perf_reading+1) {
		printk_ratelimited(KERN_CRIT "perf_state_update_and_get_delta: "
			"last reading was for idx %llu but was queried for %llu\n",
			perf_state.idx_for_last_perf_reading, current_event_idx);
	}

	current_value = cachepc_read_pmc(0);
	perf_state.delta = (current_value - perf_state.last_perf_reading);
	perf_state.delta_valid_idx = current_event_idx;

	perf_state.idx_for_last_perf_reading = current_event_idx;
	perf_state.last_perf_reading = current_value;

	return perf_state.delta;
}

void
sevstep_uspt_batch_tracking_inc_event_idx(void)
{
	spin_lock(&batch_track_state_lock);
	batch_track_state.event_next_idx++;
	spin_unlock(&batch_track_state_lock);
}

int
sevstep_uspt_batch_tracking_start(int tracking_type,uint64_t expected_events,
	int perf_cpu, bool retrack)
{
	page_fault_event_t* events;
	uint64_t buffer_size, i;

	spin_lock(&batch_track_state_lock);
	if (batch_track_state.is_active) {
		printk("userspace_page_track_signals: overwriting "
			"active batch track config!\n");
		if (batch_track_state.events != NULL ) {
			vfree(batch_track_state.events);
		}
	}
	batch_track_state.is_active = false;
	spin_unlock(&batch_track_state_lock);

	buffer_size = expected_events * sizeof(page_fault_event_t);
	printk("sevstep_uspt_batch_tracking_start trying to alloc %llu "
		"bytes buffer for events\n", buffer_size);
	events = vmalloc(buffer_size);
	if (events  == NULL) {
		printk("userspace_page_track_signals: "
			"faperf_cpuiled to alloc %llu bytes for event buffer\n",
			buffer_size);
		return 1; // note: lock not held here
	}

	// access each element once to force them into memory, improving performance
	// during tracking
	for (i = 0; i < expected_events * sizeof(page_fault_event_t); i++) {
		((volatile uint8_t*)events)[i] = 0;
	}

	perf_state.idx_for_last_perf_reading = 0;
	perf_state.last_perf_reading = 0;
	perf_state.delta_valid_idx = 0;
	perf_state.delta = 0;
	cachepc_init_pmc(0, 0xc0, 0x00, PMC_GUEST, PMC_KERNEL | PMC_USER);

	spin_lock(&batch_track_state_lock);

	batch_track_state.perf_cpu = perf_cpu;
	batch_track_state.retrack = retrack;

	batch_track_state.events = events;
	batch_track_state.event_next_idx = 0;
	batch_track_state.events_size = expected_events;

	batch_track_state.gfn_retrack_backlog_next_idx = 0;
	batch_track_state.tracking_type = tracking_type;
	batch_track_state.error_occured = false;

	batch_track_state.is_active = true;

	spin_unlock(&batch_track_state_lock);

	return 0;
}

void
sevstep_uspt_batch_tracking_handle_retrack(struct kvm_vcpu* vcpu,
	uint64_t current_fault_gfn)
{
	uint64_t ret_instr_delta;
	int i, next_idx;

	spin_lock(&batch_track_state_lock);

	if (!batch_track_state.retrack) {
		spin_unlock(&batch_track_state_lock);
		return;
	}

	if (smp_processor_id() != batch_track_state.perf_cpu) {
		printk("sevstep_uspt_batch_tracking_handle_retrack: perf was "
			"programmed on logical cpu %d but handler was called "
			"on %d. Did you forget to pin the vcpu thread?\n",
			batch_track_state.perf_cpu, smp_processor_id());
	}
	ret_instr_delta = perf_state_update_and_get_delta(batch_track_state.event_next_idx);


	// faulting instructions is probably the same as on last fault
	// try to add current fault to retrack log and return
	// for first event idx we do not have a valid ret_instr_delta.
	// Retracking for the frist time is fine, if we loop, we end up here
	// again but with a valid delta on one of the next event
	if( (ret_instr_delta < 2) && ( batch_track_state.event_next_idx != 0) ) {
		next_idx = batch_track_state.gfn_retrack_backlog_next_idx;
		if (next_idx >= ARRLEN(batch_track_state.gfn_retrack_backlog)) {
			printk("sevstep_uspt_batch_tracking_handle_retrack: retrack "
				"backlog full, dropping retrack for fault "
				"at 0x%llx\n", current_fault_gfn);
		} else {
			batch_track_state.gfn_retrack_backlog[next_idx] = current_fault_gfn;
			batch_track_state.gfn_retrack_backlog_next_idx++;
		}

		spin_unlock(&batch_track_state_lock);
		return;
	}

	/* made progress, retrack everything in backlog and reset idx */
	for (i = 0; i < batch_track_state.gfn_retrack_backlog_next_idx; i++) {
		sevstep_track_single_page(vcpu,
			batch_track_state.gfn_retrack_backlog[i],
			batch_track_state.tracking_type);
	}

	/* add current fault to list */
	batch_track_state.gfn_retrack_backlog[0] = current_fault_gfn;
	batch_track_state.gfn_retrack_backlog_next_idx = 1;

	spin_unlock(&batch_track_state_lock);

}

int
sevstep_uspt_batch_tracking_save(uint64_t faulted_gpa, uint32_t error_code,
	bool have_rip, uint64_t rip)
{
	uint64_t ret_instr_delta;
	page_fault_event_t* event;

	spin_lock(&batch_track_state_lock);

	if (!batch_track_state.is_active) {
		printk_ratelimited("userspace_page_track_signals: got save but batch tracking is not active!\n");
		batch_track_state.error_occured = true;
		spin_unlock(&batch_track_state_lock);
		return 1;
	}


	if (batch_track_state.event_next_idx >= batch_track_state.events_size) {
		printk_ratelimited("userspace_page_track_signals: events buffer is full!\n");
		batch_track_state.error_occured = true;
		spin_unlock(&batch_track_state_lock);
		return 1;
	}

	if (smp_processor_id() != batch_track_state.perf_cpu) {
		printk("sevstep_uspt_batch_tracking_handle_retrack: perf was "
			"programmed on logical cpu %d but handler was called "
			"on %d. Did you forget to pin the vcpu thread?\n",
			batch_track_state.perf_cpu, smp_processor_id());
	}
	ret_instr_delta = perf_state_update_and_get_delta(batch_track_state.event_next_idx);


	if (batch_track_state.events == NULL) {
		printk(KERN_CRIT "userspace_page_track_signals: events buf was "
			"NULL but \"is_active\" was set! This should never happen!!!\n");
		spin_unlock(&batch_track_state_lock);
		return 1;
	}

	event = &batch_track_state.events[batch_track_state.event_next_idx];
	event->id = batch_track_state.event_next_idx;
	event->faulted_gpa = faulted_gpa;
	event->error_code = error_code;
	event->have_rip_info = have_rip;
	event->rip = rip;
	event->ns_timestamp = ktime_get_real_ns();
	event->have_retired_instructions = true;
	event->retired_instructions = ret_instr_delta;

	// old inc was here

	if (batch_track_state.gfn_retrack_backlog_next_idx
			> ARRLEN(batch_track_state.gfn_retrack_backlog)) {
		printk_ratelimited("userspace_page_track_signals: "
			"gfn retrack backlog overflow!\n");
		batch_track_state.error_occured = true;
		spin_unlock(&batch_track_state_lock);
		return 1;
	}

	spin_unlock(&batch_track_state_lock);
	return 0;
}

int
sevstep_uspt_batch_tracking_stop(page_fault_event_t* results, uint64_t len, bool* error_occured)
{
	spin_lock(&batch_track_state_lock);
	if (!batch_track_state.is_active) {
		printk("userspace_page_track_signals: batch tracking not active\n");
		spin_unlock(&batch_track_state_lock);
		return 1;

	}
	batch_track_state.is_active = false;

	if (len > batch_track_state.event_next_idx) {
		printk("userspace_page_track_signals: requested %llu "
			"events but got only %llu\n",
			len, batch_track_state.event_next_idx);
		spin_unlock(&batch_track_state_lock);
		return 1;
	}

	memcpy(results,batch_track_state.events, len*sizeof(page_fault_event_t));
	vfree(batch_track_state.events);

	*error_occured = batch_track_state.error_occured;

	spin_unlock(&batch_track_state_lock);

	return 0;
}

uint64_t
sevstep_uspt_batch_tracking_get_events_count()
{
	uint64_t buf;

	spin_lock(&batch_track_state_lock);
	buf = batch_track_state.event_next_idx;
	spin_unlock(&batch_track_state_lock);

	return buf;
}

bool
sevstep_uspt_batch_tracking_in_progress()
{
	return batch_track_state.is_active;
}
