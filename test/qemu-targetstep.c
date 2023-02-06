#include "test/kvm-eviction.h"
#include "test/kvm.h"
#include "test/util.h"
#include "cachepc/uapi.h"

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <err.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

static struct cpc_event event;
static struct cpc_event_batch batch;
static uint64_t last_user_inst_gfn;

int
monitor(bool baseline)
{
	uint8_t counts[L1_SETS];
	int ret;

	ret = ioctl(kvm_dev, KVM_CPC_POLL_EVENT, &event);
	if (ret && errno == EAGAIN) return 0;
	if (ret) err(1, "KVM_CPC_POLL_EVENT");

	switch (event.type) {
	case CPC_EVENT_GUEST:
		printf("Guest %s\n", !event.guest.type ? "start" : "stop");
		if (event.guest.type == CPC_GUEST_STOP_TRACK)
			return 2;
		break;
	case CPC_EVENT_TRACK_STEP:
		ret = ioctl(kvm_dev, KVM_CPC_READ_COUNTS, counts);
		if (ret) err(1, "KVM_CPC_READ_COUNTS");

		printf("Event: rip:%016llx cnt:%llu "
			"inst:%08llx ret:%llu\n",
			vm_get_rip(), event.step.fault_count,
			event.step.inst_gfn, event.step.retinst);
		print_counts(counts);
		printf("\n");
		print_counts_raw(counts);
		printf("\n");
		break;
	default:
		errx(1, "unexpected event type %i", event.type);
	}

	ret = ioctl(kvm_dev, KVM_CPC_ACK_EVENT, &event.id);
	if (ret) err(1, "KVM_CPC_ACK_EVENT");

	return 1;
}

void
read_batch(void)
{
	uint32_t i;
	int ret;

	ret = ioctl(kvm_dev, KVM_CPC_READ_BATCH, &batch);
	if (ret && errno == EAGAIN) return;
	if (ret && errno != EAGAIN) err(1, "KVM_CPC_READ_BATCH");

	for (i = 0; i < batch.cnt; i++) {
		if (batch.buf[i].type != CPC_EVENT_TRACK_PAGE)
			continue;

		if (batch.buf[i].page.retinst_user > 0) {
			printf("GFN %08llx %04x %4llu %4llu\n",
				batch.buf[i].page.inst_gfn,
				batch.buf[i].page.fault_err,
				batch.buf[i].page.retinst,
				batch.buf[i].page.retinst_user);
			last_user_inst_gfn = batch.buf[i].page.inst_gfn;
		}
	}
}

void
reset(int sig)
{
	int ret;

	ret = ioctl(kvm_dev, KVM_CPC_RESET);
	if (ret) err(1, "KVM_CPC_RESET");

	exit(1);
}

int
main(int argc, const char **argv)
{
	uint8_t baseline[L1_SETS];
	struct cpc_track_cfg cfg;
	bool first_guest_event;
	uint32_t eventcnt;
	uint32_t arg;
	int ret;

	pin_process(0, SECONDARY_CORE, true);

	setvbuf(stdout, NULL, _IONBF, 0);

	kvm_setup_init();

	ret = ioctl(kvm_dev, KVM_CPC_RESET);
	if (ret) err(1, "KVM_CPC_RESET");

	signal(SIGINT, reset);

	arg = true;
	ret = ioctl(kvm_dev, KVM_CPC_CALC_BASELINE, &arg);
	if (ret) err(1, "KVM_CPC_CALC_BASELINE");

	memset(&cfg, 0, sizeof(cfg));
	cfg.mode = CPC_TRACK_STEPS;
	cfg.steps.with_data = true;
	cfg.steps.use_filter = true;
	ret = ioctl(kvm_dev, KVM_CPC_TRACK_MODE, &cfg);
	if (ret) err(1, "KVM_CPC_RESET");

	eventcnt = 0;
	while (eventcnt < 50) {
		eventcnt += monitor(true);
	}

	ret = ioctl(kvm_dev, KVM_CPC_VM_REQ_PAUSE);
	if (ret) err(1, "KVM_CPC_VM_REQ_PAUSE");

	while (1) {
		ret = ioctl(kvm_dev, KVM_CPC_POLL_EVENT, &event);
		if (ret && errno == EAGAIN) continue;
		if (ret) err(1, "KVM_CPC_POLL_EVENT");

		if (event.type == CPC_EVENT_PAUSE) break;

		ret = ioctl(kvm_dev, KVM_CPC_ACK_EVENT, &event.id);
		if (ret) err(1, "KVM_CPC_ACK_EVENT");
	}

	arg = false;
	ret = ioctl(kvm_dev, KVM_CPC_CALC_BASELINE, &arg);
	if (ret) err(1, "KVM_CPC_CALC_BASELINE");

	arg = true;
	ret = ioctl(kvm_dev, KVM_CPC_APPLY_BASELINE, &arg);
	if (ret) err(1, "KVM_CPC_APPLY_BASELINE");

	ret = ioctl(kvm_dev, KVM_CPC_READ_BASELINE, baseline);
	if (ret) err(1, "KVM_CPC_READ_BASELINE");

	printf("\nBaseline:\n");
	print_counts(baseline);
	printf("\n");
	print_counts_raw(baseline);
	printf("\n\n");

	memset(&cfg, 0, sizeof(&cfg));
	cfg.mode = CPC_TRACK_NONE;
	ret = ioctl(kvm_dev, KVM_CPC_TRACK_MODE, &cfg);
	if (ret) err(1, "KVM_CPC_TRACK_MODE");

	ret = ioctl(kvm_dev, KVM_CPC_ACK_EVENT, &event.id);
	if (ret) err(1, "KVM_CPC_ACK_EVENT");

	/* wait until guest program is run */
	printf("Press enter to continue..\n");
	getchar();

	arg = true;
	ret = ioctl(kvm_dev, KVM_CPC_BATCH_EVENTS, &arg);
	if (ret) err(1, "KVM_CPC_BATCH_EVENTS");

	memset(&cfg, 0, sizeof(cfg));
	cfg.mode = CPC_TRACK_PAGES;
	ret = ioctl(kvm_dev, KVM_CPC_TRACK_MODE, &cfg);
	if (ret) err(1, "KVM_CPC_TRACK_MODE");

	batch.cnt = 0;
	batch.maxcnt = CPC_EVENT_BATCH_MAX;
	batch.buf = malloc(sizeof(struct cpc_event) * batch.maxcnt);
	if (!batch.buf) err(1, "malloc");

	first_guest_event = true;
	while (1) {
		ret = ioctl(kvm_dev, KVM_CPC_POLL_EVENT, &event);
		if (ret && errno == EAGAIN) continue;
		if (ret) err(1, "KVM_CPC_POLL_EVENT");

		if (event.type == CPC_EVENT_GUEST) {
			read_batch();
			printf("Guest %s\n",
				!event.guest.type ? "start" : "stop");
		}

		if (event.type == CPC_EVENT_GUEST
				&& event.guest.type == CPC_GUEST_START_TRACK) {
			if (!first_guest_event)
				break;
			first_guest_event = false;
		}

		if (event.type == CPC_EVENT_BATCH)
			read_batch();

		ret = ioctl(kvm_dev, KVM_CPC_ACK_EVENT, &event.id);
		if (ret) err(1, "KVM_CPC_ACK_EVENT");
	}

	read_batch();

	if (!batch.cnt) errx(1, "empty batch buffer");
	memset(&cfg, 0, sizeof(cfg));
	cfg.mode = CPC_TRACK_STEPS;
	cfg.steps.target_gfn = last_user_inst_gfn;
	cfg.steps.target_user = true;
	cfg.steps.use_target = true;
	cfg.steps.use_filter = true;
	//cfg.steps.with_data = true;
	ret = ioctl(kvm_dev, KVM_CPC_TRACK_MODE, &cfg);
	if (ret) err(1, "KVM_CPC_TRACK_MODE");

	ret = ioctl(kvm_dev, KVM_CPC_ACK_EVENT, &event.id);
	if (ret) err(1, "KVM_CPC_ACK_EVENT");

	printf("Target GFN: %08llx\n", cfg.steps.target_gfn);

	while (monitor(false) != 2);
	read_batch();

	signal(SIGINT, NULL);

	ret = ioctl(kvm_dev, KVM_CPC_RESET);
	if (ret) err(1, "KVM_CPC_RESET");

	free(batch.buf);

	kvm_setup_deinit();
}

