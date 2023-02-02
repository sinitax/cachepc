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

struct cpc_event *batch_buffer;

void
report(struct cpc_event *event)
{
	if (event->type == CPC_EVENT_TRACK_PAGE) {
		printf("Page event: rip:%016llx prev:%08llx next:%08llx ret:%llu\n",
			vm_get_rip(), event->page.inst_gfn_prev,
			event->page.inst_gfn, event->page.retinst);
	} else if (event->type == CPC_EVENT_GUEST) {
		printf("Guest event: type:%u arg:%u\n",
			event->guest.type, event->guest.val);
	} else {
		printf("Unexpected event type %i\n", event->type);
	}
	printf("\n");
}

void
monitor(void)
{
	struct cpc_event event;
	struct cpc_event_batch batch;
	size_t i;
	int ret;

	ret = ioctl(kvm_dev, KVM_CPC_POLL_EVENT, &event);
	if (ret && errno == EAGAIN) return;
	if (ret) err(1, "KVM_CPC_POLL_EVENT");

	if (event.type == CPC_EVENT_BATCH) {
		batch.cnt = 0;
		batch.maxcnt = CPC_EVENT_BATCH_MAX;
		batch.buf = batch_buffer;

		ret = ioctl(kvm_dev, KVM_CPC_READ_BATCH, &batch);
		if (ret) err(1, "KVM_CPC_READ_BATCH");

		for (i = 0; i < batch.cnt; i++)
			report(&batch.buf[i]);
	} else {
		report(&event);
	}

	ret = ioctl(kvm_dev, KVM_CPC_ACK_EVENT, &event.id);
	if (ret) err(1, "KVM_CPC_ACK_EVENT");
}

int
main(int argc, const char **argv)
{
	struct cpc_track_cfg cfg;
	uint32_t arg;
	int ret;

	batch_buffer = malloc(sizeof(struct cpc_event) * CPC_EVENT_BATCH_MAX);
	if (!batch_buffer) err(1, "malloc");

	setvbuf(stdout, NULL, _IONBF, 0);

	kvm_setup_init();

	pin_process(0, SECONDARY_CORE, true);

	ret = ioctl(kvm_dev, KVM_CPC_RESET);
	if (ret) err(1, "KVM_CPC_RESET");

	arg = true;
	ret = ioctl(kvm_dev, KVM_CPC_BATCH_EVENTS, &arg);
	if (ret) err(1, "KVM_CPC_BATCH_EVENTS");

	memset(&cfg, 0, sizeof(cfg));
	cfg.mode = CPC_TRACK_PAGES;
	ret = ioctl(kvm_dev, KVM_CPC_TRACK_MODE, &cfg);
	if (ret) err(1, "KVM_CPC_TRACK_MODE");

	while (1) monitor();

	kvm_setup_deinit();
}

