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

#define TARGET_CORE 2
#define SECONDARY_CORE 3

static struct cpc_event event;

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
		if (event.guest.type == CPC_GUEST_STOP_TRACK)
			return 2;
		break;
	case CPC_EVENT_TRACK_STEP:
		ret = ioctl(kvm_dev, KVM_CPC_READ_COUNTS, counts);
		if (ret) err(1, "KVM_CPC_READ_COUNTS");

		printf("Event: rip:%016llx cnt:%llu "
			"inst:%08llu data:%08llx ret:%llu\n",
			vm_get_rip(), event.step.fault_count,
			event.step.fault_gfns[0], event.step.fault_gfns[1],
			event.step.retinst);
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
reset(int sig)
{
	int ret;

	ret = ioctl(kvm_dev, KVM_CPC_RESET);
	if (ret) err(1, "KVM_CPC_RESET");
}

int
main(int argc, const char **argv)
{
	uint8_t baseline[L1_SETS];
	uint32_t eventcnt;
	uint32_t arg;
	pid_t qemu;
	int ret;

	qemu = pgrep("qemu-system-x86_64");
	if (!qemu) errx(1, "pgrep failed");

	pin_process(0, SECONDARY_CORE, true);

	setvbuf(stdout, NULL, _IONBF, 0);

	kvm_setup_init();

	ret = ioctl(kvm_dev, KVM_CPC_RESET);
	if (ret) err(1, "KVM_CPC_RESET");

	arg = true;
	ret = ioctl(kvm_dev, KVM_CPC_CALC_BASELINE, &arg);
	if (ret) err(1, "KVM_CPC_CALC_BASELINE");

	arg = CPC_TRACK_STEPS;
	ret = ioctl(kvm_dev, KVM_CPC_TRACK_MODE, &arg);
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

	arg = CPC_TRACK_STEPS_SIGNALLED;
	ret = ioctl(kvm_dev, KVM_CPC_TRACK_MODE, &arg);
	if (ret) err(1, "KVM_CPC_RESET");

	ret = ioctl(kvm_dev, KVM_CPC_ACK_EVENT, &event.id);
	if (ret) err(1, "KVM_CPC_ACK_EVENT");

	signal(SIGINT, reset);

	while (monitor(false) != 2);

	ret = ioctl(kvm_dev, KVM_CPC_RESET);
	if (ret) err(1, "KVM_CPC_RESET");

	kvm_setup_deinit();
}

