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

static int child;
static struct cpc_event event;

uint64_t
monitor(struct kvm *kvm, bool baseline)
{
	uint8_t counts[L1_SETS];
	int ret;

	ret = ioctl(kvm_dev, KVM_CPC_POLL_EVENT, &event);
	if (ret && errno == EAGAIN) return 0;
	if (ret) err(1, "KVM_CPC_POLL_EVENT");

	if (event.type != CPC_EVENT_TRACK_STEP)
		errx(1, "unexpected event type %i", event.type);

	ret = ioctl(kvm_dev, KVM_CPC_READ_COUNTS, counts);
	if (ret) err(1, "KVM_CPC_READ_COUNTS");

	printf("Event: rip:%08llx cnt:%llu inst:%08llx data:%08llx ret:%llu misses:%u\n",
		vm_get_rip(), event.step.fault_count,
		event.step.fault_gfns[0], event.step.fault_gfns[1],
		event.step.retinst, event.step.misses);
	print_counts(counts);
	printf("\n");
	print_counts_raw(counts);
	printf("\n");

	ret = ioctl(kvm_dev, KVM_CPC_ACK_EVENT, &event.id);
	if (ret) err(1, "KVM_CPC_ACK_EVENT");

	return 1;
}

void
deinit(void)
{
	ioctl(kvm_dev, KVM_CPC_DEINIT);

	kill(child, SIGKILL);

	kvm_setup_deinit();
}

int
main(int argc, const char **argv)
{
	struct ipc *ipc;
	struct guest guest;
	struct kvm kvm;
	uint8_t baseline[L1_SETS];
	struct cpc_track_cfg cfg;
	uint64_t eventcnt;
	uint32_t arg;
	bool with_data;
	int ret;

	setvbuf(stdout, NULL, _IONBF, 0);

	with_data = true;
	if (argc > 1 && !strcmp(argv[1], "--exec-only")) {
		with_data = false;
		argc--;
		argv++;
	}

	parse_vmtype(argc, argv);

	kvm_setup_init();

	ipc = ipc_alloc();

	child = fork();
	if (child < 0) err(1, "fork");

	if (child == 0) {
		pin_process(0, TARGET_CORE, true);

		guest_init(&guest, "test/kvm-step_guest");
		vm_init(&kvm, &guest);
		guest_deinit(&guest);

		/* reset kernel module state */
		ret = ioctl(kvm_dev, KVM_CPC_RESET, NULL);
		if (ret < 0) err(1, "KVM_CPC_RESET");

		ipc_signal_parent(ipc);
		ipc_wait_parent(ipc);

		printf("VM start\n");

		do {
			ret = ioctl(kvm.vcpufd, KVM_RUN, NULL);
			if (ret < 0) err(1, "KVM_RUN");
		} while (kvm.run->exit_reason == KVM_EXIT_HLT);

		printf("VM exit\n");

		vm_deinit(&kvm);

		ipc_free(ipc);
		kvm_setup_deinit();
	} else {
		pin_process(0, SECONDARY_CORE, true);

		atexit(deinit);

		ipc_wait_child(ipc);

		printf("Monitor start\n");

		memset(&cfg, 0, sizeof(cfg));
		cfg.mode = CPC_TRACK_STEPS;
		cfg.steps.with_data = with_data;
		ret = ioctl(kvm_dev, KVM_CPC_TRACK_MODE, &cfg);
		if (ret) err(1, "KVM_CPC_TRACK_MODE");

		arg = true;
		ret = ioctl(kvm_dev, KVM_CPC_CALC_BASELINE, &arg);
		if (ret) err(1, "KVM_CPC_CALC_BASELINE");

		ipc_signal_child(ipc);

		/* run vm while baseline is calculated */
		eventcnt = 0;
		while (eventcnt < 50) {
			eventcnt += monitor(&kvm, true);
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

		ret = ioctl(kvm_dev, KVM_CPC_READ_BASELINE, baseline);
		if (ret) err(1, "KVM_CPC_READ_BASELINE");

		printf("\nBaseline:\n");
		print_counts(baseline);
		printf("\n");
		print_counts_raw(baseline);
		printf("\n\n");

		arg = true;
		ret = ioctl(kvm_dev, KVM_CPC_APPLY_BASELINE, &arg);
		if (ret) err(1, "KMV_CPC_APPLY_BASELINE");

		ret = ioctl(kvm_dev, KVM_CPC_ACK_EVENT, &event.id);
		if (ret) err(1, "KVM_CPC_ACK_EVENT");

		eventcnt = 0;
		while (eventcnt < 57) {
			eventcnt += monitor(&kvm, false);
		}

		printf("Monitor exit\n");

		ipc_free(ipc);
	}
}

