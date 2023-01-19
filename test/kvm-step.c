#define _GNU_SOURCE

#include "test/kvm.h"
#include "test/util.h"
#include "cachepc/uapi.h"

#include <linux/psp-sev.h>
#include <linux/kvm.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>
#include <assert.h>
#include <errno.h>
#include <err.h>
#include <fcntl.h>
#include <sched.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>

#define TARGET_CORE 2
#define SECONDARY_CORE 3

extern uint8_t guest_start[];
extern uint8_t guest_stop[];

uint8_t *
read_counts()
{
	uint8_t *counts;
	int ret;

	counts = malloc(L1_SETS * sizeof(uint8_t));
	if (!counts) err(1, "malloc");

	ret = ioctl(kvm_dev, KVM_CPC_READ_COUNTS, counts);
	if (ret) err(1, "ioctl KVM_CPC_READ_COUNTS");

	return counts;
}

uint64_t
monitor(struct kvm *kvm, bool baseline)
{
	struct cpc_event event;
	uint8_t counts[64];
	int ret;

	/* Get page fault info */
	ret = ioctl(kvm_dev, KVM_CPC_POLL_EVENT, &event);
	if (ret && errno == EAGAIN) return 0;
	if (ret) err(1, "ioctl KVM_CPC_POLL_EVENT");

	if (event.type != CPC_EVENT_TRACK_STEP)
		errx(1, "unexpected event type %i", event.type);

	ret = ioctl(kvm_dev, KVM_CPC_READ_COUNTS, counts);
	if (ret) err(1, "ioctl KVM_CPC_READ_COUNTS");

	printf("Event: cnt:%llu rip:%lu inst:%llu data:%llu retired:%llu\n",
		event.step.fault_count, snp_dbg_decrypt_rip(kvm->vmfd),
		event.step.fault_gfns[0], event.step.fault_gfns[1],
		event.step.retinst);
	print_counts(counts);
	printf("\n");

	ret = ioctl(kvm_dev, KVM_CPC_ACK_EVENT, &event.id);
	if (ret) err(1, "ioctl KVM_CPC_ACK_EVENT");

	return 1;
}

int
main(int argc, const char **argv)
{
	struct kvm kvm;
	uint8_t baseline[L1_SETS];
	struct cpc_event event;
	uint64_t eventcnt;
	pid_t ppid, pid;
	uint32_t arg;
	int ret;

	setvbuf(stdout, NULL, _IONBF, 0);

	pin_process(0, TARGET_CORE, true);

	kvm_setup_init();

	sev_snp_kvm_init(&kvm, L1_SIZE * 2, guest_start, guest_stop);

	/* reset kernel module state */
	ret = ioctl(kvm_dev, KVM_CPC_RESET, NULL);
	if (ret < 0) err(1, "ioctl KVM_CPC_RESET");

	ppid = getpid();
	if ((pid = fork())) {
		if (pid < 0) err(1, "fork");

		sleep(1); /* give time for child to pin other core */

		printf("VM start\n");

		do {
			ret = ioctl(kvm.vcpufd, KVM_RUN, NULL);
			if (ret < 0) err(1, "KVM_RUN");

			if (kvm.run->exit_reason == KVM_EXIT_HLT)
				printf("VM halt\n");
		} while (kvm.run->exit_reason == KVM_EXIT_HLT);

		printf("VM exit\n");
	} else {
		pin_process(0, SECONDARY_CORE, true);

		/* capture baseline by just letting it fault over and over */
		arg = CPC_TRACK_FAULT_NO_RUN;
		ret = ioctl(kvm_dev, KVM_CPC_TRACK_MODE, &arg);
		if (ret) err(1, "ioctl KVM_CPC_TRACK_MODE");

		/* calculate baseline while running vm */
		arg = true;
		ret = ioctl(kvm_dev, KVM_CPC_CALC_BASELINE, &arg);
		if (ret) err(1, "ioctl KVM_CPC_CALC_BASELINE");

		printf("Monitor ready\n");

		/* run vm while baseline is calculated */
		eventcnt = 0;
		while (eventcnt < 50) {
			eventcnt += monitor(&kvm, true);
		}

		ret = ioctl(kvm_dev, KVM_CPC_VM_REQ_PAUSE);
		if (ret) err(1, "ioctl KVM_CPC_VM_REQ_PAUSE");

		while (1) {
			ret = ioctl(kvm_dev, KVM_CPC_POLL_EVENT, &event);
			if (ret && errno == EAGAIN) continue;
			if (ret) err(1, "ioctl KVM_CPC_POLL_EVENT");

			if (event.type == CPC_EVENT_PAUSE) break;

			printf("Skipping non-pause event..\n");
			ret = ioctl(kvm_dev, KVM_CPC_ACK_EVENT, &event.id);
			if (ret) err(1, "ioctl KVM_CPC_ACK_EVENT");
		}

		arg = false;
		ret = ioctl(kvm_dev, KVM_CPC_CALC_BASELINE, &arg);
		if (ret) err(1, "ioctl KVM_CPC_CALC_BASELINE");

		ret = ioctl(kvm_dev, KVM_CPC_READ_BASELINE, baseline);
		if (ret) err(1, "ioctl KVM_CPC_READ_BASELINE");

		printf("\nBaseline:\n");
		print_counts(baseline);
		printf("\n");
		print_counts_raw(baseline);
		printf("\n\n");

		arg = true;
		ret = ioctl(kvm_dev, KVM_CPC_APPLY_BASELINE, &arg);
		if (ret) err(1, "ioctl KMV_CPC_APPLY_BASELINE");

		/* single step and log all accessed pages */
		arg = CPC_TRACK_FULL;
		ret = ioctl(kvm_dev, KVM_CPC_TRACK_MODE, &arg);
		if (ret) err(1, "ioctl KVM_CPC_TRACK_MODE");

		ret = ioctl(kvm_dev, KVM_CPC_ACK_EVENT, &event.id);
		if (ret) err(1, "ioctl KVM_CPC_ACK_EVENT");

		eventcnt = 0;
		while (eventcnt < 50) {
			eventcnt += monitor(&kvm, false);
		}

		kill(ppid, SIGINT);
		exit(0);
	}

	kvm_deinit(&kvm);

	kvm_setup_deinit();
}

