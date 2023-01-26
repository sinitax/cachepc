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

static int child;

uint64_t
monitor(struct kvm *kvm, bool baseline)
{
	struct cpc_event event;
	int ret;

	/* Get page fault info */
	ret = ioctl(kvm_dev, KVM_CPC_POLL_EVENT, &event);
	if (ret && errno == EAGAIN) return 0;
	if (ret) err(1, "KVM_CPC_POLL_EVENT");

	if (event.type != CPC_EVENT_TRACK_PAGE)
		errx(1, "unexpected event type %i", event.type);

	printf("Event: rip:%08llx prev:%llu next:%llu ret:%llu\n",
		vm_get_rip(), event.page.inst_gfn_prev,
		event.page.inst_gfn, event.page.retinst);
	printf("\n");

	ret = ioctl(kvm_dev, KVM_CPC_ACK_EVENT, &event.id);
	if (ret) err(1, "KVM_CPC_ACK_EVENT");

	return 1;
}

void
kill_child(void)
{
	kill(child, SIGKILL);
}

int
main(int argc, const char **argv)
{
	struct ipc *ipc;
	struct guest guest;
	struct kvm kvm;
	uint64_t eventcnt;
	uint32_t arg;
	int ret;

	vmtype = "kvm";
	if (argc > 1) vmtype = argv[1];
	if (strcmp(vmtype, "kvm") && strcmp(vmtype, "sev")
			&& strcmp(vmtype, "sev-es")
			&& strcmp(vmtype, "sev-snp"))
		errx(1, "invalid vm mode: %s", vmtype);

	setvbuf(stdout, NULL, _IONBF, 0);

	kvm_setup_init();

	ipc = ipc_alloc();

	child = fork();
	if (child < 0) err(1, "fork");

	if (child == 0) {
		pin_process(0, TARGET_CORE, true);

		guest_init(&guest, "test/kvm-pagestep_guest");
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

			if (kvm.run->exit_reason == KVM_EXIT_HLT)
				printf("VM halt\n");
		} while (kvm.run->exit_reason == KVM_EXIT_HLT);

		printf("VM exit\n");

		vm_deinit(&kvm);
	} else {
		pin_process(0, SECONDARY_CORE, true);

		atexit(kill_child);

		ipc_wait_child(ipc);

		printf("Monitor start\n");

		arg = CPC_TRACK_PAGES;
		ret = ioctl(kvm_dev, KVM_CPC_TRACK_MODE, &arg);
		if (ret) err(1, "KVM_CPC_TRACK_MODE");

		ipc_signal_child(ipc);

		eventcnt = 0;
		while (eventcnt < 50) {
			eventcnt += monitor(&kvm, true);
		}

		printf("Monitor exit\n");
	}

	ipc_free(ipc);

	kvm_setup_deinit();
}

