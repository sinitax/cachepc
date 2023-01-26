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

void
monitor(void)
{
	struct cpc_event event;
	int ret;

	ret = ioctl(kvm_dev, KVM_CPC_POLL_EVENT, &event);
	if (ret && errno == EAGAIN) return;
	if (ret) err(1, "KVM_CPC_POLL_EVENT");

	if (event.type != CPC_EVENT_TRACK_PAGE)
		errx(1, "unexpected event type %i", event.type);

	printf("Event: rip:%016llx prev:%08llx next:%08llx ret:%llu\n",
		vm_get_rip(), event.page.inst_gfn_prev,
		event.page.inst_gfn, event.page.retinst);
	printf("\n");

	ret = ioctl(kvm_dev, KVM_CPC_ACK_EVENT, &event.id);
	if (ret) err(1, "KVM_CPC_ACK_EVENT");
}

int
main(int argc, const char **argv)
{
	uint32_t arg;
	int ret;

	setvbuf(stdout, NULL, _IONBF, 0);

	kvm_setup_init();

	pin_process(0, SECONDARY_CORE, true);

	ret = ioctl(kvm_dev, KVM_CPC_RESET);
	if (ret) err(1, "KVM_CPC_RESET");

	arg = CPC_TRACK_PAGES_RESOLVE;
	ret = ioctl(kvm_dev, KVM_CPC_TRACK_MODE, &arg);
	if (ret) err(1, "KVM_CPC_TRACK_MODE");

	while (1) monitor();

	kvm_setup_deinit();
}

