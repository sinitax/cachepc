#include "test/util.h"
#include "cachepc/uapi.h"

#include <sys/ioctl.h>
#include <fcntl.h>
#include <assert.h>
#include <unistd.h>
#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int
main(int argc, const char **argv)
{
	uint8_t counts[L1_SETS];
	uint32_t arg, set;
	int fd, ret;

	fd = open("/dev/kvm", O_RDONLY);
	if (fd < 0) err(1, "open");

	set = 48;
	if (argc > 1) set = atoi(argv[1]);
	if (set >= L1_SETS) errx(1, "set out-of-bounds");

	ret = ioctl(fd, KVM_CPC_RESET, &arg);
	if (ret == -1) err(1, "KVM_CPC_RESET");

	arg = set;
	ret = ioctl(fd, KVM_CPC_TEST_EVICTION, &arg);
	if (ret == -1) err(1, "KVM_CPC_TEST_EVICTION");

	ret = ioctl(fd, KVM_CPC_READ_COUNTS, counts);
	if (ret == -1) err(1, "KVM_CPC_READ_COUNTS");

	print_counts(counts);
	printf("\n");
	print_counts_raw(counts);

	close(fd);

	ret = ioctl(fd, KVM_CPC_DEINIT, &arg);
	if (ret == -1) err(1, "KVM_CPC_DEINIT");

	return arg;
}
