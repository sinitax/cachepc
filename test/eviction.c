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
	uint32_t set;
	int i, fd, ret;

	fd = open("/dev/kvm", O_RDONLY);
	if (fd < 0) err(1, "open");

	set = 48;
	if (argc > 1) set = atoi(argv[1]);
	if (set >= L1_SETS)
		errx(1, "set out-of-bounds");

	ret = ioctl(fd, KVM_CPC_TEST_EVICTION, &set);
	if (ret == -1) err(1, "ioctl KVM_CPC_TEST_EVICTION");

	ret = ioctl(fd, KVM_CPC_READ_COUNTS, counts);
	if (ret == -1) err(1, "ioctl KVM_CPC_READ_COUNTS");

	for (i = 0; i < 64; i++) {
		if (i % 16 == 0 && i)
			printf("\n");
		if (counts[i] > 0)
			printf("\x1b[91m");
		printf("%2i ", i);
		if (counts[i] > 0)
			printf("\x1b[0m");
	}
	printf("\n");

	close(fd);
}
