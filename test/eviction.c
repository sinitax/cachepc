#include "cachepc/uapi.h"

#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdint.h>
#include <assert.h>
#include <unistd.h>
#include <err.h>
#include <stdlib.h>
#include <stdio.h>

int
main(int argc, const char **argv)
{
	uint16_t counts[64];
	uint32_t arg;
	int i, fd, ret;

	fd = open("/dev/kvm", O_RDONLY);
	if (fd < 0) err(1, "open");

	arg = 48;
	if (argc == 2) arg = atoi(argv[1]);

	ret = ioctl(fd, KVM_CPC_TEST_EVICTION, &arg);
	if (ret == -1) err(1, "ioctl TEST_EVICTION");

	ret = ioctl(fd, KVM_CPC_READ_COUNTS, counts);
	if (ret == -1) err(1, "ioctl READ_COUNTS");

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
