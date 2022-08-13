#include "cachepc_user.h"

#include <stdlib.h>
#include <stdio.h>
#include <err.h>
#include <fcntl.h>
#include <stdint.h>
#include <assert.h>
#include <unistd.h>
#include <stropts.h>

int
main(int argc, const char **argv)
{
	uint16_t counts[64];
	uint32_t arg;
	size_t i, len;
	int fd, ret;

	fd = open("/proc/cachepc", O_RDONLY);

	arg = 48;
	if (argc == 2) arg = atoi(argv[1]);

	ret = ioctl(fd, CACHEPC_IOCTL_TEST_EVICTION, &arg);
	if (ret == -1) err(1, "ioctl fail");

	len = read(fd, counts, sizeof(counts));
	assert(len == sizeof(counts));

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
