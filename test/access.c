#include "cachepc/uapi.h"

#include <sys/ioctl.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <err.h>
#include <fcntl.h>
#include <unistd.h>

int
main(int argc, const char **argv)
{
	uint32_t arg;
	int fd, ret;
	size_t i;

	fd = open("/proc/cachepc", O_RDONLY);
	if (fd < 0) err(1, "open");

	for (i = 0; i < 50; i++) {
		arg = 48; /* target set */
		ret = ioctl(fd, CACHEPC_IOCTL_TEST_ACCESS, &arg);
		if (ret == -1) err(1, "ioctl fail");
		printf("%i\n", arg);
	}
	
	close(fd);
}
