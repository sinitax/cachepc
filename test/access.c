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

	fd = open("/dev/kvm", O_RDONLY);
	if (fd < 0) err(1, "open");

	for (i = 0; i < 100; i++) {
		arg = 48; /* target set */
		ret = ioctl(fd, KVM_CPC_TEST_ACCESS, &arg);
		if (ret == -1) err(1, "ioctl TEST_ACCESS");
		if (arg != 1) errx(1, "access result (%i) != 1", arg);
	}

	close(fd);
}
