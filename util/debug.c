#include "cachepc/uapi.h"

#include <sys/ioctl.h>
#include <fcntl.h>
#include <err.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>

int
main(int argc, const char **argv)
{
	uint32_t arg;
	int fd, ret;

	fd = open("/dev/kvm", O_RDONLY);
	if (fd < 0) err(1, "open");

	arg = argc > 1 ? atoi(argv[1]) : 1;
	ret = ioctl(fd, KVM_CPC_DEBUG, &arg);
	if (ret == -1) err(1, "ioctl KVM_CPC_DEBUG");

	close(fd);
}
