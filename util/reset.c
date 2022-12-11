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
	uint64_t arg;
	int fd, ret;

	fd = open("/dev/kvm", O_RDONLY);
	if (fd < 0) err(1, "open");

	ret = ioctl(fd, KVM_CPC_RESET_TRACKING);
	if (ret) warn("ioctl RESET_TRACKING");

	arg = 0;
	ret = ioctl(fd, KVM_CPC_ACK_EVENT, &arg);
	if (ret) warn("ioctl ACK_EVENT");

	close(fd);
}
