#include "cachepc/uapi.h"

#include <sys/ioctl.h>
#include <fcntl.h>
#include <err.h>
#include <unistd.h>

int
main(int argc, const char **argv)
{
	int fd, ret;

	fd = open("/dev/kvm", O_RDONLY);
	if (fd < 0) err(1, "open");

	ret = ioctl(fd, KVM_CPC_RESET);
	if (ret) warn("ioctl KVM_CPC_RESET");

	close(fd);
}
