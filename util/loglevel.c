#include "cachepc/uapi.h"

#include <sys/ioctl.h>
#include <fcntl.h>
#include <err.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

int
main(int argc, const char **argv)
{
	uint32_t arg;
	int fd, ret;

	fd = open("/dev/kvm", O_RDONLY);
	if (fd < 0) err(1, "open");

	if (argc > 1 && !strcmp(argv[1], "debug"))
		arg = CPC_LOGLVL_DBG;
	else if (argc > 1 && !strcmp(argv[1], "info"))
		arg = CPC_LOGLVL_INFO;
	else
		arg = 0;

	printf("loglevel: %i\n", arg);
	ret = ioctl(fd, KVM_CPC_LOGLEVEL, &arg);
	if (ret == -1) err(1, "ioctl KVM_CPC_LOGLEVEL");

	close(fd);
}
