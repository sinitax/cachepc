#include "cachepc/uapi.h"

#include <sys/ioctl.h>
#include <err.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int
main(int argc, const char **argv)
{
	uint32_t svme;
	int kvm_fd;

	kvm_fd = open("/dev/kvm", O_RDWR);
	if (kvm_fd < 0) err(1, "open /dev/kvm");

	if (ioctl(kvm_fd, KVM_CPC_SVME_READ, &svme))
		err(1, "ioctl SVME_READ");

	printf("%u\n", svme);

	close(kvm_fd);
}
