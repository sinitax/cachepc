#include "sevstep/uapi.h"

#include <linux/kvm.h>
#include <sys/ioctl.h>

#include <err.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>

int
main(int argc, const char **argv)
{
	track_all_pages_t tracking;
	int ret, fd;

	fd = open("/proc/cachepc", O_RDONLY);
	if (!fd) err(1, "open");

	tracking.track_mode = KVM_PAGE_TRACK_ACCESS;
	ret = ioctl(fd, KVM_USPT_TRACK_ALL, &tracking); 
	if (ret == -1) err(1, "ioctl TRACK_ALL ACCESS");


	tracking.track_mode = KVM_PAGE_TRACK_RESET_ACCESSED;
	ret = ioctl(fd, KVM_USPT_TRACK_ALL, &tracking); 
	if (ret == -1) err(1, "ioctl TRACK_ALL RESET_ACCESSED");

	ret = ioctl(fd, KVM_USPT_UNTRACK_ALL, &tracking); 
	if (ret == -1) err(1, "ioctl UNTRACK_ALL");

	close(fd);
}
