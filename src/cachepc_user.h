#pragma once

#include <linux/ioctl.h>

#define CACHEPC_IOCTL_MAGIC 0xBF
#define CACHEPC_IOCTL_ACCESS_TEST _IOR(CACHEPC_IOCTL_MAGIC, 0, int)
