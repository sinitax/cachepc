#pragma once

#include "cachepc.h"

#include <linux/fs.h>

long cachepc_kvm_ioctl(struct file *file, unsigned int cmd, unsigned long argp);

void cachepc_kvm_init(void);
void cachepc_kvm_exit(void);
