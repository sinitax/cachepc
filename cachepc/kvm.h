#pragma once

#include "cachepc.h"

#include <linux/fs.h>

long cpc_kvm_ioctl(struct file *file, unsigned int cmd, unsigned long argp);

void cpc_kvm_init(void);
void cpc_kvm_exit(void);
