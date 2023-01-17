#define _GNU_SOURCE

#include "test/kvm.h"
#include "test/util.h"
#include "cachepc/uapi.h"

#include <linux/psp-sev.h>
#include <linux/kvm.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>
#include <assert.h>
#include <errno.h>
#include <err.h>
#include <fcntl.h>
#include <sched.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int kvm_dev, sev_dev;

const char *sev_fwerr_strs[] = {
	[0x00] = "Success",
	[0x01] = "Platform state is invalid",
	[0x02] = "Guest state is invalid",
	[0x03] = "Platform configuration is invalid",
	[0x04] = "Buffer too small",
	[0x05] = "Platform is already owned",
	[0x06] = "Certificate is invalid",
	[0x07] = "Request not allowed by policy",
	[0x08] = "Guest is inactive",
	[0x09] = "Invalid address",
	[0x0A] = "Bad signature",
	[0x0B] = "Bad measurement",
	[0x0C] = "Asid is already owned",
	[0x0D] = "Invalid ASID",
	[0x0E] = "WBINVD is required",
	[0x0F] = "DF_FLUSH is required",
	[0x10] = "Guest handle is invalid",
	[0x11] = "Invalid command",
	[0x12] = "Guest is active",
	[0x13] = "Hardware error",
	[0x14] = "Hardware unsafe",
	[0x15] = "Feature not supported",
	[0x16] = "Invalid parameter",
	[0x17] = "Out of resources",
	[0x18] = "Integrity checks failed",
	[0x19] = "RMP page size is incorrect",
	[0x1A] = "RMP page state is incorrect",
};

const char *sev_gstate_strs[] = {
	"UNINIT",
	"LUPDATE",
	"LSECRET",
	"RUNNING",
	"SUPDATE",
	"RUPDATE",
	"SEND"
};

const char *
sev_fwerr_str(int code)
{
	if (code < 0 || code >= ARRLEN(sev_fwerr_strs))
		return "Unknown error";

	return sev_fwerr_strs[code];
}

const char *
sev_gstate_str(int code)
{
	if (code < 0 || code >= ARRLEN(sev_gstate_strs))
		return "Unknown gstate";

	return sev_gstate_strs[code];
}

int
sev_ioctl(int vmfd, int cmd, void *data, int *error)
{
	struct kvm_sev_cmd input;
	int ret;

	memset(&input, 0, sizeof(input));
	input.id = cmd;
	input.sev_fd = sev_dev;
	input.data = (uintptr_t) data;

	ret = ioctl(vmfd, KVM_MEMORY_ENCRYPT_OP, &input);
	if (error) *error = input.error;

	return ret;
}

void
sev_get_measure(int vmfd)
{
	struct kvm_sev_launch_measure msrmt;
	int ret, fwerr;
	uint8_t *data;

	memset(&msrmt, 0, sizeof(msrmt));
	ret = sev_ioctl(vmfd, KVM_SEV_LAUNCH_MEASURE, &msrmt, &fwerr);
	if (ret == -1 && fwerr != SEV_RET_INVALID_LEN)
		errx(1, "KVM_SEV_LAUNCH_MEASURE: (%s) %s",
			strerror(errno), sev_fwerr_str(fwerr));

	data = malloc(msrmt.len);
	msrmt.uaddr = (uintptr_t) data;

	ret = sev_ioctl(vmfd, KVM_SEV_LAUNCH_MEASURE, &msrmt, &fwerr);
	if (ret == -1) errx(1, "KVM_SEV_LAUNCH_MEASURE: (%s) %s",
		strerror(errno), sev_fwerr_str(fwerr));

	free(data);
}

uint8_t
sev_guest_state(int vmfd, uint32_t handle)
{
	struct kvm_sev_guest_status status;
	int ret, fwerr;

	status.handle = handle;
	ret = sev_ioctl(vmfd, KVM_SEV_GUEST_STATUS, &status, &fwerr);
	if (ret == -1) errx(1, "KVM_SEV_GUEST_STATUS: (%s) %s",
		strerror(errno), sev_fwerr_str(fwerr));

	return status.state;
}

void
sev_dbg_decrypt(int vmfd, void *src, void *dst, size_t size)
{
	struct kvm_sev_dbg enc;
	int ret, fwerr;

	enc.src_uaddr = (uintptr_t) src;
	enc.dst_uaddr = (uintptr_t) dst;
	enc.len = size;
	ret = sev_ioctl(vmfd, KVM_SEV_DBG_DECRYPT, &enc, &fwerr);
	if (ret == -1) errx(1, "KVM_SEV_DBG_DECRYPT: (%s) %s",
		strerror(errno), sev_fwerr_str(fwerr));
}

uint64_t
sev_dbg_decrypt_rip(int vmfd)
{
	uint8_t vmsa[PAGE_SIZE];
	uint64_t rip;

	memset(vmsa, 0, PAGE_SIZE);
	sev_dbg_decrypt(vmfd, vmsa, CPC_VMSA_MAGIC_ADDR, PAGE_SIZE);

	rip = *(uint64_t *)(vmsa + 0x178);

	return rip;
}

void
snp_dbg_decrypt(int vmfd, void *src, void *dst, size_t size)
{
	struct kvm_sev_dbg enc;
	int ret, fwerr;

	assert(src == CPC_VMSA_MAGIC_ADDR);

	memset(&enc, 0, sizeof(struct kvm_sev_dbg));
	enc.src_uaddr = (uintptr_t) src;
	enc.dst_uaddr = (uintptr_t) dst;
	enc.len = size;

	ret = sev_ioctl(vmfd, KVM_SEV_DBG_DECRYPT, &enc, &fwerr);
	if (ret < 0) errx(1, "KVM_SEV_DBG_DECRYPT: (%s) %s",
		strerror(errno), sev_fwerr_str(fwerr));
}

uint64_t
snp_dbg_decrypt_rip(int vmfd)
{
	uint8_t vmsa[PAGE_SIZE];
	uint64_t rip;

	memset(vmsa, 0, PAGE_SIZE);
	snp_dbg_decrypt(vmfd, CPC_VMSA_MAGIC_ADDR, vmsa, PAGE_SIZE);

	rip = *(uint64_t *)(vmsa + 0x178);

	return rip;
}

void
kvm_init(struct kvm *kvm, size_t ramsize,
	void *code_start, void *code_stop)
{
	struct kvm_userspace_memory_region region;
	struct kvm_regs regs;
	struct kvm_sregs sregs;
	int ret;

	/* Create a kvm instance */
	kvm->vmfd = ioctl(kvm_dev, KVM_CREATE_VM, 0);
	if (kvm->vmfd < 0) err(1, "KVM_CREATE_VM");

	/* Allocate guest memory */
	kvm->memsize = ramsize;
	kvm->mem = mmap(NULL, kvm->memsize, PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (!kvm->mem) err(1, "Allocating guest memory");
	assert(code_stop - code_start <= kvm->memsize);
	memcpy(kvm->mem, code_start, code_stop - code_start);

	/* Map it into the vm */
	memset(&region, 0, sizeof(region));
	region.slot = 0;
	region.memory_size = kvm->memsize;
	region.guest_phys_addr = 0x0000;
	region.userspace_addr = (uintptr_t) kvm->mem;
	ret = ioctl(kvm->vmfd, KVM_SET_USER_MEMORY_REGION, &region);
	if (ret == -1) err(1, "KVM_SET_USER_MEMORY_REGION");

	/* Create virtual cpu core */
	kvm->vcpufd = ioctl(kvm->vmfd, KVM_CREATE_VCPU, 0);
	if (kvm->vcpufd < 0) err(1, "KVM_CREATE_VCPU");

	/* Map the shared kvm_run structure and following data */
	ret = ioctl(kvm_dev, KVM_GET_VCPU_MMAP_SIZE, NULL);
	if (ret == -1) err(1, "KVM_GET_VCPU_MMAP_SIZE");
	if (ret < sizeof(struct kvm_run))
		errx(1, "KVM_GET_VCPU_MMAP_SIZE too small");
	kvm->run = mmap(NULL, ret, PROT_READ | PROT_WRITE,
		MAP_SHARED, kvm->vcpufd, 0);
	if (!kvm->run) err(1, "mmap vcpu");

	/* Initialize segment regs */
	memset(&sregs, 0, sizeof(sregs));
	ret = ioctl(kvm->vcpufd, KVM_GET_SREGS, &sregs);
	if (ret == -1) err(1, "KVM_GET_SREGS");
	sregs.cs.base = 0;
	sregs.cs.selector = 0;
	ret = ioctl(kvm->vcpufd, KVM_SET_SREGS, &sregs);
	if (ret == -1) err(1, "KVM_SET_SREGS");

	/* Initialize rest of registers */
	memset(&regs, 0, sizeof(regs));
	regs.rip = 0;
	regs.rsp = kvm->memsize - 8;
	regs.rbp = kvm->memsize - 8;
	regs.rflags = 0x2;
	ret = ioctl(kvm->vcpufd, KVM_SET_REGS, &regs);
	if (ret == -1) err(1, "KVM_SET_REGS");
}

void
sev_kvm_init(struct kvm *kvm, size_t ramsize,
	void *code_start, void *code_stop)
{
	struct kvm_userspace_memory_region region;
	struct kvm_sev_launch_update_data update;
	struct kvm_sev_launch_start start;
	struct kvm_regs regs;
	struct kvm_sregs sregs;
	int ret, fwerr;

	/* Create a kvm instance */
	kvm->vmfd = ioctl(kvm_dev, KVM_CREATE_VM, 0);
	if (kvm->vmfd < 0) err(1, "KVM_CREATE_VM");

	/* Allocate guest memory */
	kvm->memsize = ramsize;
	kvm->mem = mmap(NULL, kvm->memsize, PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (!kvm->mem) err(1, "Allocating guest memory");
	assert(code_stop - code_start <= kvm->memsize);
	memcpy(kvm->mem, code_start, code_stop - code_start);

	/* Map it into the vm */
	memset(&region, 0, sizeof(region));
	region.slot = 0;
	region.memory_size = kvm->memsize;
	region.guest_phys_addr = 0;
	region.userspace_addr = (uintptr_t) kvm->mem;
	ret = ioctl(kvm->vmfd, KVM_SET_USER_MEMORY_REGION, &region);
	if (ret == -1) err(1, "KVM_SET_USER_MEMORY_REGION");

	/* Enable SEV for vm */
	ret = sev_ioctl(kvm->vmfd, KVM_SEV_INIT, NULL, &fwerr);
	if (ret == -1) errx(1, "KVM_SEV_INIT: (%s) %s",
		strerror(errno), sev_fwerr_str(fwerr));

	/* Create virtual cpu core */
	kvm->vcpufd = ioctl(kvm->vmfd, KVM_CREATE_VCPU, 0);
	if (kvm->vcpufd < 0) err(1, "KVM_CREATE_VCPU");

	/* Map the shared kvm_run structure and following data */
	ret = ioctl(kvm_dev, KVM_GET_VCPU_MMAP_SIZE, NULL);
	if (ret == -1) err(1, "KVM_GET_VCPU_MMAP_SIZE");
	if (ret < sizeof(struct kvm_run))
		errx(1, "KVM_GET_VCPU_MMAP_SIZE too small");
	kvm->run = mmap(NULL, ret, PROT_READ | PROT_WRITE,
		MAP_SHARED, kvm->vcpufd, 0);
	if (!kvm->run) err(1, "mmap vcpu");

	/* Initialize segment regs */
	memset(&sregs, 0, sizeof(sregs));
	ret = ioctl(kvm->vcpufd, KVM_GET_SREGS, &sregs);
	if (ret == -1) err(1, "KVM_GET_SREGS");
	sregs.cs.base = 0;
	sregs.cs.selector = 0;
	ret = ioctl(kvm->vcpufd, KVM_SET_SREGS, &sregs);
	if (ret == -1) err(1, "KVM_SET_SREGS");

	/* Initialize rest of registers */
	memset(&regs, 0, sizeof(regs));
	regs.rip = 0;
	regs.rsp = kvm->memsize - 8;
	regs.rbp = kvm->memsize - 8;
	regs.rflags = 0x2;
	ret = ioctl(kvm->vcpufd, KVM_SET_REGS, &regs);
	if (ret == -1) err(1, "KVM_SET_REGS");

	/* Generate encryption keys and set policy */
	memset(&start, 0, sizeof(start));
	start.handle = 0;
	start.policy = 0;
	ret = sev_ioctl(kvm->vmfd, KVM_SEV_LAUNCH_START, &start, &fwerr);
	if (ret == -1) errx(1, "KVM_SEV_LAUNCH_START: (%s) %s",
		strerror(errno), sev_fwerr_str(fwerr));

	/* Prepare the vm memory (by encrypting it) */
	memset(&update, 0, sizeof(update));
	update.uaddr = (uintptr_t) kvm->mem;
	update.len = ramsize;
	ret = sev_ioctl(kvm->vmfd, KVM_SEV_LAUNCH_UPDATE_DATA, &update, &fwerr);
	if (ret == -1) errx(1, "KVM_SEV_LAUNCH_UPDATE_DATA: (%s) %s",
		strerror(errno), sev_fwerr_str(fwerr));

	/* Collect a measurement (necessary) */
	sev_get_measure(kvm->vmfd);

	/* Finalize launch process */
	ret = sev_ioctl(kvm->vmfd, KVM_SEV_LAUNCH_FINISH, 0, &fwerr);
	if (ret == -1) errx(1, "KVM_SEV_LAUNCH_FINISH: (%s) %s",
		strerror(errno), sev_fwerr_str(fwerr));

	ret = sev_guest_state(kvm->vmfd, start.handle);
	if (ret != GSTATE_RUNNING)
		errx(1, "Bad guest state: %s", sev_gstate_str(fwerr));
}

void
sev_es_kvm_init(struct kvm *kvm, size_t ramsize,
	void *code_start, void *code_stop)
{
	struct kvm_userspace_memory_region region;
	struct kvm_sev_launch_update_data update;
	struct kvm_sev_launch_start start;
	struct kvm_regs regs;
	struct kvm_sregs sregs;
	int ret, fwerr;

	/* Create a kvm instance */
	kvm->vmfd = ioctl(kvm_dev, KVM_CREATE_VM, 0);
	if (kvm->vmfd < 0) err(1, "KVM_CREATE_VM");

	/* Allocate guest memory */
	kvm->memsize = ramsize;
	kvm->mem = mmap(NULL, kvm->memsize, PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (!kvm->mem) err(1, "Allocating guest memory");
	assert(code_stop - code_start <= kvm->memsize);
	memcpy(kvm->mem, code_start, code_stop - code_start);

	/* Map it into the vm */
	memset(&region, 0, sizeof(region));
	region.slot = 0;
	region.memory_size = kvm->memsize;
	region.guest_phys_addr = 0;
	region.userspace_addr = (uintptr_t) kvm->mem;
	ret = ioctl(kvm->vmfd, KVM_SET_USER_MEMORY_REGION, &region);
	if (ret == -1) err(1, "KVM_SET_USER_MEMORY_REGION");

	/* Enable SEV for vm */
	ret = sev_ioctl(kvm->vmfd, KVM_SEV_ES_INIT, NULL, &fwerr);
	if (ret == -1) errx(1, "KVM_SEV_ES_INIT: (%s) %s",
		strerror(errno), sev_fwerr_str(fwerr));

	/* Create virtual cpu core */
	kvm->vcpufd = ioctl(kvm->vmfd, KVM_CREATE_VCPU, 0);
	if (kvm->vcpufd < 0) err(1, "KVM_CREATE_VCPU");

	/* Map the shared kvm_run structure and following data */
	ret = ioctl(kvm_dev, KVM_GET_VCPU_MMAP_SIZE, NULL);
	if (ret == -1) err(1, "KVM_GET_VCPU_MMAP_SIZE");
	if (ret < sizeof(struct kvm_run))
		errx(1, "KVM_GET_VCPU_MMAP_SIZE too small");
	kvm->run = mmap(NULL, ret, PROT_READ | PROT_WRITE,
		MAP_SHARED, kvm->vcpufd, 0);
	if (!kvm->run) err(1, "mmap vcpu");

	/* Initialize segment regs */
	memset(&sregs, 0, sizeof(sregs));
	ret = ioctl(kvm->vcpufd, KVM_GET_SREGS, &sregs);
	if (ret == -1) err(1, "KVM_GET_SREGS");
	sregs.cs.base = 0;
	sregs.cs.selector = 0;
	ret = ioctl(kvm->vcpufd, KVM_SET_SREGS, &sregs);
	if (ret == -1) err(1, "KVM_SET_SREGS");

	/* Initialize rest of registers */
	memset(&regs, 0, sizeof(regs));
	regs.rip = 0;
	regs.rsp = kvm->memsize - 8;
	regs.rbp = kvm->memsize - 8;
	regs.rflags = 0x2;
	ret = ioctl(kvm->vcpufd, KVM_SET_REGS, &regs);
	if (ret == -1) err(1, "KVM_SET_REGS");

	/* Generate encryption keys and set policy */
	memset(&start, 0, sizeof(start));
	start.handle = 0;
	start.policy = 1 << 2; /* require SEV-ES */
	ret = sev_ioctl(kvm->vmfd, KVM_SEV_LAUNCH_START, &start, &fwerr);
	if (ret == -1) errx(1, "KVM_SEV_LAUNCH_START: (%s) %s",
		strerror(errno), sev_fwerr_str(fwerr));

	/* Prepare the vm memory (by encrypting it) */
	memset(&update, 0, sizeof(update));
	update.uaddr = (uintptr_t) kvm->mem;
	update.len = ramsize;
	ret = sev_ioctl(kvm->vmfd, KVM_SEV_LAUNCH_UPDATE_DATA, &update, &fwerr);
	if (ret == -1) errx(1, "KVM_SEV_LAUNCH_UPDATE_DATA: (%s) %s",
		strerror(errno), sev_fwerr_str(fwerr));

	/* Prepare the vm save area */
	ret = sev_ioctl(kvm->vmfd, KVM_SEV_LAUNCH_UPDATE_VMSA, NULL, &fwerr);
	if (ret == -1) errx(1, "KVM_SEV_LAUNCH_UPDATE_VMSA: (%s) %s",
		strerror(errno), sev_fwerr_str(fwerr));

	/* Collect a measurement (necessary) */
	sev_get_measure(kvm->vmfd);

	/* Finalize launch process */
	ret = sev_ioctl(kvm->vmfd, KVM_SEV_LAUNCH_FINISH, 0, &fwerr);
	if (ret == -1) errx(1, "KVM_SEV_LAUNCH_FINISH: (%s) %s",
		strerror(errno), sev_fwerr_str(fwerr));

	ret = sev_guest_state(kvm->vmfd, start.handle);
	if (ret != GSTATE_RUNNING)
		errx(1, "Bad guest state: %s", sev_gstate_str(fwerr));
}

void
sev_snp_kvm_init(struct kvm *kvm, size_t ramsize,
	void *code_start, void *code_stop)
{
	struct kvm_sev_snp_launch_update update;
	struct kvm_sev_snp_launch_start start;
	struct kvm_sev_snp_launch_finish finish;
	struct kvm_snp_init init;
	struct kvm_userspace_memory_region region;
	struct kvm_enc_region enc_region;
	struct kvm_sregs sregs;
	struct kvm_regs regs;
	int ret, fwerr;

	/* Create a kvm instance */
	kvm->vmfd = ioctl(kvm_dev, KVM_CREATE_VM, 0);
	if (kvm->vmfd < 0) err(1, "KVM_CREATE_VM");

	/* Allocate guest memory */
	kvm->memsize = ramsize;
	kvm->mem = mmap(NULL, kvm->memsize, PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (!kvm->mem) err(1, "Allocating guest memory");
	assert(code_stop - code_start <= kvm->memsize);
	memcpy(kvm->mem, code_start, code_stop - code_start);

	/* Map it into the vm */
	memset(&region, 0, sizeof(region));
	region.slot = 0;
	region.memory_size = kvm->memsize;
	region.guest_phys_addr = 0;
	region.userspace_addr = (uintptr_t) kvm->mem;
	ret = ioctl(kvm->vmfd, KVM_SET_USER_MEMORY_REGION, &region);
	if (ret == -1) err(1, "KVM_SET_USER_MEMORY_REGION");

	/* Enable SEV for vm */
	memset(&init, 0, sizeof(init));
	ret = sev_ioctl(kvm->vmfd, KVM_SEV_SNP_INIT, &init, &fwerr);
	if (ret == -1) errx(1, "KVM_SEV_SNP_INIT: (%s) %s",
		strerror(errno), sev_fwerr_str(fwerr));

	/* Register memory region */
	memset(&enc_region, 0, sizeof(enc_region));
	enc_region.addr = (uintptr_t) kvm->mem;
	enc_region.size = kvm->memsize;
	ret = ioctl(kvm->vmfd, KVM_MEMORY_ENCRYPT_REG_REGION, &enc_region);
	if (ret == -1) err(1, "KVM_MEMORY_ENCRYPT_REG_REGION");

	/* Create virtual cpu */
	kvm->vcpufd = ioctl(kvm->vmfd, KVM_CREATE_VCPU, 0);
	if (kvm->vcpufd < 0) err(1, "KVM_CREATE_VCPU");

	/* Map the shared kvm_run structure and following data */
	ret = ioctl(kvm_dev, KVM_GET_VCPU_MMAP_SIZE, NULL);
	if (ret == -1) err(1, "KVM_GET_VCPU_MMAP_SIZE");
	if (ret < sizeof(struct kvm_run))
		errx(1, "KVM_GET_VCPU_MMAP_SIZE too small");
	kvm->run = mmap(NULL, ret, PROT_READ | PROT_WRITE,
		MAP_SHARED, kvm->vcpufd, 0);
	if (!kvm->run) err(1, "mmap vcpu");

	/* Initialize segment regs */
	memset(&sregs, 0, sizeof(sregs));
	ret = ioctl(kvm->vcpufd, KVM_GET_SREGS, &sregs);
	if (ret == -1) err(1, "KVM_GET_SREGS");
	sregs.cs.base = 0;
	sregs.cs.selector = 0;
	ret = ioctl(kvm->vcpufd, KVM_SET_SREGS, &sregs);
	if (ret == -1) err(1, "KVM_SET_SREGS");

	/* Initialize rest of registers */
	memset(&regs, 0, sizeof(regs));
	regs.rip = 0;
	regs.rsp = kvm->memsize - 8 - L1_LINESIZE * L1_SETS;
	regs.rbp = kvm->memsize - 8 - L1_LINESIZE * L1_SETS;
	ret = ioctl(kvm->vcpufd, KVM_SET_REGS, &regs);
	if (ret == -1) err(1, "KVM_SET_REGS");

	/* Generate encryption keys and set policy */
	memset(&start, 0, sizeof(start));
	start.policy = 1 << 17; /* must be set */
	start.policy |= 1 << 19; /* allow debug */
	start.policy |= 1 << 16; /* allow simultaneous multi-threading */ 
	ret = sev_ioctl(kvm->vmfd, KVM_SEV_SNP_LAUNCH_START, &start, &fwerr);
	if (ret == -1) errx(1, "KVM_SEV_SNP_LAUNCH_START: (%s) %s",
		strerror(errno), sev_fwerr_str(fwerr));

	/* Prepare the vm memory */
	memset(&update, 0, sizeof(update));
	update.uaddr = (uintptr_t) kvm->mem;
	update.len = ramsize;
	update.start_gfn = 0;
	update.page_type = KVM_SEV_SNP_PAGE_TYPE_NORMAL;
	ret = sev_ioctl(kvm->vmfd, KVM_SEV_SNP_LAUNCH_UPDATE, &update, &fwerr);
	if (ret == -1) errx(1, "KVM_SEV_SNP_LAUNCH_UPDATE: (%s) %s",
		strerror(errno), sev_fwerr_str(fwerr));

	/* Finalize launch process */
	memset(&finish, 0, sizeof(finish));
	ret = sev_ioctl(kvm->vmfd, KVM_SEV_SNP_LAUNCH_FINISH, &finish, &fwerr);
	if (ret == -1) errx(1, "KVM_SEV_SNP_LAUNCH_FINISH: (%s) %s",
		strerror(errno), sev_fwerr_str(fwerr));
}

void
kvm_deinit(struct kvm *kvm)
{
	close(kvm->vmfd);
	close(kvm->vcpufd);
	munmap(kvm->mem, kvm->memsize);
}

void
kvm_setup_init(void)
{
	int ret;

	kvm_dev = open("/dev/kvm", O_RDWR | O_CLOEXEC);
	if (kvm_dev < 0) err(1, "open /dev/kvm");

	sev_dev = open("/dev/sev", O_RDWR | O_CLOEXEC);
	if (sev_dev < 0) err(1, "open /dev/sev");

	/* ensure we have the stable version of the api */
	ret = ioctl(kvm_dev, KVM_GET_API_VERSION, NULL);
	if (ret == -1) err(1, "KVM_GET_API_VERSION");
	if (ret != 12) errx(1, "KVM_GET_API_VERSION %d, expected 12", ret);

}

void
kvm_setup_deinit(void)
{
	close(kvm_dev);
	close(sev_dev);
}
