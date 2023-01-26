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
const char *vmtype;

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

	if (vmfd == MAIN_VMFD) {
		ret = ioctl(kvm_dev, KVM_CPC_MEMORY_ENCRYPT_OP, &input);
		if (error) *error = input.error;
	} else {
		ret = ioctl(vmfd, KVM_MEMORY_ENCRYPT_OP, &input);
		if (error) *error = input.error;
	}

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
guest_init(struct guest *guest, const char *filename)
{
	FILE *f;

	f = fopen(filename, "r");
	if (!f) err(1, "fopen");

	fseek(f, 0, SEEK_END);
	guest->code_size = ftell(f);
	fseek(f, 0, SEEK_SET);

	guest->code = malloc(guest->code_size);
	if (!guest->code) err(1, "malloc");

	if (!fread(guest->code, guest->code_size, 1, f))
		errx(1, "read guest");

	guest->mem_size = 0;

	fclose(f);
}

void
guest_deinit(struct guest *guest)
{
	free(guest->code);
}

void
kvm_create_vm(struct kvm *kvm)
{
	kvm->vmfd = ioctl(kvm_dev, KVM_CREATE_VM, 0);
	if (kvm->vmfd < 0) err(1, "KVM_CREATE_VM");
}

void
kvm_init_memory(struct kvm *kvm, size_t mem_size, void *code, size_t code_size)
{
	struct kvm_userspace_memory_region region;
	int ret;

	kvm->memsize = mem_size;
	kvm->mem = mmap(NULL, kvm->memsize, PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (!kvm->mem) err(1, "mmap kvm->mem");
	/* nop slide oob to detect errors quickly */
	memset(kvm->mem, 0x90, kvm->memsize);
	assert(code_size <= kvm->memsize);
	memcpy(kvm->mem, code, code_size);

	memset(&region, 0, sizeof(region));
	region.slot = 0;
	region.memory_size = kvm->memsize;
	region.guest_phys_addr = 0x0000;
	region.userspace_addr = (uintptr_t) kvm->mem;
	ret = ioctl(kvm->vmfd, KVM_SET_USER_MEMORY_REGION, &region);
	if (ret == -1) err(1, "KVM_SET_USER_MEMORY_REGION");
}

void
kvm_create_vcpu(struct kvm *kvm)
{
	int ret;

	kvm->vcpufd = ioctl(kvm->vmfd, KVM_CREATE_VCPU, 0);
	if (kvm->vcpufd < 0) err(1, "KVM_CREATE_VCPU");

	ret = ioctl(kvm_dev, KVM_GET_VCPU_MMAP_SIZE, NULL);
	if (ret == -1) err(1, "KVM_GET_VCPU_MMAP_SIZE");
	if (ret < sizeof(struct kvm_run))
		errx(1, "KVM_GET_VCPU_MMAP_SIZE too small");
	kvm->runsize = ret;
	kvm->run = mmap(NULL, kvm->runsize, PROT_READ | PROT_WRITE,
		MAP_SHARED, kvm->vcpufd, 0);
	if (!kvm->run) err(1, "mmap kvm->run");
}

void
kvm_init_regs(struct kvm *kvm)
{
	struct kvm_regs regs;
	struct kvm_sregs sregs;
	int ret;

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
	ret = ioctl(kvm->vcpufd, KVM_SET_REGS, &regs);
	if (ret == -1) err(1, "KVM_SET_REGS");
}

void
kvm_init(struct kvm *kvm, struct guest *guest)
{
	kvm_create_vm(kvm);

	kvm_init_memory(kvm, guest->mem_size, guest->code, guest->code_size);

	kvm_create_vcpu(kvm);

	kvm_init_regs(kvm);
}

void
sev_kvm_init(struct kvm *kvm, struct guest *guest)
{
	struct kvm_sev_launch_update_data update;
	struct kvm_sev_launch_start start;
	int ret, fwerr;

	kvm_create_vm(kvm);

	kvm_init_memory(kvm, guest->mem_size, guest->code, guest->code_size);

	/* Enable SEV for vm */
	ret = sev_ioctl(kvm->vmfd, KVM_SEV_INIT, NULL, &fwerr);
	if (ret == -1) errx(1, "KVM_SEV_INIT: (%s) %s",
		strerror(errno), sev_fwerr_str(fwerr));

	kvm_create_vcpu(kvm);

	kvm_init_regs(kvm);

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
	update.len = kvm->memsize;
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
sev_es_kvm_init(struct kvm *kvm, struct guest *guest)
{
	struct kvm_sev_launch_update_data update;
	struct kvm_sev_launch_start start;
	int ret, fwerr;

	kvm_create_vm(kvm);

	kvm_init_memory(kvm, guest->mem_size, guest->code, guest->code_size);

	/* Enable SEV for vm */
	ret = sev_ioctl(kvm->vmfd, KVM_SEV_ES_INIT, NULL, &fwerr);
	if (ret == -1) errx(1, "KVM_SEV_ES_INIT: (%s) %s",
		strerror(errno), sev_fwerr_str(fwerr));

	kvm_create_vcpu(kvm);

	kvm_init_regs(kvm);

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
	update.len = kvm->memsize;
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
sev_snp_kvm_init(struct kvm *kvm, struct guest *guest)
{
	struct kvm_sev_snp_launch_update update;
	struct kvm_sev_snp_launch_start start;
	struct kvm_sev_snp_launch_finish finish;
	struct kvm_enc_region enc_region;
	struct kvm_snp_init init;
	int ret, fwerr;

	kvm_create_vm(kvm);

	kvm_init_memory(kvm, guest->mem_size, guest->code, guest->code_size);

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

	kvm_create_vcpu(kvm);

	kvm_init_regs(kvm);

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
	update.len = kvm->memsize;
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
	munmap(kvm->run, kvm->runsize);
}

uint64_t
vm_get_rip(void)
{
	struct cpc_sev_cmd cmd;
	int ret, fwerr;

	cmd.id = SEV_CPC_GET_RIP;
	ret = sev_ioctl(MAIN_VMFD, KVM_SEV_CACHEPC, &cmd, &fwerr);
	if (ret == -1) errx(1, "KVM_SEV_CACHEPC: (%s) %s",
		strerror(errno), sev_fwerr_str(fwerr));

	return cmd.data;
}

void
parse_vmtype(int argc, const char **argv)
{
	vmtype = "kvm";
	if (argc > 1) vmtype = argv[1];
	if (strcmp(vmtype, "kvm") && strcmp(vmtype, "sev")
			&& strcmp(vmtype, "sev-es")
			&& strcmp(vmtype, "sev-snp"))
		errx(1, "invalid vm mode: %s", vmtype);
}

void
vm_init(struct kvm *kvm, struct guest *guest)
{
	if (!guest->mem_size)
		guest->mem_size = L1_SIZE * 2;

	if (!strcmp(vmtype, "kvm")) {
		kvm_init(kvm, guest);
	} else if (!strcmp(vmtype, "sev")) {
		sev_kvm_init(kvm, guest);
	} else if (!strcmp(vmtype, "sev-es")) {
		sev_es_kvm_init(kvm, guest);
	} else if (!strcmp(vmtype, "sev-snp")) {
		sev_snp_kvm_init(kvm, guest);
	} else {
		errx(1, "invalid version");
	}
}

void
vm_deinit(struct kvm *kvm)
{
	kvm_deinit(kvm);
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
