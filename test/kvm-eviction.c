#define _GNU_SOURCE

#include "kvm-eviction.h"
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
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>

#define ARRLEN(x) (sizeof(x) / sizeof((x)[0]))
#define MIN(a,b) ((a) > (b) ? (b) : (a))

#define SAMPLE_COUNT 64

#define TARGET_CORE 2
#define SECONDARY_CORE 3

enum {
	WITH,
	WITHOUT
};

struct kvm {
	int fd, vmfd, vcpufd;
	void *mem;
	size_t memsize;
	struct kvm_run *run;
};

/* start and end for guest assembly */
extern uint8_t start_guest_with[];
extern uint8_t stop_guest_with[];
extern uint8_t start_guest_without[];
extern uint8_t stop_guest_without[];

static const char *vmtype;

static int kvm_dev, sev_dev;

enum {
	GSTATE_UNINIT,
	GSTATE_LUPDATE,
	GSTATE_LSECRET,
	GSTATE_RUNNING,
	GSTATE_SUPDATE,
	GSTATE_RUPDATE,
	GSTATE_SENT
};

const char *sev_fwerr_strs[] = {
	"Success",
	"Platform state is invalid",
	"Guest state is invalid",
	"Platform configuration is invalid",
	"Buffer too small",
	"Platform is already owned",
	"Certificate is invalid",
	"Policy is not allowed",
	"Guest is not active",
	"Invalid address",
	"Bad signature",
	"Bad measurement",
	"Asid is already owned",
	"Invalid ASID",
	"WBINVD is required",
	"DF_FLUSH is required",
	"Guest handle is invalid",
	"Invalid command",
	"Guest is active",
	"Hardware error",
	"Hardware unsafe",
	"Feature not supported",
	"Invalid parameter",
	"Out of resources",
	"Integrity checks failed"
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

void
hexdump(void *data, int len)
{
	int i;

	for (i = 0; i < len; i++) {
		if (i % 16 == 0 && i)
			printf("\n");
		printf("%02X ", *(uint8_t *)(data + i));
	}
	printf("\n");
}

bool
pin_process(pid_t pid, int cpu, bool assert)
{
	cpu_set_t cpuset;
	int ret;

	CPU_ZERO(&cpuset);
	CPU_SET(cpu, &cpuset);
	ret = sched_setaffinity(pid, sizeof(cpu_set_t), &cpuset);
	if (ret == -1) {
		if (assert) err(1, "sched_setaffinity");
		return false;
	}

	return true;
}

int
read_stat_core(pid_t pid)
{
	char path[256];
	char line[2048];
	FILE *file;
	char *p;
	int i, cpu;

	snprintf(path, sizeof(path), "/proc/%u/stat", pid);
	file = fopen(path, "r");
	if (!file) return -1;

	if (!fgets(line, sizeof(line), file))
		err(1, "read stat");

	p = line;
	for (i = 0; i < 38 && (p = strchr(p, ' ')); i++)
		p += 1;

	if (!p) errx(1, "stat format");
	cpu = atoi(p);

	fclose(file);

	return cpu;
}

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
sev_debug_encrypt(int vmfd, void *src, void *dst, size_t size)
{
	struct kvm_sev_dbg enc;
	int ret, fwerr;

	enc.src_uaddr = (uintptr_t) src;
	enc.dst_uaddr = (uintptr_t) dst;
	enc.len = size;
	ret = sev_ioctl(vmfd, KVM_SEV_DBG_ENCRYPT, &enc, &fwerr);
	if (ret == -1) errx(1, "KVM_SEV_DBG_ENCRYPT: (%s) %s",
		strerror(errno), sev_fwerr_str(fwerr));
}

void
sev_debug_decrypt(int vmfd, void *src, void *dst, size_t size)
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
	struct kvm_sev_launch_update_data update;
	struct kvm_sev_launch_start start;
	struct kvm_userspace_memory_region region;
	struct kvm_sev_dbg dec;
	struct kvm_regs regs;
	struct kvm_sregs sregs;
	int ret, fwerr;
	void *buf;

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

	/* Enable SEV-ES for vm */
	ret = sev_ioctl(kvm->vmfd, KVM_SEV_ES_INIT, NULL, &fwerr);
	if (ret == -1) errx(1, "KVM_SEV_ES_INIT: (%s) %s",
		strerror(errno), sev_fwerr_str(fwerr));

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
	regs.rsp = kvm->memsize - 8;
	regs.rbp = kvm->memsize - 8;
	ret = ioctl(kvm->vcpufd, KVM_SET_REGS, &regs);
	if (ret == -1) err(1, "KVM_SET_REGS");

	/* Generate encryption keys and set policy */
	memset(&start, 0, sizeof(start));
	start.handle = 0;
	start.policy = 1 << 2; /* require ES */
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

	/* Validate code was encrypted correctly */
	buf = malloc(ramsize);
	dec.src_uaddr = (uint64_t) kvm->mem;
	dec.dst_uaddr = (uint64_t) buf;
	dec.len = ramsize;
	ret = sev_ioctl(kvm->vmfd, KVM_SEV_DBG_DECRYPT, &dec, &fwerr);
	if (ret == -1) errx(1, "KVM_SEV_DBG_DECRYPT: (%s) %s",
		strerror(errno), sev_fwerr_str(fwerr));
	if (memcmp(buf, code_start, code_stop - code_start))
		errx(1, "VM ram not encrypted correctly");
}

void
sev_snp_kvm_init(struct kvm *kvm, size_t ramsize,
	void *code_start, void *code_stop)
{
	errx(1, "Not implemented");
}

void
vm_init(struct kvm *kvm, size_t ramsize, void *code_start, void *code_end)
{
	if (!strcmp(vmtype, "kvm")) {
		kvm_init(kvm, ramsize, code_start, code_end);
	} else if (!strcmp(vmtype, "sev")) {
		sev_kvm_init(kvm, ramsize, code_start, code_end);
	} else if (!strcmp(vmtype, "sev-es")) {
		sev_es_kvm_init(kvm, ramsize, code_start, code_end);
	} else if (!strcmp(vmtype, "sev-snp")) {
		sev_snp_kvm_init(kvm, ramsize, code_start, code_end);
	} else {
		errx(1, "invalid version");
	}
}

void
vm_deinit(struct kvm *kvm)
{
	close(kvm->vmfd);
	close(kvm->vcpufd);
	munmap(kvm->mem, kvm->memsize);
}

void
print_counts(uint8_t *counts)
{
	int i;

	for (i = 0; i < 64; i++) {
		if (i % 16 == 0 && i)
			printf("\n");
		if (counts[i] == 1)
			printf("\x1b[38;5;88m");
		else if (counts[i] > 1)
			printf("\x1b[38;5;196m");
		printf("%2i ", i);
		if (counts[i] > 0)
			printf("\x1b[0m");
	}

	printf("\nTarget Set %i Count: %u\n\n",
		TARGET_SET, counts[TARGET_SET]);
}

void
collect(struct kvm *kvm, uint8_t *counts)
{
	struct kvm_regs regs;
	int ret;

	/* run vm twice, use count without initial stack setup */
	ret = ioctl(kvm->vcpufd, KVM_RUN, NULL);
	if (ret == -1) err(1, "KVM_RUN");

	if (kvm->run->exit_reason == KVM_EXIT_MMIO) {
		memset(&regs, 0, sizeof(regs));
		ret = ioctl(kvm->vcpufd, KVM_GET_REGS, &regs);
		if (ret == -1) err(1, "KVM_GET_REGS");
		errx(1, "Victim access OOB: %llu %08llx => %02X\n",
			kvm->run->mmio.phys_addr, regs.rip,
			((uint8_t *)kvm->mem)[regs.rip]);
	} else if (kvm->run->exit_reason != KVM_EXIT_HYPERCALL) {
		errx(1, "KVM died: %i\n", kvm->run->exit_reason);
	}

	ret = ioctl(kvm_dev, KVM_CPC_READ_COUNTS, counts);
	if (ret == -1) err(1, "ioctl KVM_CPC_READ_COUNTS");
}

int
main(int argc, const char **argv)
{
	struct kvm vms[2];
	uint8_t counts[2][SAMPLE_COUNT][L1_SETS];
	uint8_t baseline[L1_SETS];
	int i, k, ret;

	vmtype = "kvm";
	if (argc > 1) vmtype = argv[1];
	if (strcmp(vmtype, "kvm") && strcmp(vmtype, "sev")
			&& strcmp(vmtype, "sev-es")
			&& strcmp(vmtype, "sev-snp"))
		errx(1, "invalid vm mode: %s", vmtype);

	setvbuf(stdout, NULL, _IONBF, 0);

	pin_process(0, TARGET_CORE, true);

	kvm_dev = open("/dev/kvm", O_RDWR | O_CLOEXEC);
	if (kvm_dev < 0) err(1, "open /dev/kvm");

	sev_dev = open("/dev/sev", O_RDWR | O_CLOEXEC);
	if (sev_dev < 0) err(1, "open /dev/sev");

	/* Make sure we have the stable version of the API */
	ret = ioctl(kvm_dev, KVM_GET_API_VERSION, NULL);
	if (ret == -1) err(1, "KVM_GET_API_VERSION");
	if (ret != 12) errx(1, "KVM_GET_API_VERSION %d, expected 12", ret);

	/* Reset kernel module state */
	ret = ioctl(kvm_dev, KVM_CPC_RESET);
	if (ret == -1) err(1, "ioctl KVM_CPC_RESET");

	vm_init(&vms[WITH], 2 * L1_SIZE,
		start_guest_with, stop_guest_with);
	vm_init(&vms[WITHOUT], 2 * L1_SIZE,
		start_guest_without, stop_guest_without);

	for (i = 0; i < SAMPLE_COUNT; i++) {
		collect(&vms[WITH], counts[WITH][i]);
		collect(&vms[WITHOUT], counts[WITHOUT][i]);
	}

	memset(baseline, 0xff, L1_SETS);
	for (i = 0; i < SAMPLE_COUNT; i++) {
		for (k = 0; k < L1_SETS; k++) {
			if (counts[WITH][i][k] < baseline[k])
				baseline[k] = counts[WITH][i][k];
			if (counts[WITHOUT][i][k] < baseline[k])
				baseline[k] = counts[WITHOUT][i][k];
		}
	}

	for (i = 0; i < SAMPLE_COUNT; i++) {
		for (k = 0; k < L1_SETS; k++) {
			counts[WITH][i][k] -= baseline[k];
			counts[WITHOUT][i][k] -= baseline[k];
		}

		printf("=== Sample %2i ===\n\n", i);

		printf("With eviction:\n");
		print_counts(counts[WITH][i]);

		printf("Without eviction:\n");
		print_counts(counts[WITHOUT][i]);
	}

	for (i = 0; i < SAMPLE_COUNT; i++) {
		for (k = 0; k < L1_SETS; k++) {
			if (counts[WITH][i][k] + baseline[k] >= L1_ASSOC)
				warnx("sample %i: With count OOB for set %i (=%i)",
					i, k, counts[WITH][i][k] + baseline[k]);

			if (counts[WITHOUT][i][k] + baseline[k] >= L1_ASSOC)
				warnx("sample %i: Without count OOB for set %i (=%i)",
					i, k, counts[WITHOUT][i][k] + baseline[k]);
		}

		if (!counts[WITH][i][TARGET_SET])
			warnx("sample %i: Missing eviction in target set %i (=%i,%i)",
				i, TARGET_SET, counts[WITH][i][TARGET_SET],
				counts[WITH][i][TARGET_SET] + baseline[i]);
	}

	vm_deinit(&vms[WITH]);
	vm_deinit(&vms[WITHOUT]);

	close(kvm_dev);
	close(sev_dev);
}

