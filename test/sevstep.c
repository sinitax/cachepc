#define _GNU_SOURCE

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

#define TARGET_CORE 2
#define SECONDARY_CORE 3

#define TARGET_SET 15

struct kvm {
	int vmfd, vcpufd;
	void *mem;
	size_t memsize;
	struct kvm_run *run;
};

/* start and end for guest assembly */
extern uint8_t __start_guest_with[];
extern uint8_t __stop_guest_with[];

/* ioctl dev fds */
static int kvm_dev, sev_dev, kvm_dev;
static int faultcnt;

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

__attribute__((section("guest_with"))) void
vm_guest_with(void)
{
	while (1) {
		asm volatile("mov (%0), %%eax" : :
			"r" (L1_LINESIZE * (L1_SETS * 3 + TARGET_SET)) : "rax");
	}
}

bool
pin_process(pid_t pid, int cpu, bool assert)
{
	cpu_set_t cpuset;
	int ret;

	CPU_ZERO(&cpuset);
	CPU_SET(cpu, &cpuset);
	ret = sched_setaffinity(pid, sizeof(cpu_set_t), &cpuset);
	if (ret < 0) {
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

uint8_t * 
sev_get_measure(int vmfd)
{
	struct kvm_sev_launch_measure msrmt;
	int ret, fwerr;
	uint8_t *data;

	memset(&msrmt, 0, sizeof(msrmt));
	ret = sev_ioctl(vmfd, KVM_SEV_LAUNCH_MEASURE, &msrmt, &fwerr);
	if (ret < 0 && fwerr != SEV_RET_INVALID_LEN) {
		errx(1, "LAUNCH_MEASURE: (%s) %s",
			strerror(errno), sev_fwerr_str(fwerr));
	}

	data = malloc(msrmt.len);
	msrmt.uaddr = (uintptr_t) data;

	ret = sev_ioctl(vmfd, KVM_SEV_LAUNCH_MEASURE, &msrmt, &fwerr);
	if (ret < 0) {
		errx(1, "LAUNCH_MEASURE: (%s) %s",
			strerror(errno), sev_fwerr_str(fwerr));
	}

	return data;
}

uint8_t
sev_guest_state(int vmfd, uint32_t handle)
{
	struct kvm_sev_guest_status status;
	int ret, fwerr;

	status.handle = handle;
	ret = sev_ioctl(vmfd, KVM_SEV_GUEST_STATUS, &status, &fwerr);
	if (ret < 0) {
		errx(1, "KVM_SEV_GUEST_STATUS: (%s) %s",
			strerror(errno), sev_fwerr_str(fwerr));
	}

	return status.state;
}

void
sev_dbg_encrypt(int vmfd, void *dst, void *src, size_t size)
{
	struct kvm_sev_dbg enc;
	int ret, fwerr;

	memset(&enc, 0, sizeof(struct kvm_sev_dbg));
	enc.src_uaddr = (uintptr_t) src;
	enc.dst_uaddr = (uintptr_t) dst;
	enc.len = size;

	ret = sev_ioctl(vmfd, KVM_SEV_DBG_ENCRYPT, &enc, &fwerr);
	if (ret < 0) errx(1, "KVM_SEV_DBG_ENCRYPT: (%s) %s",
		strerror(errno), sev_fwerr_str(fwerr));
}

void
sev_dbg_decrypt(int vmfd, void *dst, void *src, size_t size)
{
	struct kvm_sev_dbg enc;
	int ret, fwerr;

	memset(&enc, 0, sizeof(struct kvm_sev_dbg));
	enc.src_uaddr = (uintptr_t) src;
	enc.dst_uaddr = (uintptr_t) dst;
	enc.len = size;

	ret = sev_ioctl(vmfd, KVM_SEV_DBG_DECRYPT, &enc, &fwerr);
	if (ret < 0) errx(1, "KVM_SEV_DBG_DECRYPT: (%s) %s",
		strerror(errno), sev_fwerr_str(fwerr));
}

uint64_t
sev_dbg_rip(int vmfd)
{
	void *vmsa;
	uint64_t rip;
	int ret;

	vmsa = NULL;
	if (posix_memalign(&vmsa, PAGE_SIZE, PAGE_SIZE))
		err(1, "memalign");
	memset(vmsa, 0, PAGE_SIZE);

	ret = ioctl(kvm_dev, KVM_CPC_VMSA_READ, vmsa);
	if (ret == -1) err(1, "ioctl VMSA_READ");

	sev_dbg_decrypt(vmfd, vmsa, CPC_VMSA_MAGIC_ADDR, PAGE_SIZE);
	// hexdump(vmsa, PAGE_SIZE);

	rip = *(uint64_t *)(vmsa + 0x178);

	free(vmsa);

	return rip;
}

void
sev_kvm_init(struct kvm *kvm, size_t ramsize, void *code_start, void *code_stop)
{
	// REF: https://www.amd.com/system/files/TechDocs/55766_SEV-KM_API_Specification.pdf
	struct kvm_sev_launch_update_data update;
	struct kvm_sev_launch_start start;
	struct kvm_userspace_memory_region region;
	struct kvm_regs regs;
	struct kvm_sregs sregs;
	uint8_t *msrmt;
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
	if (ret < 0) err(1, "KVM_SET_USER_MEMORY_REGION");

	/* Enable SEV for vm */
	ret = sev_ioctl(kvm->vmfd, KVM_SEV_ES_INIT, NULL, &fwerr);
	if (ret < 0) errx(1, "KVM_SEV_ES_INIT: (%s) %s",
		strerror(errno), sev_fwerr_str(fwerr));

	/* Create virtual cpu */
	kvm->vcpufd = ioctl(kvm->vmfd, KVM_CREATE_VCPU, 0);
	if (kvm->vcpufd < 0) err(1, "KVM_CREATE_VCPU");

	/* Map the shared kvm_run structure and following data */
	ret = ioctl(kvm_dev, KVM_GET_VCPU_MMAP_SIZE, NULL);
	if (ret < 0) err(1, "KVM_GET_VCPU_MMAP_SIZE");
	if (ret < sizeof(struct kvm_run))
		errx(1, "KVM_GET_VCPU_MMAP_SIZE too small");
	kvm->run = mmap(NULL, ret, PROT_READ | PROT_WRITE,
		MAP_SHARED, kvm->vcpufd, 0);
	if (!kvm->run) err(1, "mmap vcpu");

	/* Initialize segment regs */
	memset(&sregs, 0, sizeof(sregs));
	ret = ioctl(kvm->vcpufd, KVM_GET_SREGS, &sregs);
	if (ret < 0) err(1, "KVM_GET_SREGS");
	sregs.cs.base = 0;
	sregs.cs.selector = 0;
	ret = ioctl(kvm->vcpufd, KVM_SET_SREGS, &sregs);
	if (ret < 0) err(1, "KVM_SET_SREGS");

	/* Initialize rest of registers */
	memset(&regs, 0, sizeof(regs));
	regs.rip = 0;
	regs.rsp = kvm->memsize - L1_SETS * L1_LINESIZE - 8;
	regs.rbp = kvm->memsize - L1_SETS * L1_LINESIZE - 8;
	ret = ioctl(kvm->vcpufd, KVM_SET_REGS, &regs);
	if (ret < 0) err(1, "KVM_SET_REGS");

	/* Generate encryption keys and set policy */
	memset(&start, 0, sizeof(start));
	start.handle = 0;
	// start.policy = 1 << 0; /* disallow debug */
	start.policy = 1 << 2; /* require ES */
	ret = sev_ioctl(kvm->vmfd, KVM_SEV_LAUNCH_START, &start, &fwerr);
	if (ret < 0) errx(1, "KVM_SEV_LAUNCH_START: (%s) %s",
		strerror(errno), sev_fwerr_str(fwerr));

	/* Prepare the vm memory (by encrypting it) */
	memset(&update, 0, sizeof(update));
	update.uaddr = (uintptr_t) kvm->mem;
	update.len = ramsize;
	ret = sev_ioctl(kvm->vmfd, KVM_SEV_LAUNCH_UPDATE_DATA, &update, &fwerr);
	if (ret < 0) errx(1, "KVM_SEV_LAUNCH_UPDATE_DATA: (%s) %s",
		strerror(errno), sev_fwerr_str(fwerr));

	/* Prepare the vm save area */
	ret = sev_ioctl(kvm->vmfd, KVM_SEV_LAUNCH_UPDATE_VMSA, NULL, &fwerr);
	if (ret < 0) errx(1, "KVM_SEV_LAUNCH_UPDATE_VMSA: (%s) %s",
		strerror(errno), sev_fwerr_str(fwerr));

	/* Collect a measurement (necessary) */
	msrmt = sev_get_measure(kvm->vmfd);
	free(msrmt);

	/* Finalize launch process */
	ret = sev_ioctl(kvm->vmfd, KVM_SEV_LAUNCH_FINISH, 0, &fwerr);
	if (ret < 0) errx(1, "KVM_SEV_LAUNCH_FINISH: (%s) %s",
		strerror(errno), sev_fwerr_str(fwerr));
	ret = sev_guest_state(kvm->vmfd, start.handle);
	if (ret != GSTATE_RUNNING)
		errx(1, "Bad guest state: %s", sev_gstate_str(fwerr));
}

void
sev_kvm_deinit(struct kvm *kvm)
{
	close(kvm->vmfd);
	close(kvm->vcpufd);
	munmap(kvm->mem, kvm->memsize);
}

cpc_msrmt_t *
read_counts()
{
	cpc_msrmt_t *counts;
	int i, ret;

	counts = malloc(L1_SETS * sizeof(cpc_msrmt_t));
	if (!counts) err(1, "malloc");

	ret = ioctl(kvm_dev, KVM_CPC_READ_COUNTS, counts);
	if (ret == -1) err(1, "ioctl READ_COUNTS");

	for (i = 0; i < L1_SETS; i++) {
		if (counts[i] > 8)
			errx(1, "Invalid counts set %i", i);
	}	

	return counts;
}

void
print_counts(cpc_msrmt_t *counts)
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
	printf("\n");
}

void
print_counts_raw(cpc_msrmt_t *counts)
{
	int i;

	for (i = 0; i < 64; i++) {
		if (i % 16 == 0 && i)
			printf("\n");
		if (counts[i] == 1)
			printf("\x1b[38;5;88m");
		else if (counts[i] > 1)
			printf("\x1b[38;5;196m");
		printf("%02X ", (uint8_t) counts[i]);
		if (counts[i] > 0)
			printf("\x1b[0m");
	}
	printf("\n");
}

void
runonce(struct kvm *kvm)
{
	int ret;

	ret = ioctl(kvm->vcpufd, KVM_RUN, NULL);
	if (ret < 0) err(1, "KVM_RUN");
}

int
monitor(struct kvm *kvm, bool baseline)
{
	struct cpc_track_event event;
	cpc_msrmt_t counts[64];
	uint64_t rip;
	int ret, i;

	/* Get page fault info */
	ret = ioctl(kvm_dev, KVM_CPC_POLL_EVENT, &event);
	if (!ret) {
		if (!baseline) {
			rip = sev_dbg_rip(kvm->vmfd);
			printf("Event: inst:%llu data:%llu retired:%llu rip:%lu\n",
				event.inst_fault_gfn, event.data_fault_gfn,
				event.retinst, rip);
		}
		faultcnt++;

		ret = ioctl(kvm_dev, KVM_CPC_READ_COUNTS, counts);
		if (ret == -1) err(1, "ioctl READ_COUNTS");

		if (!baseline) {
			print_counts(counts);
			printf("\n");
		}

		for (i = 0; i < 64; i++) {
			if (counts[i] > 8) {
				errx(1, "Invalid count for set %i (%llu)",
					i, counts[i]);
			}
		}

		ret = ioctl(kvm_dev, KVM_CPC_ACK_EVENT, &event.id);
		if (ret == -1) err(1, "ioctl ACK_EVENT");
	} else if (errno != EAGAIN) {
		perror("ioctl POLL_EVENT");
		return 1;
	}

	return 0;
}

int
main(int argc, const char **argv)
{
	struct kvm kvm_with_access;
	uint64_t track_mode;
	pid_t ppid, pid;
	uint32_t arg;
	struct cpc_track_event event;
	cpc_msrmt_t baseline[64];
	int ret, i;

	setvbuf(stdout, NULL, _IONBF, 0);

	pin_process(0, TARGET_CORE, true);

	sev_dev = open("/dev/sev", O_RDWR | O_CLOEXEC);
	if (sev_dev < 0) err(1, "open /dev/sev");

	kvm_dev = open("/dev/kvm", O_RDWR | O_CLOEXEC);
	if (kvm_dev < 0) err(1, "open /dev/kvm");

	/* Make sure we have the stable version of the API */
	ret = ioctl(kvm_dev, KVM_GET_API_VERSION, NULL);
	if (ret < 0) err(1, "KVM_GET_API_VERSION");
	if (ret != 12) errx(1, "KVM_GET_API_VERSION %d, expected 12", ret);

	/* Setup needed performance counters */
	ret = ioctl(kvm_dev, KVM_CPC_SETUP_PMC, NULL);
	if (ret < 0) err(1, "ioctl SETUP_PMC");

	sev_kvm_init(&kvm_with_access, L1_SIZE * 2,
		__start_guest_with, __stop_guest_with);

	/* Page tracking init needs to happen after kvm
	 * init so main_kvm is set.. */

	/* Reset previous tracking */
	ret = ioctl(kvm_dev, KVM_CPC_RESET_TRACKING, NULL);
	if (ret == -1) err(1, "ioctl RESET_TRACKING");

	/* Do data access stepping */
	arg = CPC_TRACK_DATA_ACCESS;
	ret = ioctl(kvm_dev, KVM_CPC_TRACK_MODE, &arg);
	if (ret == -1) err(1, "ioctl TRACK_MODE");

	/* Init page tracking */
	track_mode = KVM_PAGE_TRACK_ACCESS;
	ret = ioctl(kvm_dev, KVM_CPC_TRACK_ALL, &track_mode);
	if (ret == -1) err(1, "ioctl TRACK_ALL");

	ppid = getpid();
	if ((pid = fork())) {
		if (pid < 0) err(1, "fork");

		sleep(1); /* give time for child to pin other core */

		printf("VMRUN\n");
		runonce(&kvm_with_access);
		printf("VMRUN DONE\n");
	} else {
		pin_process(0, SECONDARY_CORE, true);
		printf("PINNED\n");

		arg = true;
		ret = ioctl(kvm_dev, KVM_CPC_MEASURE_BASELINE, &arg);
		if (ret == -1) err(1, "ioctl MEASURE_BASELINE");

		faultcnt = 0;
		while (faultcnt < 30) {
			if (monitor(&kvm_with_access, true)) break;
		}

		do {
			ret = ioctl(kvm_dev, KVM_CPC_POLL_EVENT, &event);
			if (ret == -1 && errno != EAGAIN)
				err(1, "ioctl POLL_EVENT");
		} while (ret == -1 && errno == EAGAIN);

		arg = false;
		ret = ioctl(kvm_dev, KVM_CPC_MEASURE_BASELINE, &arg);
		if (ret == -1) err(1, "ioctl MEASURE_BASELINE");

		ret = ioctl(kvm_dev, KVM_CPC_READ_BASELINE, baseline);
		if (ret == -1) err(1, "ioctl READ_BASELINE");

		printf("\n>>> BASELINE:\n");
		print_counts(baseline);
		printf("\n");
		print_counts_raw(baseline);
		printf("\n");

		/* Check baseline for saturated sets */
		for (i = 0; i < 64; i++) {
			if (baseline[i] >= 8)
				errx(1, "!!! Baseline set %i full\n", i);
		}

		arg = true;
		ret = ioctl(kvm_dev, KVM_CPC_SUB_BASELINE, &arg);
		if (ret == -1) err(1, "ioctl SUB_BASELINE");

		ret = ioctl(kvm_dev, KVM_CPC_ACK_EVENT, &event.id);
		if (ret == -1) err(1, "ioctl ACK_EVENT");

		faultcnt = 0;
		while (faultcnt < 30) {
			if (monitor(&kvm_with_access, false)) break;
		}

		kill(ppid, SIGTERM);
		exit(0);
	}

	sev_kvm_deinit(&kvm_with_access);
	
	close(kvm_dev);
	close(sev_dev);
}

