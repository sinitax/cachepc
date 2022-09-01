/* for CPU_ZERO macros.. */
#define _GNU_SOURCE

#include "cachepc_user.h"

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

#define SAMPLE_COUNT 100

#define TARGET_CORE 2
#define SECONDARY_CORE 3

#define TARGET_CACHE_LINESIZE 64
#define TARGET_SET 15

struct kvm {
	int fd, vmfd, vcpufd;
	void *mem;
	size_t memsize;
	struct kvm_run *run;
};

/* start and end for guest assembly */
extern uint8_t __start_guest_with[];
extern uint8_t __stop_guest_with[];
extern uint8_t __start_guest_without[];
extern uint8_t __stop_guest_without[];

bool ready = false;
bool processed = false;

ssize_t sysret;
pid_t victim_pid;

/* ioctl dev fds */
int kvm_dev, sev_dev, cachepc_dev;

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

// REF: https://events19.linuxfoundation.org/wp-content/uploads/2017/12/Extending-Secure-Encrypted-Virtualization-with-SEV-ES-Thomas-Lendacky-AMD.pdf
// REF: https://www.spinics.net/lists/linux-kselftest/msg27206.html
__attribute__((section("guest_with"))) void
vm_guest_with(void)
{
	while (1) {
		asm volatile("mov (%[v]), %%bl"
			: : [v] "r" (TARGET_CACHE_LINESIZE * TARGET_SET));
		asm volatile("out %%al, (%%dx)" : : );
		//asm volatile("hlt"); 
		//asm volatile("rep; vmmcall\n\r");
	}
}

__attribute__((section("guest_without"))) void
vm_guest_without(void)
{
	while (1) {
		//asm volatile("hlt");
		asm volatile("out %%al, (%%dx)" : : );
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
	if (ret < 0 && fwerr != SEV_RET_INVALID_LEN)
		errx(1, "LAUNCH_MEASURE: (%s) %s", strerror(errno), sev_fwerr_str(fwerr));

	data = malloc(msrmt.len);
	msrmt.uaddr = (uintptr_t) data;

	ret = sev_ioctl(vmfd, KVM_SEV_LAUNCH_MEASURE, &msrmt, &fwerr);
	if (ret < 0)
		errx(1, "LAUNCH_MEASURE: (%s) %s", strerror(errno), sev_fwerr_str(fwerr));

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
sev_debug_encrypt(int vmfd, void *src, void *dst, size_t size)
{
	struct kvm_sev_dbg enc;
	int ret, fwerr;

	enc.src_uaddr = (uintptr_t) src;
	enc.dst_uaddr = (uintptr_t) dst;
	enc.len = size;
	ret = sev_ioctl(vmfd, KVM_SEV_DBG_ENCRYPT, &enc, &fwerr);
	if (ret < 0) errx(1, "KVM_SEV_DBG_ENCRYPT: (%s) %s",
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
	if (ret < 0) errx(1, "KVM_SEV_DBG_DECRYPT: (%s) %s",
		strerror(errno), sev_fwerr_str(fwerr));
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
	region.guest_phys_addr = 0x0000;
	region.userspace_addr = (uintptr_t) kvm->mem;
	ret = ioctl(kvm->vmfd, KVM_SET_USER_MEMORY_REGION, &region);
	if (ret < 0) err(1, "KVM_SET_USER_MEMORY_REGION");

	/* Enable SEV for vm */
	ret = sev_ioctl(kvm->vmfd, KVM_SEV_INIT, NULL, &fwerr);
	if (ret < 0) errx(1, "KVM_SEV_INIT: (%s) %s",
		strerror(errno), sev_fwerr_str(fwerr));

	/* Generate encryption keys and set policy */
	memset(&start, 0, sizeof(start));
	start.handle = 0;
	start.policy = 0;
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
		
	/* Create virtual cpu core */
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
	regs.rip = 0x0;
	regs.rsp = kvm->memsize - 1;
	regs.rbp = kvm->memsize - 1;
	regs.rax = 0;
	regs.rdx = 0;
	regs.rflags = 0x2;
	ret = ioctl(kvm->vcpufd, KVM_SET_REGS, &regs);
	if (ret < 0) err(1, "KVM_SET_REGS");
}

void
sev_kvm_deinit(struct kvm *kvm)
{
	close(kvm->vmfd);
	close(kvm->vcpufd);
	munmap(kvm->mem, kvm->memsize);
}

uint16_t *
read_counts() 
{
	uint16_t *counts;
	size_t len;

	counts = malloc(64 * sizeof(uint16_t));
	lseek(cachepc_dev, 0, SEEK_SET);
	len = read(cachepc_dev, counts, 64 * sizeof(uint16_t));
	assert(len == 64 * sizeof(uint16_t));

	return counts;
}

void
print_counts(uint16_t *counts)
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
	printf("\n Target Set %i Count: %hu\n", TARGET_SET, counts[TARGET_SET]);
	printf("\n");
}

uint16_t *
collect(const char *prefix, void *code_start, void *code_stop)
{
	struct kvm_regs regs;
	struct kvm kvm;
	uint16_t *counts;
	int ret;

	sev_kvm_init(&kvm, 64 * 64 * 8 * 2, code_start, code_stop);

	/* run vm twice, use count without initial stack setup */
	ret = ioctl(kvm.vcpufd, KVM_RUN, NULL);
	ret = ioctl(kvm.vcpufd, KVM_RUN, NULL);
	if (ret < 0) err(1, "KVM_RUN");

	if (kvm.run->exit_reason == KVM_EXIT_MMIO) {
		memset(&regs, 0, sizeof(regs));
		ret = ioctl(kvm.vcpufd, KVM_GET_REGS, &regs);
		if (ret < 0) err(1, "KVM_GET_REGS");
		errx(1, "Victim access OOB: %llu %08llx => %02X\n",
			kvm.run->mmio.phys_addr, regs.rip,
			((uint8_t *)kvm.mem)[regs.rip]);
	} else if (kvm.run->exit_reason != KVM_EXIT_IO) {
		errx(1, "KVM died: %i\n", kvm.run->exit_reason);
	}

	counts = read_counts();

	sev_kvm_deinit(&kvm);

	return counts;
}

int
main(int argc, const char **argv)
{
	uint16_t without_access[SAMPLE_COUNT][64];
	uint16_t with_access[SAMPLE_COUNT][64];
	uint16_t *counts, *baseline;
	uint32_t arg;
	int i, k, ret;
	
	setvbuf(stdout, NULL, _IONBF, 0);

	pin_process(0, TARGET_CORE, true);

	cachepc_dev = open("/proc/cachepc", O_RDONLY);
	if (cachepc_dev < 0) err(1, "open /proc/cachepc");

	sev_dev = open("/dev/sev", O_RDWR | O_CLOEXEC);
	if (sev_dev < 0) err(1, "open /dev/sev");

	kvm_dev = open("/dev/kvm", O_RDWR | O_CLOEXEC);
	if (kvm_dev < 0) err(1, "open /dev/kvm");

	/* Make sure we have the stable version of the API */
	ret = ioctl(kvm_dev, KVM_GET_API_VERSION, NULL);
	if (ret < 0) err(1, "KVM_GET_API_VERSION");
	if (ret != 12) errx(1, "KVM_GET_API_VERSION %d, expected 12", ret);

	// Init L1 miss counter
	arg = 0x000064D8;
	ret = ioctl(cachepc_dev, CACHEPC_IOCTL_INIT_PMC, &arg);
	if (ret < 0) err(1, "ioctl fail");

	baseline = calloc(sizeof(uint16_t), 64);
	if (!baseline) err(1, "counts");
	for (k = 0; k < 64; k++)
		baseline[k] = UINT16_MAX;

	for (i = 0; i < SAMPLE_COUNT; i++) {
		counts = collect("without", __start_guest_without, __stop_guest_without);
		memcpy(without_access[i], counts, 64 * sizeof(uint16_t));
		free(counts);

		counts = collect("with", __start_guest_with, __stop_guest_with);
		memcpy(with_access[i], counts, 64 * sizeof(uint16_t));
		free(counts);

		for (k = 0; k < 64; k++) {
			baseline[k] = MIN(baseline[k], without_access[i][k]);
			baseline[k] = MIN(baseline[k], with_access[i][k]);
		}
	}
	
	for (i = 0; i < SAMPLE_COUNT; i++) {
		for (k = 0; k < 64; k++) {
			with_access[i][k] -= baseline[k];
			without_access[i][k] -= baseline[k];
		}

		printf("Evictions with access:\n");
		print_counts(with_access[i]);

		printf("Evictions without access:\n");
		print_counts(without_access[i]);
	}

	for (i = 0; i < SAMPLE_COUNT; i++) {
		assert(with_access[i][TARGET_SET] > 0);
		//assert(without_access[i][TARGET_SET] == 0);
	}

	free(baseline);

	close(cachepc_dev);
	close(kvm_dev);
	close(sev_dev);
}

