/* for CPU_ZERO macros.. */
#define _GNU_SOURCE

#include "cachepc_user.h"

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

struct kvm {
	int fd;
	int vmfd;
	int vcpufd;
	void *mem;
};

/* start and end for guest assembly */
extern uint8_t __start_guest_with[];
extern uint8_t __stop_guest_with[];
extern uint8_t __start_guest_without[];
extern uint8_t __stop_guest_without[];

static bool ready = false;
static bool processed = false;

static ssize_t sysret;
static pid_t victim_pid;

static struct kvm kvm;
static struct kvm_run *kvm_run;

static int cachepc_fd;

#define TARGET_CACHE_LINESIZE 64
#define TARGET_SET 15

__attribute__((section("guest_with"))) void
vm_guest_with(void)
{
	while (1) {
		asm volatile("mov (%[v]), %%bl"
			: : [v] "r" (TARGET_CACHE_LINESIZE * TARGET_SET));
		asm volatile("out %%al, (%%dx)" : : );
	}
}

__attribute__((section("guest_without"))) void
vm_guest_without(void)
{
	while (1) {
		asm volatile("out %%al, (%%dx)" : : );
	}
}

bool
pin_process(pid_t pid, int cpu, bool assert)
{
	cpu_set_t cpuset;
	int status;

	CPU_ZERO(&cpuset);
	CPU_SET(cpu, &cpuset);
	status = sched_setaffinity(pid, sizeof(cpu_set_t), &cpuset);
	if (status < 0) {
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

void
clear_cores(uint64_t cpu_mask)
{
	DIR *proc_dir, *task_dir;
	struct dirent *proc_ent, *task_ent;
	char taskpath[256];
	pid_t pid, tid;
	bool res;
	int cpu;

	/* move all processes from the target cpu to secondary */

	proc_dir = opendir("/proc");
	if (!proc_dir) err(1, "opendir");

	while ((proc_ent = readdir(proc_dir))) {
		pid = atoi(proc_ent->d_name);
		if (!pid) continue;

		cpu = read_stat_core(pid);
		if (cpu >= 0 && (1 << cpu) & cpu_mask) {
			res = pin_process(pid, SECONDARY_CORE, false);
			// if (!res) printf("Failed pin %i from %i\n", pid, cpu);
			if (res) printf("Pinned %i from %i\n", tid, cpu);
			continue;
		}

		snprintf(taskpath, sizeof(taskpath), "/proc/%u/task", pid);
		task_dir = opendir(taskpath);
		if (!task_dir) err(1, "opendir");

		while ((task_ent = readdir(task_dir))) {
			tid = atoi(task_ent->d_name);
			if (!tid || tid == pid) continue;

			cpu = read_stat_core(tid);
			if (cpu >= 0 && (1 << cpu) & cpu_mask) {
				res = pin_process(tid, SECONDARY_CORE, false);
				//if (!res) printf("Failed pin %i from %i\n", tid, cpu);
				if (res) printf("Pinned thread %i from %i\n", tid, cpu);
			}
		}

		closedir(task_dir);
	}

	closedir(proc_dir);
}

void
kvm_init(size_t ramsize, void *code_start, void *code_stop)
{
	struct kvm_userspace_memory_region region;
	struct kvm_regs regs;
	struct kvm_sregs sregs;
	int ret;

	kvm.fd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
	if (kvm.fd < 0) err(1, "/dev/kvm");

	/* Make sure we have the stable version of the API */
	ret = ioctl(kvm.fd, KVM_GET_API_VERSION, NULL);
	if (ret == -1) err(1, "KVM_GET_API_VERSION");
	if (ret != 12) errx(1, "KVM_GET_API_VERSION %d, expected 12", ret);

	kvm.vmfd = ioctl(kvm.fd, KVM_CREATE_VM, 0);
	if (kvm.vmfd < 0) err(1, "KVM_CREATE_VM");

	/* Allocate one aligned page of guest memory to hold the code. */
	kvm.mem = mmap(NULL, ramsize, PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (!kvm.mem) err(1, "allocating guest memory");
	assert(code_stop - code_start <= ramsize);
	memcpy(kvm.mem, code_start, code_stop - code_start);

	/* Map it into vm memory */
	memset(&region, 0, sizeof(region));
	region.slot = 0;
	region.memory_size = ramsize;
	region.guest_phys_addr = 0x0000;
	region.userspace_addr = (uint64_t) kvm.mem;

	ret = ioctl(kvm.vmfd, KVM_SET_USER_MEMORY_REGION, &region);
	if (ret < 0) err(1, "KVM_SET_USER_MEMORY_REGION");

	kvm.vcpufd = ioctl(kvm.vmfd, KVM_CREATE_VCPU, 0);
	if (kvm.vcpufd < 0) err(1, "KVM_CREATE_VCPU");

	/* Map the shared kvm_run structure and following data. */
	ret = ioctl(kvm.fd, KVM_GET_VCPU_MMAP_SIZE, NULL);
	if (ret < 0) err(1, "KVM_GET_VCPU_MMAP_SIZE");

	if (ret < sizeof(struct kvm_run))
		errx(1, "KVM_GET_VCPU_MMAP_SIZE too small");
	kvm_run = mmap(NULL, ret, PROT_READ | PROT_WRITE,
		MAP_SHARED, kvm.vcpufd, 0);
	if (!kvm_run) err(1, "mmap vcpu");

	/* Initialize CS to point at 0, via a read-modify-write of sregs. */
	memset(&sregs, 0, sizeof(sregs));
	ret = ioctl(kvm.vcpufd, KVM_GET_SREGS, &sregs);
	if (ret < 0) err(1, "KVM_GET_SREGS");
	sregs.cs.base = 0;
	sregs.cs.selector = 0;
	ret = ioctl(kvm.vcpufd, KVM_SET_SREGS, &sregs);
	if (ret < 0) err(1, "KVM_SET_SREGS");

	/* Initialize registers: instruction pointer for our code, addends, and
	 * initial flags required by x86 architecture. */
	memset(&regs, 0, sizeof(regs));
	regs.rip = 0x0;
	regs.rsp = ramsize - 1;
	regs.rbp = ramsize - 1;
	regs.rax = 0;
	regs.rdx = 0;
	regs.rflags = 0x2;
	ret = ioctl(kvm.vcpufd, KVM_SET_REGS, &regs);
	if (ret < 0) err(1, "KVM_SET_REGS");
}


int kvm_vm_ioctl(int vmfd, int type, ...)
{
    int ret;
    void *arg;
    va_list ap;

    va_start(ap, type);
    arg = va_arg(ap, void *);
    va_end(ap);

    
    ret = ioctl(vmfd, type, arg);
    if (ret == -1) {
        ret = -errno;
    }
    return ret;
}


//VU: Copied the below function from qemu, 
//e.g. https://github.dev/OpenChannelSSD/qemu-nvme/blob/master/target/i386/sev.c
//SEe also here: https://www.kernel.org/doc/Documentation/virt/kvm/amd-memory-encryption.rst
//"The The main ioctl to access SEV is KVM_MEMORY_ENCRYPT_OP. "
//If non-NULL, the argument to KVM_MEMORY_ENCRYPT_OP must be a struct kvm_sev_cmd::
/*
       struct kvm_sev_cmd {
               __u32 id;
               __u64 data;
               __u32 error;
               __u32 sev_fd;
       };


The ``id`` field contains the subcommand, and the ``data`` field points to
another struct containing arguments specific to command.  The ``sev_fd``
should point to a file descriptor that is opened on the ``/dev/sev``
device, if needed (see individual commands).
*/
static int
sev_ioctl(int fd, int cmd, void *data, int *error)
{
    int r;
    struct kvm_sev_cmd input;

    memset(&input, 0x0, sizeof(input));

    input.id = cmd;
    input.sev_fd = fd;
    input.data = (__u64)(unsigned long)data;

    r = kvm_vm_ioctl(kvm.vmfd, KVM_MEMORY_ENCRYPT_OP, &input);

    if (error) {
        *error = input.error;
    }

    return r;
}

void
kvm_svm_init(size_t ramsize, void *code_start, void *code_stop)
{
	//https://www.amd.com/system/files/TechDocs/55766_SEV-KM_API_Specification.pdf
	//
	int sev_fd;
	int fw_error;
	int status;
	struct kvm_regs regs;
	uint16_t *counts;
	int ret, r;

	/* using cache size for alignment of kvm memory access */
	kvm_init(64 * 64 * 8 * 2, code_start, code_stop);

	ret = 0;
	kvm_run->exit_reason = 0;
	sev_fd = open("/dev/sev", O_RDWR | O_CLOEXEC);
	if (sev_fd < 0) err(1, "/dev/sev");
	//kvm.fd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
	//if (kvm.fd < 0) err(1, "/dev/kvm");
	///kvm.vmfd = ioctl(kvm.fd, KVM_CREATE_VM, 0);
	//if (kvm.vmfd < 0) err(1, "KVM_CREATE_VM");
	//int r = ioctl(kvm.fd, KVM_GET_API_VERSION, NULL); //sev_ioctl(sev_fd, NULL, NULL, &fw_error);
	//if (r == -1) err(1, "KVM_GET_API_VERSION");
	//if (r != 12) errx(1, "KVM_GET_API_VERSION %d, expected 12", r);
	//printf("KVM API Version %d\n", r);
	r = ioctl(kvm.vmfd, KVM_MEMORY_ENCRYPT_OP, NULL); //sev_ioctl(sev_fd, NULL, NULL, &fw_error);
	printf("SEV ioctol %d \n",r);
	printf("fw_error %d \n", fw_error);
	if (r < 0) err(1,"SEV ioctol does not seem to be enabled");
	r = sev_ioctl(sev_fd,KVM_SEV_INIT, NULL, &fw_error); //sev_ioctl(sev_fd, NULL, NULL, &fw_error);
	printf("SEV ioctol %d \n",r);
	printf("fw_error %d \n", fw_error);
	if (r < 0) err(1,"Problem with KVM_SEV_INIT");
	//Next command: 
	struct kvm_sev_launch_start start;
	memset(&start, 0, sizeof(struct kvm_sev_launch_start));
	start.handle = 0; //Create a new handle
	start.policy = 0x30000;
	r = sev_ioctl(sev_fd,KVM_SEV_LAUNCH_START, &start, &fw_error); //sev_ioctl(sev_fd, NULL, NULL, &fw_error);
	printf("SEV ioctol %d, start.handle %d \n",r, start.handle);
	printf("fw_error %d \n", fw_error);
	if (r < 0) err(1,"Problem with KVM_SEV_INIT");
	



	

	//printf("Return code opening /dev/sev %d\n", sev_fd);
	//printf("Return code 	%d \n", ioctl(sev_fd, KVM_SEV_ES_INIT, NULL));
}

uint16_t *
read_counts() 
{
	uint16_t *counts = (uint16_t *)malloc(64*sizeof(uint16_t));
	size_t len;

	lseek(cachepc_fd, 0, SEEK_SET);
	len = read(cachepc_fd, counts, 64 * sizeof(uint16_t));
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
	printf("\n Target Set Count: %d %hu \n", TARGET_SET, counts[TARGET_SET]);
	printf("\n");
}

uint16_t *
collect(const char *prefix, void *code_start, void *code_stop)
{
	struct kvm_regs regs;
	uint16_t *counts;
	int ret;

	/* using cache size for alignment of kvm memory access */
	kvm_init(64 * 64 * 8 * 2, code_start, code_stop);

	ret = 0;
	kvm_run->exit_reason = 0;

	/* run vm twice, use count without initial stack setup */
	ret = ioctl(kvm.vcpufd, KVM_RUN, NULL);
	ret = ioctl(kvm.vcpufd, KVM_RUN, NULL);

	if (kvm_run->exit_reason == KVM_EXIT_MMIO) {
		memset(&regs, 0, sizeof(regs));
		ret = ioctl(kvm.vcpufd, KVM_GET_REGS, &regs);
		if (ret < 0) err(1, "KVM_GET_REGS");
		errx(1, "Victim access OOB: %lu %08llx => %02X\n",
			kvm_run->mmio.phys_addr, regs.rip,
			((uint8_t*)kvm.mem)[regs.rip]);
	}

	if (ret < 0 || kvm_run->exit_reason != KVM_EXIT_IO)
		errx(1, "KVM died: %i %i\n", ret, kvm_run->exit_reason);

	counts = read_counts();

	close(kvm.fd);
	close(kvm.vmfd);
	close(kvm.vcpufd);

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

	clear_cores(1 << TARGET_CORE);
	pin_process(0, TARGET_CORE, true);

	cachepc_fd = open("/proc/cachepc", O_RDONLY);
	if (cachepc_fd < 0) err(1, "open /proc/cachepc");

	/* init L1 miss counter */
	arg = 0x000064D8;
	ret = ioctl(cachepc_fd, CACHEPC_IOCTL_INIT_PMC, &arg);
	if (ret == -1) err(1, "ioctl fail");

	baseline = calloc(sizeof(uint16_t), 64);
	if (!baseline) err(1, "counts");
	for (k = 0; k < 64; k++)
		baseline[k] = UINT16_MAX;
	kvm_svm_init(64 * 64 * 8 * 2, __start_guest_with, __stop_guest_with);
	return 0;
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

	close(cachepc_fd);
}

