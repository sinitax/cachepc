/* for CPU_ZERO macros.. */
#define _GNU_SOURCE

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
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#define ARRLEN(x) (sizeof(x) / sizeof((x)[0]))

#define SAMPLE_COUNT 100

#define TARGET_CORE 2
#define SECONDARY_CORE 2

#define TARGET_CACHE L1

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

static const uint8_t kvm_code[] = {
	0xba, 0xf8, 0x03, /* mov $0x3f8, %dx */
	0x00, 0xd8,       /* add %bl, %al */
	0x04, '0',        /* add $'0', %al */
	0xee,             /* out %al, (%dx) */
	0xb0, '\n',       /* mov $'\n', %al */
	0xee,             /* out %al, (%dx) */
	0xf4,             /* hlt */
};

#if TARGET_CACHE == L1
static int perf_counters[] = {400, 401}; /* L1 Miss */
#elif TARGET_CACHE == L2
static int perf_counters[] = {404, 402, 403}; /* L2 Miss */
#endif

static bool ready = false;
static bool processed = false;

static ssize_t sysret;
static pid_t victim_pid;

static struct kvm kvm;
static struct kvm_run *kvm_run;

#define TARGET_CACHE_LINESIZE 64
#define TARGET_SET 15

__attribute__((section("guest_with"))) void
vm_guest_with(void)
{
	while (1) {
		asm volatile("mov %%bl, (%[v])"
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

static inline uint64_t
read_pmc(uint64_t event)
{
	uint32_t lo, hi;

	asm volatile (
		"mov %[event], %%rcx\t\n"
		"rdpmc\t\n"
		: "=a" (lo), "=d" (hi)
		: [event] "r" (event)
	);

	return ((uint64_t) hi << 32) | lo;
}

bool
pin_process(pid_t pid, int cpu, bool assert)
{
	cpu_set_t cpuset;
	int status;

	CPU_ZERO(&cpuset);
	CPU_SET(cpu, &cpuset);
    return true;
	status = sched_setaffinity(pid, sizeof(cpu_set_t), &cpuset);
	if (status < 0) {
		if (assert) err(EXIT_FAILURE, "sched_setaffinity");
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
		err(EXIT_FAILURE, "read stat");

	p = line;
	for (i = 0; i < 38 && (p = strchr(p, ' ')); i++)
		p += 1;

	if (!p) errx(EXIT_FAILURE, "stat format");
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
	if (!proc_dir) err(EXIT_FAILURE, "opendir");

	while ((proc_ent = readdir(proc_dir))) {
		pid = atoi(proc_ent->d_name);
		if (!pid) continue;

		cpu = read_stat_core(pid);
		if (cpu >= 0 && (1 << cpu) & cpu_mask) {
			res = pin_process(pid, SECONDARY_CORE, false);
			if (!res) printf("Failed pin %i from %i\n", pid, cpu);
			continue;
		}

		snprintf(taskpath, sizeof(taskpath), "/proc/%u/task", pid);
		task_dir = opendir(taskpath);
		if (!task_dir) err(EXIT_FAILURE, "opendir");

		while ((task_ent = readdir(task_dir))) {
			tid = atoi(task_ent->d_name);
			if (!tid || tid == pid) continue;

			cpu = read_stat_core(tid);
			if (cpu >= 0 && (1 << cpu) & cpu_mask) {
				res = pin_process(tid, SECONDARY_CORE, false);
				if (!res) printf("Failed pin %i from %i\n", tid, cpu);
			}
		}

		closedir(task_dir);
	}

	closedir(proc_dir);
}

void
kvm_init(size_t ramsize, size_t code_start, size_t code_stop)
{
	struct kvm_userspace_memory_region region;
	struct kvm_regs regs;
	struct kvm_sregs sregs;
	int ret;

	kvm.fd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
	if (kvm.fd < 0)
		err(EXIT_FAILURE, "/dev/kvm");

	/* Make sure we have the stable version of the API */
	ret = ioctl(kvm.fd, KVM_GET_API_VERSION, NULL);
	if (ret == -1)
		err(EXIT_FAILURE, "KVM_GET_API_VERSION");
	if (ret != 12)
		errx(EXIT_FAILURE, "KVM_GET_API_VERSION %d, expected 12", ret);

	kvm.vmfd = ioctl(kvm.fd, KVM_CREATE_VM, 0);
	if (kvm.vmfd < 0)
		err(EXIT_FAILURE, "KVM_CREATE_VM");

	/* Allocate one aligned page of guest memory to hold the code. */
	kvm.mem = mmap(NULL, ramsize, PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (!kvm.mem) err(EXIT_FAILURE, "allocating guest memory");
	assert(code_stop - code_start <= ramsize);
	memcpy(kvm.mem, code_start, code_stop - code_start);

	/* Map it to the second page frame (to avoid the real-mode IDT at 0). */
	memset(&region, 0, sizeof(region));
	region.slot = 0;
	region.memory_size = ramsize;
	region.guest_phys_addr = 0x0000;
	region.userspace_addr = (uint64_t) kvm.mem;
    printf("Ramsize %d\n", region.memory_size);
	printf("Access guest %d\n", TARGET_CACHE_LINESIZE * TARGET_SET);
	ret = ioctl(kvm.vmfd, KVM_SET_USER_MEMORY_REGION, &region);
	if (ret < 0) err(EXIT_FAILURE, "KVM_SET_USER_MEMORY_REGION");

	kvm.vcpufd = ioctl(kvm.vmfd, KVM_CREATE_VCPU, 0);
	if (kvm.vcpufd < 0) err(EXIT_FAILURE, "KVM_CREATE_VCPU");

	/* Map the shared kvm_run structure and following data. */
	ret = ioctl(kvm.fd, KVM_GET_VCPU_MMAP_SIZE, NULL);
	if (ret < 0) err(EXIT_FAILURE, "KVM_GET_VCPU_MMAP_SIZE");

	if (ret < sizeof(struct kvm_run))
		errx(EXIT_FAILURE, "KVM_GET_VCPU_MMAP_SIZE too small");
	kvm_run = mmap(NULL, ret, PROT_READ | PROT_WRITE,
		MAP_SHARED, kvm.vcpufd, 0);
	if (!kvm_run) err(EXIT_FAILURE, "mmap vcpu");

	/* Initialize CS to point at 0, via a read-modify-write of sregs. */
	memset(&sregs, 0, sizeof(sregs));
	ret = ioctl(kvm.vcpufd, KVM_GET_SREGS, &sregs);
	if (ret < 0) err(EXIT_FAILURE, "KVM_GET_SREGS");
	sregs.cs.base = 0;
	sregs.cs.selector = 0;
	ret = ioctl(kvm.vcpufd, KVM_SET_SREGS, &sregs);
	if (ret < 0) err(EXIT_FAILURE, "KVM_SET_SREGS");

	/* Initialize registers: instruction pointer for our code, addends, and
	 * initial flags required by x86 architecture. */
	memset(&regs, 0, sizeof(regs));
	regs.rip = 0x0;
	regs.rax = 0;
	regs.rdx = 0;
	regs.rflags = 0x2;
	ret = ioctl(kvm.vcpufd, KVM_SET_REGS, &regs);
	if (ret < 0) err(EXIT_FAILURE, "KVM_SET_REGS");
}

int16_t *print_accessed_sets(){
	//int16_t counts[64];
	int16_t *counts = (int16_t *)malloc(64*sizeof(int16_t));
	size_t i, len;
	int fd;
	fd = open("/proc/cachepc", O_RDONLY);
	len = read(fd, counts, 64*sizeof(int16_t)); // sizeof(counts));
	assert(len == 64*sizeof(int16_t));//sizeof(counts));

	for (i = 0; i < 64; i++) {
			//printf("%d %hu\n", i, counts[i]);
			//continue;
			if (i % 16 == 0 && i)
					printf("\n");
			if (counts[i] > 0)
					printf("\x1b[91m");
			printf("%2i ", i);
			if (counts[i] > 0)
					printf("\x1b[0m");
	}
	printf("\n Target Set Count: %d %hu \n", TARGET_SET, counts[TARGET_SET]);
	printf("\n");
	close(fd);
	return counts;
}


void
collect(	const char *prefix, size_t code_start, size_t code_stop)
{
	int ret;

	/* using cache size for alignment of kvm memory access */
	//kvm_init(32768, code_start, code_stop);
	kvm_init(131072, code_start, code_stop);
	printf("KVm init done\n");


	ret = 0;
	kvm_run->exit_reason = KVM_EXIT_IO;

	
	printf("Now calling KVM_RUN");
	ret = ioctl(kvm.vcpufd, KVM_RUN, NULL);
	if (kvm_run->exit_reason == KVM_EXIT_MMIO)
		errx(EXIT_FAILURE, "Victim access OOB: %lu\n",
			kvm_run->mmio.phys_addr);

	if (ret < 0 || kvm_run->exit_reason != KVM_EXIT_IO)
		errx(EXIT_FAILURE, "KVM died: %i %i\n",
			ret, kvm_run->exit_reason);
	close(kvm.fd);
	close(kvm.vmfd);
	close(kvm.vcpufd);
}

void dump_msrmt_results_to_log(char *log_file_path, int16_t msrmt_results[SAMPLE_COUNT][64]){
	FILE *fp = fopen(log_file_path,"w+");
	if (!fp){
		errx(EXIT_FAILURE, "Failed to open log file\n");
	}
	fprintf(fp, "Number of samples: %d\n", SAMPLE_COUNT);
	fprintf(fp, "Target set: %d\n", TARGET_SET);
	fprintf(fp, "Measurements per sample: %d\n", 64);
	fprintf(fp, "Legend: target set: %d\n", TARGET_SET);
	fprintf(fp, "Output cache attack data\n"); 
	for(int i=0; i<SAMPLE_COUNT; ++i){
		fprintf(fp, "Sample number %d:\n", i);
		for(int j=0; j<64; ++j){
			fprintf(fp, "%3d ", msrmt_results[i][j]);
			//assert((msrmt_results[i][TARGET_SET] > 0));
		}
		fprintf(fp,"\n");
	}
	close(fp);

}

int
main(int argc, const char **argv)
{
	
	setvbuf(stdout, NULL, _IONBF, 0);

	clear_cores(1 << TARGET_CORE);
	pin_process(0, TARGET_CORE, true);


	printf("\n");
	printf("Number of samples: %d\n", SAMPLE_COUNT);
	printf("Target set: %d\n", TARGET_SET);

	int16_t msmrt_without_access[SAMPLE_COUNT][64];
	int16_t msmrt_with_access[SAMPLE_COUNT][64];
	for(int i=0; i < SAMPLE_COUNT; ++i){
		printf("First: Testing VM without memory access \n");
		collect("without", __start_guest_without, __stop_guest_without);
		int16_t *tmp_res =  print_accessed_sets();
		memcpy(msmrt_without_access[i], tmp_res, 64*sizeof(int16_t));
		free(tmp_res);
		printf("Now: Testing access with memory access \n");
		collect( "with", __start_guest_with, __stop_guest_with);
		tmp_res = print_accessed_sets();
		memcpy(msmrt_with_access[i], tmp_res, 64*sizeof(int16_t));
		free(tmp_res);
	}
	printf("#### MSRT_WITHOUT_ACCESS ####\n");
	for(int i=0; i<SAMPLE_COUNT; ++i){
		printf("Sample number %d:\n", i);
		for(int j=0; j<64; ++j){
			printf("%3d ", msmrt_without_access[i][j]);
		}
		putchar('\n');
	}
	printf("\n");
	printf("#### MSRT_WITH_ACCESS ####\n");
	for(int i=0; i<SAMPLE_COUNT; ++i){
		printf("Sample number %d:\n", i);
		for(int j=0; j<64; ++j){
			printf("%3d ", msmrt_with_access[i][j]);
			assert((msmrt_with_access[i][TARGET_SET] > 0));
		}
		putchar('\n');
	}
	printf("\n");
	dump_msrmt_results_to_log("msmrt_without_access.out", msmrt_without_access);
	dump_msrmt_results_to_log("msmrt_with_access.out", msmrt_with_access);

}
