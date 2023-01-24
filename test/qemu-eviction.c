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
#include <dirent.h>
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

/* ioctl dev fds */
static int kvm_dev;
static int faultcnt;

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
	if (ret < 0) {
		if (assert) err(1, "sched_setaffinity");
		return false;
	}

	return true;
}

cpc_msrmt_t *
read_counts()
{
	cpc_msrmt_t *counts;
	int i, ret;

	counts = malloc(L1_SETS * sizeof(cpc_msrmt_t));
	if (!counts) err(1, "malloc");

	ret = ioctl(kvm_dev, KVM_CPC_READ_COUNTS, counts);
	if (ret) err(1, "ioctl READ_COUNTS");

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

int
monitor(bool baseline)
{
	struct cpc_event event;
	cpc_msrmt_t counts[64];
	uint64_t inst_fault_gfn;
	uint64_t read_fault_gfn;
	uint64_t arg;
	int ret, i;

	/* Get page fault info */
	ret = ioctl(kvm_dev, KVM_CPC_POLL_EVENT, &event);
	if (ret) {
		if (errno == EAGAIN)
			return 0;
		perror("ioctl POLL_EVENT");
		return 1;
	}

	if (event.type == CPC_EVENT_CPUID) {
		printf("CPUID EVENT\n");
		if (event.guest.type == CPC_GUEST_START_TRACK) {
			ret = ioctl(kvm_dev, KVM_CPC_TRACK_EXEC_CUR, &inst_fault_gfn);
			if (ret) err(1, "ioctl TRACK_EXEC_CUR");

			printf("CPUID INST PAGE: %lu\n", inst_fault_gfn);

			arg = inst_fault_gfn;
			ret = ioctl(kvm_dev, KVM_CPC_TRACK_RANGE_START, &arg);
			if (ret) err(1, "ioctl TRACK_RANGE_START");

			arg = inst_fault_gfn+8;
			ret = ioctl(kvm_dev, KVM_CPC_TRACK_RANGE_END, &arg);
			if (ret) err(1, "ioctl TRACK_RANGE_END");
		} else if (event.guest.type == CPC_GUEST_STOP_TRACK) {
			arg = 0;
			ret = ioctl(kvm_dev, KVM_CPC_TRACK_RANGE_START, &arg);
			if (ret) err(1, "ioctl TRACK_RANGE_START");

			arg = 0;
			ret = ioctl(kvm_dev, KVM_CPC_TRACK_RANGE_END, &arg);
			if (ret) err(1, "ioctl TRACK_RANGE_END");
		}

		faultcnt++;
	} else if (event.type == CPC_EVENT_TRACK_STEP) {
		printf("STEP EVENT\n");

		ret = ioctl(kvm_dev, KVM_CPC_READ_COUNTS, counts);
		if (ret) err(1, "ioctl READ_COUNTS");

		inst_fault_gfn = 0;
		read_fault_gfn = 0;
		for (i = 0; i < event.step.fault_count; i++) {
			if ((event.step.fault_errs[i] & 0b11111) == 0b10100)
				inst_fault_gfn = event.step.fault_gfns[i];
			else if ((event.step.fault_errs[i] & 0b00110) == 0b00100)
				read_fault_gfn = event.step.fault_gfns[i];
		}

		if (!baseline) {
			printf("Event: cnt:%llu inst:%lu data:%lu retired:%llu\n",
				event.step.fault_count, inst_fault_gfn,
				read_fault_gfn, event.step.retinst);
			print_counts(counts);
			printf("\n");
		}

		for (i = 0; i < 64; i++) {
			if (counts[i] > 8) {
				warnx("Invalid count for set %i (%llu)",
					i, counts[i]);
				counts[i] = 8;
			}
		}

		if (baseline) faultcnt++;
	} else if (event.type == CPC_EVENT_TRACK_PAGE) {
		printf("PAGE EVENT\n");

		printf("Event: prev:%llu new:%llu retired:%llu\n",
			event.page.inst_gfn_prev, event.page.inst_gfn,
		       	event.page.retinst);
	}

	ret = ioctl(kvm_dev, KVM_CPC_ACK_EVENT, &event.id);
	if (ret) err(1, "ioctl ACK_EVENT");

	return 0;
}

int
pgrep(const char *bin)
{
	char path[PATH_MAX];
	char buf[PATH_MAX];
	char *cmp;
	struct dirent *ent;
	FILE *f;
	DIR *dir;

	dir = opendir("/proc");
	if (!dir) err(1, "opendir");

	while ((ent = readdir(dir))) {
		snprintf(path, sizeof(path), "/proc/%s/cmdline", ent->d_name);
		f = fopen(path, "rb");
		if (!f) continue;
		memset(buf, 0, sizeof(buf));
		fread(buf, 1, sizeof(buf), f);
		if ((cmp = strrchr(buf, '/')))
			cmp += 1;
		else
			cmp = buf;
		if (!strcmp(cmp, bin))
			return atoi(ent->d_name);
		fclose(f);
	}

	closedir(dir);

	return 0;
}

int
main(int argc, const char **argv)
{
	pid_t pid;
	uint32_t arg;
	struct cpc_event event;
	cpc_msrmt_t baseline[64];
	int ret, i;

	kvm_setup_init();

	setvbuf(stdout, NULL, _IONBF, 0);

	pid = pgrep("qemu-system-x86_64");
	if (!pid) errx(1, "Failed to find qemu instance");
	printf("PID %i\n", pid);

	pin_process(pid, TARGET_CORE, true);
	pin_process(0, TARGET_CORE, true);

	/* Setup needed performance counters */
	ret = ioctl(kvm_dev, KVM_CPC_SETUP_PMC, NULL);
	if (ret < 0) err(1, "ioctl SETUP_PMC");

	/* Reset previous tracking */
	ret = ioctl(kvm_dev, KVM_CPC_RESET_TRACKING, NULL);
	if (ret) err(1, "ioctl RESET_TRACKING");

	pin_process(0, SECONDARY_CORE, true);
	printf("PINNED\n");

	// arg = false;
	// ret = ioctl(kvm_dev, KVM_CPC_SUB_BASELINE, &arg);
	// if (ret) err(1, "ioctl SUB_BASELINE");

	// arg = true;
	// ret = ioctl(kvm_dev, KVM_CPC_MEASURE_BASELINE, &arg);
	// if (ret) err(1, "ioctl MEASURE_BASELINE");

	// arg = KVM_PAGE_TRACK_ACCESS;
	// ret = ioctl(kvm_dev, KVM_CPC_TRACK_ALL, &arg);
	// if (ret) err(1, "ioctl TRACK_ALL");

	// arg = CPC_TRACK_DATA_ACCESS;
	// ret = ioctl(kvm_dev, KVM_CPC_TRACK_MODE, &arg);
	// if (ret) err(1, "ioctl TRACK_MODE");

	// faultcnt = 0;
	// while (faultcnt < 100) {
	// 	if (monitor(true)) break;
	// }

	// do {
	// 	ret = ioctl(kvm_dev, KVM_CPC_POLL_EVENT, &event);
	// 	if (ret && errno != EAGAIN)
	// 		err(1, "ioctl POLL_EVENT");
	// } while (ret && errno == EAGAIN);

	// arg = KVM_PAGE_TRACK_ACCESS;
	// ret = ioctl(kvm_dev, KVM_CPC_UNTRACK_ALL, &arg);
	// if (ret) err(1, "ioctl UNTRACK_ALL");

	arg = CPC_TRACK_EXEC;
	ret = ioctl(kvm_dev, KVM_CPC_TRACK_MODE, &arg);
	if (ret) err(1, "ioctl TRACK_MODE");

	arg = KVM_PAGE_TRACK_EXEC;
	ret = ioctl(kvm_dev, KVM_CPC_TRACK_ALL, &arg);
	if (ret) err(1, "ioctl TRACK_ALL");

	// arg = false;
	// ret = ioctl(kvm_dev, KVM_CPC_MEASURE_BASELINE, &arg);
	// if (ret) err(1, "ioctl MEASURE_BASELINE");

	// ret = ioctl(kvm_dev, KVM_CPC_READ_BASELINE, baseline);
	// if (ret) err(1, "ioctl READ_BASELINE");

	// printf("\n>>> BASELINE:\n");
	// print_counts(baseline);
	// printf("\n");
	// print_counts_raw(baseline);
	// printf("\n");

	// /* Check baseline for saturated sets */
	// for (i = 0; i < 64; i++) {
	// 	if (baseline[i] >= 8)
	// 		errx(1, "!!! Baseline set %i full\n", i);
	// }

	// arg = true;
	// ret = ioctl(kvm_dev, KVM_CPC_SUB_BASELINE, &arg);
	// if (ret) err(1, "ioctl SUB_BASELINE");

	// ret = ioctl(kvm_dev, KVM_CPC_ACK_EVENT, &event.id);
	// if (ret) err(1, "ioctl ACK_EVENT");

	faultcnt = 0;
	while (faultcnt < 10) {
		if (monitor(false)) break;
	}

	arg = KVM_PAGE_TRACK_EXEC;
	ret = ioctl(kvm_dev, KVM_CPC_UNTRACK_ALL, &arg);
	if (ret) err(1, "ioctl UNTRACK_ALL");

	kvm_setup_deinit();
}

