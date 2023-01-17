#define _GNU_SOURCE

#include "test/util.h"

#include <err.h>
#include <sched.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

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
	printf("\n");
}

void
print_counts_raw(uint8_t *counts)
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
