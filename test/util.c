#define _GNU_SOURCE

#include "test/util.h"

#include <pthread.h>
#include <sys/mman.h>
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

struct ipc *
ipc_alloc(void)
{
	pthread_mutexattr_t mutex_attr;
	pthread_condattr_t cond_attr;
	struct ipc *ipc;

	pthread_condattr_init(&cond_attr);
	pthread_condattr_setpshared(&cond_attr, PTHREAD_PROCESS_SHARED);

	pthread_mutexattr_init(&mutex_attr);
	pthread_mutexattr_setpshared(&mutex_attr, PTHREAD_PROCESS_SHARED);

	ipc = mmap(NULL, sizeof(struct ipc), PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (ipc == MAP_FAILED) err(1, "mmap");

	pthread_mutex_init(&ipc->lock, &mutex_attr);

	pthread_cond_init(&ipc->sig_parent, &cond_attr);
	ipc->has_sig_parent = false;

	pthread_cond_init(&ipc->sig_child, &cond_attr);
	ipc->has_sig_child = false;

	ipc->init = true;

	return ipc;
}

void
ipc_free(struct ipc *ipc)
{
	if (ipc->init) {
		pthread_mutex_destroy(&ipc->lock);
		pthread_cond_destroy(&ipc->sig_parent);
		pthread_cond_destroy(&ipc->sig_child);
		ipc->init = false;
	}
	munmap(ipc, sizeof(ipc));
}

void
ipc_signal_parent(struct ipc *ipc)
{
	if (!ipc->init) errx(1, "ipc deinit");
	pthread_mutex_lock(&ipc->lock);
	if (!ipc->has_sig_child)
		pthread_cond_signal(&ipc->sig_child);
	ipc->has_sig_child = true;
	pthread_mutex_unlock(&ipc->lock);
}

void
ipc_wait_child(struct ipc *ipc)
{
	if (!ipc->init) errx(1, "ipc deinit");
	pthread_mutex_lock(&ipc->lock);
	while (!ipc->has_sig_child)
		pthread_cond_wait(&ipc->sig_child, &ipc->lock);
	ipc->has_sig_child = false;
	pthread_mutex_unlock(&ipc->lock);
}

void
ipc_signal_child(struct ipc *ipc)
{
	if (!ipc->init) errx(1, "ipc deinit");
	pthread_mutex_lock(&ipc->lock);
	if (!ipc->has_sig_parent)
		pthread_cond_signal(&ipc->sig_parent);
	ipc->has_sig_parent = true;
	pthread_mutex_unlock(&ipc->lock);
}

void
ipc_wait_parent(struct ipc *ipc)
{
	if (!ipc->init) errx(1, "ipc deinit");
	pthread_mutex_lock(&ipc->lock);
	while (!ipc->has_sig_parent)
		pthread_cond_wait(&ipc->sig_parent, &ipc->lock);
	ipc->has_sig_parent = false;
	pthread_mutex_unlock(&ipc->lock);
}
