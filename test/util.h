#pragma once

#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>

#define ARRLEN(x) (sizeof(x) / sizeof((x)[0]))
#define MIN(a,b) ((a) > (b) ? (b) : (a))

struct ipc {
	pthread_mutex_t lock;
	pthread_cond_t sig_parent;
	bool has_sig_parent;
	pthread_cond_t sig_child;
	bool has_sig_child;
	bool init;
};

void hexdump(void *data, int len);

bool pin_process(pid_t pid, int cpu, bool assert);

int read_stat_core(pid_t pid);
int pgrep(const char *cmd);

void print_counts(uint8_t *counts);
void print_counts_raw(uint8_t *counts);

struct ipc *ipc_alloc(void);
void ipc_free(struct ipc *ipc);
void ipc_signal_child(struct ipc *ipc);
void ipc_wait_child(struct ipc *ipc);
void ipc_signal_parent(struct ipc *ipc);
void ipc_wait_parent(struct ipc *ipc);
