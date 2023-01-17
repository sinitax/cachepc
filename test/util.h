#pragma once

#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>

#define ARRLEN(x) (sizeof(x) / sizeof((x)[0]))
#define MIN(a,b) ((a) > (b) ? (b) : (a))

void hexdump(void *data, int len);

bool pin_process(pid_t pid, int cpu, bool assert);

int read_stat_core(pid_t pid);

void print_counts(uint8_t *counts);
void print_counts_raw(uint8_t *counts);
