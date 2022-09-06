#pragma once

#include <linux/kernel.h>

#define CPUID_AFFECTED_REGS "rax", "rbx", "rcx", "rdx"

__attribute__((always_inline))
static inline void cachepc_cpuid(void);

__attribute__((always_inline))
static inline void cachepc_lfence(void);

__attribute__((always_inline))
static inline void cachepc_sfence(void);

__attribute__((always_inline))
static inline void cachepc_mfence(void);

__attribute__((always_inline))
static inline void cachepc_readq(void *p);

void
cachepc_cpuid(void)
{
	asm volatile(
		"mov $0x80000005, %%eax\n\t"
		"cpuid\n\t"
		::: CPUID_AFFECTED_REGS
	);
}

void
cachepc_lfence(void)
{
	asm volatile(
		"lfence\n\t"
		::: "memory"
	);
}

void
cachepc_sfence(void)
{
	asm volatile(
		"sfence\n\t"
		::: "memory"
	);
}

void
cachepc_mfence(void)
{
	asm volatile(
		"mfence\n\t"
		::: "memory"
	);
}

void
cachepc_readq(void *p)
{
	asm volatile (
		"movq (%0), %%r10\n\t"
		: : "r" (p) : "r10"
	);
}
