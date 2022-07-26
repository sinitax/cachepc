#pragma once

#include <linux/kernel.h>

#define CPUID_AFFECTED_REGS "rax", "rbx", "rcx", "rdx"

__attribute__((always_inline))
static inline uint64_t cachepc_readpmc(uint64_t event);

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

__attribute__((always_inline))
static inline void cachepc_victim(void *p);

uint64_t
cachepc_readpmc(uint64_t event)
{
	uint32_t lo, hi;

	asm volatile (
		"rdmsr"
		: "=a" (lo), "=d" (hi)
		: "c"(event)
	);

	return ((uint64_t) hi << 32) | lo;
}

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
		::
	);
}

void
cachepc_sfence(void)
{
	asm volatile(
		"sfence\n\t"
		::
	);
}

void
cachepc_mfence(void)
{
	asm volatile(
		"mfence\n\t"
		::
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

void
cachepc_victim(void *p)
{
	cachepc_mfence();
	cachepc_readq(p);
}
