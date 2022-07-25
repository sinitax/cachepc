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
