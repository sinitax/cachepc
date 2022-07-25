#pragma once

#include <linux/kernel.h>
#include <linux/types.h> 
#include <linux/slab.h>

#include "asm.h"
#include "cache_types.h"
#include "util.h"

#define L2_HIT_CNTR 0xC0010201
#define L2_MISS_CNTR 0xC0010203

void cachepc_init_counters(void);

cache_ctx *cachepc_get_ctx(cache_level cl);
cacheline *cachepc_prepare_ds(cache_ctx *ctx);
void cachepc_save_msrmts(cacheline *head, const char *prefix, int index);
void cachepc_print_msrmts(cacheline *head);

__attribute__((always_inline))
static inline cacheline *cachepc_prime(cacheline *head);

__attribute__((always_inline))
static inline cacheline *cachepc_prime_rev(cacheline *head);

__attribute__((always_inline))
static inline cacheline *cachepc_probe_set(cacheline *curr_cl);

__attribute__((always_inline))
static inline cacheline *cachepc_probe(cacheline *head);

/*
 * Prime phase: fill the target cache (encoded in the size of the data structure)
 * with the prepared data structure, i.e. with attacker data.
 */
static inline cacheline *
cachepc_prime(cacheline *head)
{
    cacheline *curr_cl;

    printk(KERN_WARNING "PROBE");

    cachepc_cpuid();
    curr_cl = head;
    do {
        curr_cl = curr_cl->next;
        cachepc_mfence();
    } while(curr_cl != head);
    cachepc_cpuid();

    return curr_cl->prev;
}

/*
 * Same as prime, but in the reverse direction, i.e. the same direction that probe
 * uses. This is beneficial for the following scenarios:
 *     - L1:
 *         - Trigger collision chain-reaction to amplify an evicted set (but this has
 *           the downside of more noisy measurements).
 *     - L2:
 *         - Always use this for L2, otherwise the first cache sets will still reside
 *           in L1 unless the victim filled L1 completely. In this case, an eviction
 *           has randomly (depending on where the cache set is placed in the randomised
 *           data structure) the following effect:
 *             A) An evicted set is L2_ACCESS_TIME - L1_ACCESS_TIME slower
 *             B) An evicted set is L3_ACCESS_TIME - L2_ACCESS_TIME slower
 */
static inline cacheline *
cachepc_prime_rev(cacheline *head)
{
    cacheline *curr_cl;

    cachepc_cpuid();
    curr_cl = head;
    do {
        curr_cl = curr_cl->prev;
        cachepc_mfence();
    } while(curr_cl != head);
    cachepc_cpuid();

    return curr_cl->prev;
}

static inline cacheline *
cachepc_probe_set(cacheline *curr_cl)
{
	uint64_t pre1, pre2;
	uint64_t post1, post2;
	cacheline *next_cl;

	pre1 = cachepc_readpmc(L2_HIT_CNTR);
	pre2 = cachepc_readpmc(L2_MISS_CNTR);

	cachepc_mfence();
	asm volatile(
		"mov 8(%[curr_cl]), %%rax \n\t"              // +8
		"mov 8(%%rax), %%rcx \n\t"                   // +16
		"mov 8(%%rcx), %%rax \n\t"                   // +24
		"mov 8(%%rax), %%rcx \n\t"                   // +32
		"mov 8(%%rcx), %%rax \n\t"                   // +40
		"mov 8(%%rax), %%rcx \n\t"                   // +48
		"mov 8(%%rcx), %[curr_cl_out] \n\t"          // +56
		"mov 8(%[curr_cl_out]), %[next_cl_out] \n\t" // +64
		: [next_cl_out] "=r" (next_cl),
		  [curr_cl_out] "=r" (curr_cl)
		: [curr_cl] "r" (curr_cl)
		: "rax", "rcx"
	);
	cachepc_mfence();
	cachepc_cpuid();

	post1 = cachepc_readpmc(L2_HIT_CNTR);
	cachepc_cpuid();
	post2 = cachepc_readpmc(L2_MISS_CNTR);
	cachepc_cpuid();

	/* works across size boundary */
	curr_cl->count = 0;
	curr_cl->count += post1 - pre1;
	curr_cl->count += post2 - pre2;

	return next_cl;
}

static inline cacheline *
cachepc_probe(cacheline *head)
{
	cacheline *curr_cs;

	printk(KERN_WARNING "PROBE");
       
	curr_cs = head;
	do {
		curr_cs = cachepc_probe_set(curr_cs);
	} while (__builtin_expect(curr_cs != head, 1));

	return curr_cs->next;
}

