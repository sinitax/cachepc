#pragma once

#include "asm.h"
#include "cache_types.h"
#include "util.h"
#include "cachepc_user.h"

void cachepc_init_counters(void);

cache_ctx *cachepc_get_ctx(cache_level cl);
void cachepc_release_ctx(cache_ctx *ctx);

cacheline *cachepc_prepare_ds(cache_ctx *ctx);
void cachepc_release_ds(cache_ctx *ctx, cacheline *ds);

cacheline *cachepc_prepare_victim(cache_ctx *ctx, uint32_t set);
void cachepc_release_victim(cache_ctx *ctx, cacheline *ptr);

void cachepc_save_msrmts(cacheline *head);
void cachepc_print_msrmts(cacheline *head);

__attribute__((always_inline))
static inline cacheline *cachepc_prime(cacheline *head);

__attribute__((always_inline))
static inline cacheline *cachepc_prime_rev(cacheline *head);

__attribute__((always_inline))
static inline cacheline *cachepc_probe(cacheline *head);

__attribute__((always_inline))
static inline void cachepc_victim(void *p);

extern uint16_t *cachepc_msrmts;
extern size_t cachepc_msrmts_count;

extern cache_ctx *cachepc_ctx;
extern cacheline *cachepc_ds;

/*
 * Prime phase: fill the target cache (encoded in the size of the data structure)
 * with the prepared data structure, i.e. with attacker data.
 */
cacheline *
cachepc_prime(cacheline *head)
{
    cacheline *curr_cl;

    //printk(KERN_WARNING "CachePC: Priming..\n");

    cachepc_cpuid();
    curr_cl = head;
    do {
        curr_cl = curr_cl->next;
        cachepc_mfence();
    } while(curr_cl != head);
    cachepc_cpuid();

    //printk(KERN_WARNING "CachePC: Priming done\n");

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
cacheline *
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

cacheline *
cachepc_probe(cacheline *start_cl)
{
	uint64_t pre, post;
	cacheline *next_cl;
	cacheline *curr_cl;
	volatile register uint64_t i asm("r12");

	curr_cl = start_cl;

	do {
		pre = cachepc_readpmc(0);
		pre += cachepc_readpmc(1);

		cachepc_mfence();
		cachepc_cpuid();
		
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

		post = cachepc_readpmc(0);
		post += cachepc_readpmc(1);

		cachepc_mfence();
		cachepc_cpuid();

		/* works across size boundary */
		curr_cl->count = post - pre;

		curr_cl = next_cl;
	} while (__builtin_expect(curr_cl != start_cl, 1));

	return curr_cl->next;
}

void
cachepc_victim(void *p)
{
	cachepc_cpuid();
	cachepc_mfence();
	cachepc_readq(p);
}
