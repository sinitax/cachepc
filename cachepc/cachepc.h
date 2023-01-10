#pragma once

#include "asm.h"
#include "uapi.h"

#include "../../include/asm/apic.h"
#include "../../include/asm/irq_vectors.h"

#define L1_CACHE 0
#define L2_CACHE 1

#define CACHE_GROUP_SIZE (PAGE_SIZE / L1_LINESIZE)

#define CACHEPC_GET_BIT(b, i) (((b) >> (i)) & 1)
#define CACHEPC_SET_BIT(b, i) ((b) | (1 << (i)))

/* Operate cacheline flags
 * Used flags:
 *  32                    2              1       0
 * |  | ... | cache group initialized | last | first |
 */
#define CL_DEFAULT_FLAGS 0
#define CL_SET_FIRST(flags) CACHEPC_SET_BIT(flags, 0)
#define CL_SET_LAST(flags) CACHEPC_SET_BIT(flags, 1)
#define CL_SET_GROUP_INIT(flags) CACHEPC_SET_BIT(flags, 2)
#define CL_IS_FIRST(flags) CACHEPC_GET_BIT(flags, 0)
#define CL_IS_LAST(flags) CACHEPC_GET_BIT(flags, 1)
#define CL_IS_GROUP_INIT(flags) CACHEPC_GET_BIT(flags, 2)

#define CL_NEXT_OFFSET offsetof(struct cacheline, next)
#define CL_PREV_OFFSET offsetof(struct cacheline, prev)

#define PMC_KERNEL (1 << 1)
#define PMC_USER   (1 << 0)

#define PMC_HOST  (1 << 1)
#define PMC_GUEST (1 << 0)

#define CPC_DBG(...) do { \
	if (cachepc_debug) pr_info("CachePC: " __VA_ARGS__); } while (0)
#define CPC_INFO(...) do { pr_info("CachePC: " __VA_ARGS__); } while (0)
#define CPC_WARN(...) do { pr_warn("CachePC: " __VA_ARGS__); } while (0)
#define CPC_ERR(...) do { pr_err("CachePC: " __VA_ARGS__); } while (0)

typedef struct cacheline cacheline;
typedef struct cache_ctx cache_ctx;

struct cache_ctx {
    int cache_level;

    uint32_t sets;
    uint32_t associativity;
    uint32_t nr_of_cachelines;
    uint32_t set_size;
    uint32_t cache_size;
};

struct cacheline {
    /* Doubly linked cache lines inside same cache set */
    cacheline *next;
    cacheline *prev;

    uint32_t cache_set;
    uint32_t cache_line;
    uint32_t flags;

    uint64_t count;

    /* padding to fill cache line */
    char padding[24];
};

struct cpc_fault {
	uint64_t gfn;
	uint32_t err;

	struct list_head list;
};

static_assert(sizeof(struct cacheline) == L1_LINESIZE,
	"Bad cache line struct size");
static_assert(CL_NEXT_OFFSET == 0 && CL_PREV_OFFSET == 8);

bool cachepc_verify_topology(void);

void cachepc_init_pmc(uint8_t index, uint8_t event_no, uint8_t event_mask,
	uint8_t host_guest, uint8_t kernel_user);
void cachepc_reset_pmc(uint8_t index);

cache_ctx *cachepc_get_ctx(int cache_level);
void cachepc_release_ctx(cache_ctx *ctx);

cacheline *cachepc_prepare_ds(cache_ctx *ctx);
void cachepc_release_ds(cache_ctx *ctx, cacheline *ds);

cacheline *cachepc_prepare_victim(cache_ctx *ctx, uint32_t set);
void cachepc_release_victim(cache_ctx *ctx, cacheline *ptr);

void *cachepc_aligned_alloc(size_t alignment, size_t size);

void cachepc_save_msrmts(cacheline *head);
void cachepc_print_msrmts(cacheline *head);
void cachepc_update_baseline(void);

void cachepc_prime_vcall(uintptr_t ret, cacheline *cl);
void cachepc_probe_vcall(uintptr_t ret, cacheline *cl);

__attribute__((always_inline))
static inline cacheline *cachepc_prime(cacheline *head);

__attribute__((always_inline))
static inline cacheline *cachepc_probe(cacheline *head);

__attribute__((always_inline))
static inline void cachepc_victim(void *p);

__attribute__((always_inline))
static inline uint64_t cachepc_read_pmc(uint64_t event);

__attribute__((always_inline))
static inline void cachepc_apic_oneshot(uint32_t interval);

extern bool cachepc_debug;

extern uint8_t *cachepc_msrmts;
extern uint8_t *cachepc_baseline;
extern bool cachepc_baseline_measure;
extern bool cachepc_baseline_active;

extern bool cachepc_single_step;
extern uint32_t cachepc_track_mode;
extern uint32_t cachepc_apic_timer;

extern uint64_t cachepc_track_start_gfn;
extern uint64_t cachepc_track_end_gfn;

extern uint64_t cachepc_retinst;
extern uint64_t cachepc_retinst_prev;

extern uint64_t cachepc_rip;
extern uint64_t cachepc_rip_prev;

extern uint64_t cachepc_inst_fault_gfn;
extern uint32_t cachepc_inst_fault_err;
extern uint64_t cachepc_inst_fault_retinst;

extern struct list_head cachepc_faults;

extern cache_ctx *cachepc_ctx;
extern cacheline *cachepc_ds;

extern uint64_t cachepc_regs_tmp[16];
extern uint64_t cachepc_regs_vm[16];

/*
 * Prime phase: fill the target cache (encoded in the size of the data structure)
 * with the prepared data structure, i.e. with attacker data.
 */
cacheline *
cachepc_prime(cacheline *head)
{
	cacheline *curr_cl, *prev_cl;

	cachepc_mfence();
	cachepc_cpuid();
	
	curr_cl = head;
	do {
		prev_cl = curr_cl;
		curr_cl = curr_cl->next;
	} while (curr_cl != head);

	cachepc_mfence();
	cachepc_cpuid();

	return prev_cl;
}

cacheline *
cachepc_probe(cacheline *start_cl)
{
	uint64_t pre, post;
	cacheline *next_cl;
	cacheline *curr_cl;

	cachepc_mfence();
	cachepc_cpuid();

	curr_cl = start_cl;

	do {
		pre = cachepc_read_pmc(0);

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

		post = cachepc_read_pmc(0);

		/* works across size boundary */
		curr_cl->count = post - pre;

		curr_cl = next_cl;
	} while (__builtin_expect(curr_cl != start_cl, 1));

	next_cl = curr_cl->next;

	cachepc_mfence();
	cachepc_cpuid();

	return next_cl;
}

void
cachepc_victim(void *p)
{
	cachepc_mfence();
	cachepc_cpuid();

	cachepc_readq(p);

	cachepc_mfence();
	cachepc_cpuid();
}

uint64_t
cachepc_read_pmc(uint64_t event)
{
	uint32_t lo, hi;
	uint64_t res;

	cachepc_mfence();
	cachepc_cpuid();

	event = 0xC0010201 + 2 * event;

	asm volatile (
		"rdmsr"
		: "=a" (lo), "=d" (hi)
		: "c"(event)
	);
	res = (((uint64_t) hi) << 32) | (uint64_t) lo;

	cachepc_mfence();
	cachepc_cpuid();

	return res;
}

void
cachepc_apic_oneshot(uint32_t interval)
{
	native_apic_mem_write(APIC_LVTT, LOCAL_TIMER_VECTOR | APIC_LVT_TIMER_ONESHOT);
	native_apic_mem_write(APIC_TDCR, APIC_TDR_DIV_1);
	native_apic_mem_write(APIC_TMICT, interval);
}
