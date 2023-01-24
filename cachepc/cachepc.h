#pragma once

#include "uapi.h"

#include "../../include/asm/apic.h"
#include "../../include/asm/irq_vectors.h"

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
	uint32_t sets;
	uint32_t associativity;
	uint32_t nr_of_cachelines;
	uint32_t set_size;
	uint32_t cache_size;
};

struct cacheline {
	cacheline *next;
	cacheline *prev;
	uint64_t count;

	uint32_t cache_set;
	uint32_t cache_line;
	uint32_t flags;

	char padding[28];
};

struct cpc_fault {
	uint64_t gfn;
	uint32_t err;

	struct list_head list;
};

struct cpc_track_exec {
	bool cur_avail;
	uint64_t cur_gfn;
	uint64_t retinst;
};

static_assert(sizeof(struct cacheline) == L1_LINESIZE, "Bad cacheline struct");
static_assert(CPC_CL_NEXT_OFFSET == offsetof(struct cacheline, next));
static_assert(CPC_CL_PREV_OFFSET == offsetof(struct cacheline, prev));
static_assert(CPC_CL_COUNT_OFFSET == offsetof(struct cacheline, count));

bool cachepc_verify_topology(void);

void cachepc_write_msr(uint64_t addr, uint64_t clear_bits, uint64_t set_bits);

void cachepc_init_pmc(uint8_t index, uint8_t event_no, uint8_t event_mask,
	uint8_t host_guest, uint8_t kernel_user);
void cachepc_reset_pmc(uint8_t index);

cache_ctx *cachepc_get_ctx(void);
void cachepc_release_ctx(cache_ctx *ctx);

cacheline *cachepc_prepare_ds(cache_ctx *ctx);
void cachepc_release_ds(cache_ctx *ctx, cacheline *ds);

cacheline *cachepc_prepare_victim(cache_ctx *ctx, uint32_t set);
void cachepc_release_victim(cache_ctx *ctx, cacheline *ptr);

void *cachepc_aligned_alloc(size_t alignment, size_t size);

void cachepc_save_msrmts(cacheline *head);
void cachepc_print_msrmts(cacheline *head);

cacheline *cachepc_prime(cacheline *head);
void cachepc_probe(cacheline *head);

uint64_t cachepc_read_pmc(uint64_t event);

void cachepc_apic_oneshot_run(uint32_t interval);

extern bool cachepc_debug;

extern struct cacheline *cachepc_victim;

extern uint8_t *cachepc_msrmts;
extern uint8_t *cachepc_baseline;
extern bool cachepc_baseline_measure;
extern bool cachepc_baseline_active;

extern bool cachepc_pause_vm;

extern bool cachepc_singlestep;
extern bool cachepc_singlestep_reset;
extern bool cachepc_long_step;

extern bool cachepc_apic_oneshot;
extern uint32_t cachepc_apic_timer;

extern uint32_t cachepc_track_mode;
extern uint64_t cachepc_track_start_gfn;
extern uint64_t cachepc_track_end_gfn;

extern uint64_t cachepc_retinst;
extern uint64_t cachepc_retinst_prev;

extern uint64_t cachepc_rip;
extern uint64_t cachepc_rip_prev;
extern bool cachepc_rip_prev_set;

extern struct cpc_track_exec cachepc_track_exec;

extern struct list_head cachepc_faults;

extern cache_ctx *cachepc_ctx;
extern cacheline *cachepc_ds;

extern uint64_t cachepc_regs_tmp[16];
extern uint64_t cachepc_regs_vm[16];
