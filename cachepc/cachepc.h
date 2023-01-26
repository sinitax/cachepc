#pragma once

#include "uapi.h"

#include "../../include/asm/apic.h"
#include "../../include/asm/irq_vectors.h"

#define PMC_KERNEL (1 << 1)
#define PMC_USER   (1 << 0)

#define PMC_HOST  (1 << 1)
#define PMC_GUEST (1 << 0)

#define CPC_DBG(...) do { \
	if (cachepc_debug) pr_info("CachePC: " __VA_ARGS__); } while (0)
#define CPC_INFO(...) do { pr_info("CachePC: " __VA_ARGS__); } while (0)
#define CPC_WARN(...) do { pr_warn("CachePC: " __VA_ARGS__); } while (0)
#define CPC_ERR(...) do { pr_err("CachePC: " __VA_ARGS__); } while (0)

struct cacheline {
	struct cacheline *next;
	struct cacheline *prev;
	uint64_t count;

	uint32_t cache_set;
	uint32_t cache_line;
	bool first;

	char padding[31];
};

struct cpc_fault {
	uint64_t gfn;
	uint32_t err;

	struct list_head list;
};

struct cpc_track_pages {
	bool cur_avail;
	uint64_t cur_gfn;
	uint64_t retinst;
	bool step;
};

struct cpc_track_steps_signalled {
	bool enabled;
	bool target_avail;
	uint64_t target_gfn;
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

struct cacheline *cachepc_ds_alloc(struct cacheline **ds_ul);

void *cachepc_aligned_alloc(size_t alignment, size_t size);

void cachepc_save_msrmts(struct cacheline *head);
void cachepc_print_msrmts(struct cacheline *head);

struct cacheline *cachepc_prime(struct cacheline *head);
void cachepc_probe(struct cacheline *head);

uint64_t cachepc_read_pmc(uint64_t event);

void cachepc_apic_oneshot_run(uint32_t interval);

extern bool cachepc_debug;

extern uint8_t *cachepc_msrmts;
extern uint8_t *cachepc_baseline;
extern bool cachepc_baseline_measure;
extern bool cachepc_baseline_active;

extern bool cachepc_pause_vm;

extern bool cachepc_prime_probe;

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

extern struct cpc_track_pages cpc_track_pages;
extern struct cpc_track_steps_signalled cpc_track_steps_signalled;

extern struct list_head cachepc_faults;

extern struct cacheline *cachepc_ds;

extern uint64_t cachepc_regs_tmp[16];
extern uint64_t cachepc_regs_vm[16];
