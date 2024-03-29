#pragma once

#include "uapi.h"

#include "../../include/asm/apic.h"
#include "../../include/asm/irq_vectors.h"

#define PMC_KERNEL (1 << 1)
#define PMC_USER   (1 << 0)

#define PMC_HOST  (1 << 1)
#define PMC_GUEST (1 << 0)

#define CPC_L1MISS_PMC_INIT(pmc) \
	cpc_init_pmc(pmc, 0x60, 0b10000000, 0, PMC_KERNEL)

#define CPC_L1MISS_GUEST_PMC_INIT(pmc) \
	cpc_init_pmc(pmc, 0x60, 0b10000000, PMC_GUEST, PMC_USER | PMC_KERNEL)

#define CPC_RETINST_PMC_INIT(pmc) \
	cpc_init_pmc(pmc, 0xC0, 0x00, PMC_GUEST, PMC_USER | PMC_KERNEL)

#define CPC_RETINST_USER_PMC_INIT(pmc) \
	cpc_init_pmc(pmc, 0xC0, 0x00, PMC_GUEST, PMC_USER)

#define CPC_DBG(...) do { \
		if (cpc_loglevel >= CPC_LOGLVL_DBG) \
			pr_info("CachePC: " __VA_ARGS__); \
	} while (0)
#define CPC_INFO(...) do { \
		if (cpc_loglevel >= CPC_LOGLVL_INFO) \
			pr_info("CachePC: " __VA_ARGS__); \
	} while (0)
#define CPC_WARN(...) do { pr_warn("CachePC: " __VA_ARGS__); } while (0)
#define CPC_ERR(...) do { pr_err("CachePC: " __VA_ARGS__); } while (0)

struct cpc_cl {
	struct cpc_cl *next;
	struct cpc_cl *prev;
	uint64_t count;

	uint32_t set;
	uint32_t line;
	bool first;

	char padding[31];
};

struct cpc_fault {
	uint64_t gfn;
	uint32_t err;

	struct list_head list;
};

struct cpc_track_pages {
	bool singlestep_resolve;
	uint64_t retinst;
	uint64_t retinst_user;
	bool in_step;

	bool prev_avail;
	uint64_t prev_gfn;
	uint16_t prev_err;

	bool cur_avail;
	uint64_t cur_gfn;
	uint16_t cur_err;

	bool next_avail;
	uint64_t next_gfn;
	uint16_t next_err;
};

struct cpc_track_steps {
	bool with_data;
	bool use_target;
	bool target_user;
	uint64_t target_gfn;
	bool stepping;
	bool in_target;
	bool use_filter;
};

static_assert(sizeof(struct cpc_cl) == L1_LINESIZE, "Bad cacheline struct");
static_assert(CPC_CL_NEXT_OFFSET == offsetof(struct cpc_cl, next));
static_assert(CPC_CL_PREV_OFFSET == offsetof(struct cpc_cl, prev));
static_assert(CPC_CL_COUNT_OFFSET == offsetof(struct cpc_cl, count));

bool cpc_verify_topology(void);

void cpc_write_msr(uint64_t addr, uint64_t clear_bits, uint64_t set_bits);

void cpc_init_pmc(uint8_t index, uint8_t event_no, uint8_t event_mask,
	uint8_t host_guest, uint8_t kernel_user);
void cpc_reset_pmc(uint8_t index);

struct cpc_cl *cpc_ds_alloc(struct cpc_cl **ds_ul);

void *cpc_aligned_alloc(size_t alignment, size_t size);

void cpc_save_msrmts(struct cpc_cl *head);
void cpc_print_msrmts(struct cpc_cl *head);

struct cpc_cl *cpc_prime(struct cpc_cl *head);
void cpc_probe(struct cpc_cl *head);

uint64_t cpc_read_pmc(uint64_t event);

void cpc_apic_oneshot_run(uint32_t interval);

extern uint32_t cpc_loglevel;

extern uint8_t *cpc_msrmts;
extern uint8_t *cpc_baseline;
extern bool cpc_baseline_measure;
extern bool cpc_baseline_active;

extern uint32_t cpc_guest_misses;
extern uint32_t cpc_baseline_guest_misses;

extern uint32_t cpc_svm_exitcode;

extern bool cpc_pause_vm;

extern bool cpc_prime_probe;

extern bool cpc_singlestep;
extern bool cpc_singlestep_reset;
extern bool cpc_long_step;

extern bool cpc_apic_oneshot;
extern int32_t cpc_apic_timer;
extern int32_t cpc_apic_timer_softdiv;
extern int32_t cpc_apic_timer_min;
extern int32_t cpc_apic_timer_dec_npf;
extern int32_t cpc_apic_timer_dec_intr;

extern uint32_t cpc_track_mode;
extern uint64_t cpc_track_start_gfn;
extern uint64_t cpc_track_end_gfn;

extern uint64_t cpc_retinst;
extern uint64_t cpc_retinst_user;
extern uint64_t cpc_retinst_prev;

extern uint64_t cpc_rip;
extern uint64_t cpc_rip_prev;
extern bool cpc_rip_prev_set;

extern struct cpc_track_pages cpc_track_pages;
extern struct cpc_track_steps cpc_track_steps;

extern struct list_head cpc_faults;

extern struct cpc_cl *cpc_ds;
extern struct cpc_cl *cpc_ds_probe;
