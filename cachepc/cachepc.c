#include "cachepc.h"
#include "uapi.h"

#include "../../include/asm/processor.h"

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/ioctl.h>

#define SET_MASK(SETS) (((((uintptr_t) SETS) * L1_LINESIZE) - 1) ^ (L1_LINESIZE - 1))

#define REMOVE_PAGE_OFFSET(ptr) ((void *) (((uintptr_t) ptr) & PAGE_MASK))

#define MIN(a, b) ((a) < (b) ? (a) : (b))

static void *remove_cache_set(cache_ctx *ctx, void *ptr);

static cacheline *prepare_cache_set_ds(cache_ctx *ctx, uint32_t *set, uint32_t sets_len);
static cacheline *build_cache_ds(cache_ctx *ctx, cacheline **cacheline_ptr_arr);
static void build_randomized_list_for_cache_set(cache_ctx *ctx, cacheline **cacheline_ptr_arr);
static cacheline **allocate_cache_ds(cache_ctx *ctx);
static uint16_t get_virt_cache_set(cache_ctx *ctx, void *ptr);

static void random_perm(uint32_t *arr, uint32_t arr_len);
static void gen_random_indices(uint32_t *arr, uint32_t arr_len);
static bool is_in_arr(uint32_t elem, uint32_t *arr, uint32_t arr_len);

bool
cachepc_verify_topology(void)
{
	uint32_t assoc, linesize;
	uint32_t size, sets;
	uint32_t val;

	if (PAGE_SIZE != L1_SETS * L1_LINESIZE)
		CPC_ERR("System pagesize does not guarentee "
			"virtual memory access will hit corresponding "
			"physical cacheline, PAGE_SIZE != L1_SETS * L1_LINESIZE");

	/* REF: PPR Family 19h Model 01h Vol 1/2 Rev 0.50 May 27.2021 P.94 */
	val = native_cpuid_ecx(0x80000005);
	size = ((val >> 24) & 0xFF) * 1024;
	assoc = (val >> 16) & 0xFF;
	linesize = val & 0xFF;
	sets = size / (linesize * assoc);
	if (size != L1_SIZE || assoc != L1_ASSOC
			|| linesize != L1_LINESIZE || sets != L1_SETS) {
		CPC_ERR("L1 topology is invalid!\n");
		CPC_ERR("L1_SIZE (expected) %u vs. (real) %u\n",
			L1_SIZE, size);
		CPC_ERR("L1_ASSOC (expected) %u vs. (real) %u\n",
			L1_ASSOC, assoc);
		CPC_ERR("L1_LINESIZE (expected) %u vs. (real) %u\n",
			L1_LINESIZE, linesize);
		CPC_ERR("L1_SETS (expected) %u vs. (real) %u\n",
			L1_SETS, sets);
		return true;
	}

	/* REF: PPR Family 19h Model 01h Vol 1/2 Rev 0.50 May 27.2021 P.94 */
	val = native_cpuid_ecx(0x80000006);
	size = ((val >> 16) & 0xFFFF) * 1024;
	assoc = (val >> 12) & 0xF;
	linesize = val & 0xFF;
	switch (assoc) {
	case 0x1:
	case 0x2:
	case 0x4:
		break;
	case 0x6:
		assoc = 8;
		break;
	case 0x8:
		assoc = 16;
		break;
	case 0xA:
		assoc = 32;
		break;
	case 0xB:
		assoc = 48;
		break;
	case 0xC:
		assoc = 64;
		break;
	case 0xD:
		assoc = 96;
		break;
	case 0xE:
		assoc = 128;
		break;
	case 0xF:
		assoc = size / linesize;
		break;
	default:
		CPC_ERR("Read invalid L2 associativity: %i\n", assoc);
		return true;
	}
	sets = size / (linesize * assoc);
	if (size != L2_SIZE || assoc != L2_ASSOC
			|| linesize != L2_LINESIZE || sets != L2_SETS) {
		CPC_ERR("L2 topology is invalid!\n");
		CPC_ERR("L2_SIZE (expected) %u vs. (real) %u\n",
			L2_SIZE, size);
		CPC_ERR("L2_ASSOC (expected) %u vs. (real) %u\n",
			L2_ASSOC, assoc);
		CPC_ERR("L2_LINESIZE (expected) %u vs. (real) %u\n",
			L2_LINESIZE, linesize);
		CPC_ERR("L2_SETS (expected) %u vs. (real) %u\n",
			L2_SETS, sets);
		return true;
	}

	return false;
}

void
cachepc_write_msr(uint64_t addr, uint64_t clear_bits, uint64_t set_bits)
{
	uint64_t val, newval;

	val = __rdmsr(addr);
	val &= ~clear_bits;
	val |= set_bits;
	native_wrmsrl(addr, val);

	newval = __rdmsr(addr);
	if (val != newval) {
		CPC_ERR("Write MSR at %08llX failed (%08llx vs %08llx)\n",
			addr, val, newval);
	}
}

void
cachepc_init_pmc(uint8_t index, uint8_t event_no, uint8_t event_mask,
	uint8_t host_guest, uint8_t kernel_user)
{
	uint64_t event;

	/* REF: PPR Family 19h Model 01h Vol 1/2 Rev 0.50 May 27.2021 P.166 */

	WARN_ON(index >= 6);
	if (index >= 6) return;

	event = event_no | (event_mask << 8);
	event |= (1ULL << 22); /* enable performance counter */
	event |= ((kernel_user & 0b11) * 1ULL) << 16;
	event |= ((host_guest & 0b11) * 1ULL) << 40;

	// CPC_INFO("Initializing %i. PMC %02X:%02X (%016llx)\n",
	// 	index, event_no, event_mask, event);
	cachepc_write_msr(0xc0010200 + index * 2, ~0ULL, event);
}

void
cachepc_reset_pmc(uint8_t index)
{
	WARN_ON(index >= 6);
	if (index >= 6) return;

	cachepc_write_msr(0xc0010201 + index * 2, ~0ULL, 0);
}

cache_ctx *
cachepc_get_ctx(void)
{
	cache_ctx *ctx;

	ctx = kzalloc(sizeof(cache_ctx), GFP_KERNEL);
	BUG_ON(ctx == NULL);

	ctx->sets = L1_SETS;
	ctx->associativity = L1_ASSOC;
	ctx->nr_of_cachelines = ctx->sets * ctx->associativity;
	ctx->set_size = L1_LINESIZE * ctx->associativity;
	ctx->cache_size = ctx->sets * ctx->set_size;

	return ctx;
}

void
cachepc_release_ctx(cache_ctx *ctx)
{
	kfree(ctx);
}

/* initialises the complete cache data structure for the given context */
cacheline *
cachepc_prepare_ds(cache_ctx *ctx)
{
	cacheline **cacheline_ptr_arr;
	cacheline *cache_ds;

       	cacheline_ptr_arr = allocate_cache_ds(ctx);
	cache_ds = build_cache_ds(ctx, cacheline_ptr_arr);
	kfree(cacheline_ptr_arr);

	return cache_ds;
}

void
cachepc_release_ds(cache_ctx *ctx, cacheline *ds)
{
	kfree(remove_cache_set(ctx, ds));
}

cacheline *
cachepc_prepare_victim(cache_ctx *ctx, uint32_t set)
{
	cacheline *victim_set, *victim_cl;

	victim_set = prepare_cache_set_ds(ctx, &set, 1);
	victim_cl = victim_set;

	return victim_cl;
}

void
cachepc_release_victim(cache_ctx *ctx, cacheline *victim)
{
	kfree(remove_cache_set(ctx, victim));
}

void *
cachepc_aligned_alloc(size_t alignment, size_t size)
{
	void *p;

	if (size % alignment != 0)
		size = size - (size % alignment) + alignment;
	p = kzalloc(size, GFP_KERNEL);
	BUG_ON(!p || ((uintptr_t) p) % alignment != 0);

	return p;
}

void
cachepc_save_msrmts(cacheline *head)
{
	cacheline *curr_cl;
	size_t i;

	curr_cl = head;
	do {
		if (CL_IS_FIRST(curr_cl->flags)) {
			BUG_ON(curr_cl->cache_set >= L1_SETS);
			WARN_ON(curr_cl->count > L1_ASSOC);
			cachepc_msrmts[curr_cl->cache_set] = curr_cl->count;
		} else {
			BUG_ON(curr_cl->count != 0);
		}

		curr_cl = curr_cl->prev;
	} while (curr_cl != head);

	if (cachepc_baseline_measure) {
		for (i = 0; i < L1_SETS; i++) {
			cachepc_baseline[i] = MIN(cachepc_baseline[i],
				cachepc_msrmts[i]);
		}
	}

	if (cachepc_baseline_active) {
		for (i = 0; i < L1_SETS; i++) {
			if (!cachepc_baseline_active)
				WARN_ON(cachepc_msrmts[i] < cachepc_baseline[i]);
			cachepc_msrmts[i] -= cachepc_baseline[i];
		}
	}
}

void
cachepc_print_msrmts(cacheline *head)
{
	cacheline *curr_cl;

	curr_cl = head;
	do {
		if (CL_IS_FIRST(curr_cl->flags)) {
			CPC_INFO("Count for cache set %i: %llu\n",
				curr_cl->cache_set, curr_cl->count);
		}

		curr_cl = curr_cl->prev;
	} while (curr_cl != head);
}

cacheline *
prepare_cache_set_ds(cache_ctx *ctx, uint32_t *sets, uint32_t sets_len)
{
	cacheline *cache_ds, **first_cl_in_sets, **last_cl_in_sets;
	cacheline *to_del_cls, *curr_cl, *next_cl, *cache_set_ds;
	uint32_t i, cache_groups_len, cache_groups_max_len;
	uint32_t *cache_groups;
       
	cache_ds = cachepc_prepare_ds(ctx);

	first_cl_in_sets = kzalloc(ctx->sets * sizeof(cacheline *), GFP_KERNEL);
	BUG_ON(first_cl_in_sets == NULL);

	last_cl_in_sets  = kzalloc(ctx->sets * sizeof(cacheline *), GFP_KERNEL);
	BUG_ON(last_cl_in_sets == NULL);

	/* find the cache groups that are used, so that we can delete the
	 * other ones later (to avoid memory leaks) */
	cache_groups_max_len = ctx->sets / CACHE_GROUP_SIZE;
	cache_groups = kmalloc(cache_groups_max_len * sizeof(uint32_t), GFP_KERNEL);
	BUG_ON(cache_groups == NULL);

	cache_groups_len = 0;
	for (i = 0; i < sets_len; ++i) {
		if (!is_in_arr(sets[i] / CACHE_GROUP_SIZE, cache_groups, cache_groups_len)) {
			cache_groups[cache_groups_len] = sets[i] / CACHE_GROUP_SIZE;
			++cache_groups_len;
		}
	}

	to_del_cls = NULL;
	curr_cl = cache_ds;

	/* extract the partial data structure for the cache sets and
	 * ensure correct freeing */
	do {
		next_cl = curr_cl->next;

		if (CL_IS_FIRST(curr_cl->flags)) {
			first_cl_in_sets[curr_cl->cache_set] = curr_cl;
		}
		if (CL_IS_LAST(curr_cl->flags)) {
			last_cl_in_sets[curr_cl->cache_set] = curr_cl;
		}

		curr_cl = next_cl;

	} while (curr_cl != cache_ds);

	/* fix partial cache set ds */
	for (i = 0; i < sets_len; ++i) {
		last_cl_in_sets[sets[i]]->next = first_cl_in_sets[sets[(i + 1) % sets_len]];
		first_cl_in_sets[sets[(i + 1) % sets_len]]->prev = last_cl_in_sets[sets[i]];
	}
	cache_set_ds = first_cl_in_sets[sets[0]];

	kfree(first_cl_in_sets);
	kfree(last_cl_in_sets);
	kfree(cache_groups);

	return cache_set_ds;
}

void *
remove_cache_set(cache_ctx *ctx, void *ptr)
{
	return (void *) (((uintptr_t) ptr) & ~SET_MASK(ctx->sets));
}

/*
 * Create a randomized doubly linked list with the following structure:
 * set A <--> set B <--> ... <--> set X <--> set A
 * where each set is one of the cache sets, in a random order.
 * The sets are a doubly linked list of cachelines themselves:
 * set A:
 *  line[A + x0 * #sets] <--> line[A + x1 * #sets] <--> ...
 * where x0, x1, ..., xD is a random permutation of 1, 2, ..., D
 * and D = Associativity = | cache set |
 */
cacheline *
build_cache_ds(cache_ctx *ctx, cacheline **cl_ptr_arr) {
	cacheline **first_cl_in_sets, **last_cl_in_sets;
	cacheline **cl_ptr_arr_sorted;
	cacheline *curr_cl;
	cacheline *cache_ds;
	uint32_t *idx_per_set;
	uint32_t idx_curr_set, set_offset;
	uint32_t i, j, set, set_len;
	uint32_t *idx_map;

 	idx_per_set = kzalloc(ctx->sets * sizeof(uint32_t), GFP_KERNEL);
	BUG_ON(idx_per_set == NULL);

	cl_ptr_arr_sorted = kzalloc(ctx->nr_of_cachelines * sizeof(cacheline *), GFP_KERNEL);
	BUG_ON(cl_ptr_arr_sorted == NULL);

	set_len = ctx->associativity;
	for (i = 0; i < ctx->nr_of_cachelines; ++i) {
		set_offset = cl_ptr_arr[i]->cache_set * set_len;
		idx_curr_set = idx_per_set[cl_ptr_arr[i]->cache_set];

		cl_ptr_arr_sorted[set_offset + idx_curr_set] = cl_ptr_arr[i];
		idx_per_set[cl_ptr_arr[i]->cache_set] += 1;
	}

	/* build doubly linked list for every set */
	for (set = 0; set < ctx->sets; ++set) {
		set_offset = set * set_len;
		build_randomized_list_for_cache_set(ctx, cl_ptr_arr_sorted + set_offset);
	}

	/* relink the sets among each other */
	idx_map = kzalloc(ctx->sets * sizeof(uint32_t), GFP_KERNEL);
	BUG_ON(idx_map == NULL);

	gen_random_indices(idx_map, ctx->sets);

	first_cl_in_sets = kzalloc(ctx->sets * sizeof(cacheline *), GFP_KERNEL);
	BUG_ON(first_cl_in_sets == NULL);

	last_cl_in_sets  = kzalloc(ctx->sets * sizeof(cacheline *), GFP_KERNEL);
	BUG_ON(last_cl_in_sets == NULL);

	for (j = 0; j < ctx->nr_of_cachelines; ++j) {
		curr_cl = cl_ptr_arr_sorted[j];
		if (CL_IS_FIRST(curr_cl->flags))
			first_cl_in_sets[curr_cl->cache_set] = curr_cl;
		if (CL_IS_LAST(curr_cl->flags))
			last_cl_in_sets[curr_cl->cache_set] = curr_cl;
	}

	/* connect up sets */
	for (i = 0; i < ctx->sets; ++i) {
		last_cl_in_sets[idx_map[i]]->next = first_cl_in_sets[idx_map[(i + 1) % ctx->sets]];
		first_cl_in_sets[idx_map[(i + 1) % ctx->sets]]->prev = last_cl_in_sets[idx_map[i]];
	}
	cache_ds = first_cl_in_sets[idx_map[0]];

	kfree(cl_ptr_arr_sorted);
	kfree(first_cl_in_sets);
	kfree(last_cl_in_sets);
	kfree(idx_per_set);
	kfree(idx_map);

	return cache_ds;
}

/*
 * Helper function to build a randomised list of cacheline structs for a set
 */
void
build_randomized_list_for_cache_set(cache_ctx *ctx, cacheline **cacheline_ptr_arr)
{
	cacheline *curr_cl;
	uint32_t len, *idx_map;
	uint16_t i;

	len = ctx->associativity;
	idx_map = kzalloc(len * sizeof(uint32_t), GFP_KERNEL);
	BUG_ON(idx_map == NULL);

	gen_random_indices(idx_map, len);

	for (i = 0; i < len; ++i) {
		curr_cl = cacheline_ptr_arr[idx_map[i]];
		curr_cl->next = cacheline_ptr_arr[idx_map[(i + 1) % len]];
		curr_cl->prev = cacheline_ptr_arr[idx_map[(len - 1 + i) % len]];

		if (idx_map[i] == 0) {
			curr_cl->flags = CL_SET_FIRST(CL_DEFAULT_FLAGS);
			curr_cl->prev->flags = CL_SET_LAST(CL_DEFAULT_FLAGS);
		} else {
			curr_cl->flags |= CL_DEFAULT_FLAGS;
		}
	}

	kfree(idx_map);
}

/*
 * Allocate a data structure that fills the complete cache, i.e. consisting
 * of `associativity` many cache lines for each cache set.
 */
cacheline **
allocate_cache_ds(cache_ctx *ctx)
{
	cacheline **cl_ptr_arr, *cl_arr;
	uint32_t i;

	cl_ptr_arr = kzalloc(ctx->nr_of_cachelines * sizeof(cacheline *), GFP_KERNEL);
	BUG_ON(cl_ptr_arr == NULL);

	cl_arr = cachepc_aligned_alloc(PAGE_SIZE, ctx->cache_size);
	for (i = 0; i < ctx->nr_of_cachelines; ++i) {
		cl_ptr_arr[i] = cl_arr + i;
		cl_ptr_arr[i]->cache_set = get_virt_cache_set(ctx, cl_ptr_arr[i]);
		cl_ptr_arr[i]->cache_line = i / ctx->sets;
		cl_ptr_arr[i]->count = 0;
	}

	return cl_ptr_arr;
}

uint16_t
get_virt_cache_set(cache_ctx *ctx, void *ptr)
{
	return (uint16_t) ((((uintptr_t) ptr) & SET_MASK(ctx->sets)) / L1_LINESIZE);
}

void
random_perm(uint32_t *arr, uint32_t arr_len)
{
	uint32_t i;

	/* no special ordering needed when prefetcher is disabled */
	for (i = 0; i < arr_len; i++)
		arr[i] = i;

	// /* prevent stream prefetching by alternating access direction */
	// mid = arr_len / 2;
	// for (i = 0; i < arr_len; i++)
	// 	arr[i] = mid + (i % 2 ? -1 : 1) * ((i + 1) / 2);
}

void
gen_random_indices(uint32_t *arr, uint32_t arr_len)
{
	uint32_t i;

	for (i = 0; i < arr_len; ++i)
		arr[i] = i;
	random_perm(arr, arr_len);
}

bool
is_in_arr(uint32_t elem, uint32_t *arr, uint32_t arr_len)
{
	uint32_t i;

	for (i = 0; i < arr_len; ++i) {
		if (arr[i] == elem)
			return true;
	}

	return false;
}

void
cachepc_apic_oneshot_run(uint32_t interval)
{
	native_apic_mem_write(APIC_LVTT, LOCAL_TIMER_VECTOR | APIC_LVT_TIMER_ONESHOT);
	native_apic_mem_write(APIC_TDCR, APIC_TDR_DIV_1);
	native_apic_mem_write(APIC_TMICT, interval);
}
