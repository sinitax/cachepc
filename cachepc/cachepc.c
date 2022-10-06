#include "cachepc.h"

#include <linux/kernel.h>
#include <linux/types.h> 
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/ioctl.h>

#define SET_MASK(SETS) (((((uintptr_t) SETS) * CACHELINE_SIZE) - 1) ^ (CACHELINE_SIZE - 1))

#define REMOVE_PAGE_OFFSET(ptr) ((void *) (((uintptr_t) ptr) & PAGE_MASK))

static void cl_insert(cacheline *last_cl, cacheline *new_cl);
static void *remove_cache_set(cache_ctx *ctx, void *ptr);
static void *remove_cache_group_set(void *ptr);

static cacheline *prepare_cache_set_ds(cache_ctx *ctx, uint32_t *set, uint32_t sets_len);
static cacheline *build_cache_ds(cache_ctx *ctx, cacheline **cacheline_ptr_arr);
static void build_randomized_list_for_cache_set(cache_ctx *ctx, cacheline **cacheline_ptr_arr);
static cacheline **allocate_cache_ds(cache_ctx *ctx);
static uint16_t get_virt_cache_set(cache_ctx *ctx, void *ptr);

static void random_perm(uint32_t *arr, uint32_t arr_len);
static void gen_random_indices(uint32_t *arr, uint32_t arr_len);
static bool is_in_arr(uint32_t elem, uint32_t *arr, uint32_t arr_len);

void
cachepc_init_pmc(uint8_t index, uint8_t event_no, uint8_t event_mask,
	int host_guest, int kernel_user)
{
	uint64_t event;
	uint64_t reg_addr;

	/* REF: https://developer.amd.com/resources/developer-guides-manuals (PPR 17H 31H, P.166)
	 *
	 * performance event selection via 0xC001_020X with X = (0..A)[::2]
	 * performance event reading viea 0XC001_020X with X = (1..B)[::2]
	 */

	WARN_ON(index >= 6);
	if (index >= 6) return;

	reg_addr = 0xc0010200 + index * 2;
	event = event_no | (event_mask << 8);
	event |= (1ULL << 22); /* enable performance counter */
	event |= ((kernel_user & 0b11) * 1ULL) << 16;
	event |= ((host_guest & 0b11) * 1ULL) << 40;
	printk(KERN_WARNING "CachePC: Initialized %i. PMC %02X:%02X\n",
		index, event_no, event_mask);
	asm volatile ("wrmsr" : : "c"(reg_addr), "a"(event), "d"(0x00));
}

cache_ctx *
cachepc_get_ctx(int cache_level)
{
	cache_ctx *ctx;
       
	ctx = kzalloc(sizeof(cache_ctx), GFP_KERNEL);
	BUG_ON(ctx == NULL);

	BUG_ON(cache_level != L1_CACHE);
	if (cache_level == L1_CACHE) {
		ctx->addressing = L1_ADDRESSING;
		ctx->sets = L1_SETS;
		ctx->associativity = L1_ASSOCIATIVITY;
		ctx->access_time = L1_ACCESS_TIME;
	} else if (cache_level == L2_CACHE) {
		ctx->addressing = L2_ADDRESSING;
		ctx->sets = L2_SETS;
		ctx->associativity = L2_ASSOCIATIVITY;
		ctx->access_time = L2_ACCESS_TIME;
	} else {
		return NULL;
	}

	ctx->cache_level = cache_level;
	ctx->nr_of_cachelines = ctx->sets * ctx->associativity;
	ctx->set_size = CACHELINE_SIZE * ctx->associativity;
	ctx->cache_size = ctx->sets * ctx->set_size;

	return ctx;
}

void
cachepc_release_ctx(cache_ctx *ctx)
{
	kfree(ctx);
}


/*
 * Initialises the complete cache data structure for the given context
 */
cacheline *
cachepc_prepare_ds(cache_ctx *ctx)
{
	cacheline **cacheline_ptr_arr;
	cacheline *cache_ds;

	//printk(KERN_WARNING "CachePC: Preparing ds..\n");
	
       	cacheline_ptr_arr = allocate_cache_ds(ctx);
	cache_ds = build_cache_ds(ctx, cacheline_ptr_arr);
	kfree(cacheline_ptr_arr);

	// printk(KERN_WARNING "CachePC: Preparing ds done\n");

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
	cacheline *curr_cl, *next_cl;

	victim_set = prepare_cache_set_ds(ctx, &set, 1);
	victim_cl = victim_set;

	// Free the other lines in the same set that are not used.
	if (ctx->addressing == PHYSICAL_ADDRESSING) {
		curr_cl = victim_cl->next;
		do {
			next_cl = curr_cl->next;
			// Here, it is ok to free them directly, as every line in the same
			// set is from a different page anyway.
			kfree(remove_cache_group_set(curr_cl));
			curr_cl = next_cl;
		} while(curr_cl != victim_cl);
	}

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
	BUG_ON(((uintptr_t) p) % alignment != 0);

	return p;
}

void
cachepc_save_msrmts(cacheline *head)
{
	cacheline *curr_cl;

	// printk(KERN_WARNING "CachePC: Updating /proc/cachepc\n");

	curr_cl = head;
	do {
		if (CL_IS_FIRST(curr_cl->flags)) {
			BUG_ON(curr_cl->cache_set >= cachepc_msrmts_count);
			cachepc_msrmts[curr_cl->cache_set] = curr_cl->count;
		}

		curr_cl = curr_cl->prev;
	} while (curr_cl != head);
}

void
cachepc_print_msrmts(cacheline *head)
{
	cacheline *curr_cl;

	curr_cl = head;
	do {
		if (CL_IS_FIRST(curr_cl->flags)) {
			printk(KERN_WARNING "CachePC: Count for cache set %i: %llu\n",
				curr_cl->cache_set, curr_cl->count);
		}

		curr_cl = curr_cl->prev;
	} while (curr_cl != head);
}

void __attribute__((optimize(1))) // prevent instruction reordering
cachepc_prime_vcall(uintptr_t ret, cacheline *cl)
{
	cachepc_prime(cl);
	asm volatile ("mov %0, %%rax; jmp *%%rax" : : "r"(ret) : "rax");
}

void __attribute__((optimize(1))) // prevent instruction reordering
cachepc_probe_vcall(uintptr_t ret, cacheline *cl)
{
	cachepc_probe(cl);
	asm volatile ("mov %0, %%rax; jmp *%%rax" : : "r"(ret) : "rax");
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

	// Find the cache groups that are used, so that we can delete the other ones
	// later (to avoid memory leaks)
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

	// Extract the partial data structure for the cache sets and ensure correct freeing
	do {
		next_cl = curr_cl->next;

		if (CL_IS_FIRST(curr_cl->flags)) {
			first_cl_in_sets[curr_cl->cache_set] = curr_cl;
		}
		if (CL_IS_LAST(curr_cl->flags)) {
			last_cl_in_sets[curr_cl->cache_set] = curr_cl;
		}

		if (ctx->addressing == PHYSICAL_ADDRESSING && !is_in_arr(
			curr_cl->cache_set / CACHE_GROUP_SIZE, cache_groups, cache_groups_len))
		{
			// Already free all unused blocks of the cache ds for physical
			// addressing, because we loose their refs
			cl_insert(to_del_cls, curr_cl);
			to_del_cls = curr_cl;
		}
		curr_cl = next_cl;

	} while (curr_cl != cache_ds);

	// Fix partial cache set ds
	for (i = 0; i < sets_len; ++i) {
		last_cl_in_sets[sets[i]]->next = first_cl_in_sets[sets[(i + 1) % sets_len]];
		first_cl_in_sets[sets[(i + 1) % sets_len]]->prev = last_cl_in_sets[sets[i]];
	}
	cache_set_ds = first_cl_in_sets[sets[0]];

	// Free unused cache lines
	if (ctx->addressing == PHYSICAL_ADDRESSING) {
		cachepc_release_ds(ctx, to_del_cls);
	}

	kfree(first_cl_in_sets);
	kfree(last_cl_in_sets);
	kfree(cache_groups);

	return cache_set_ds;
}

void 
cl_insert(cacheline *last_cl, cacheline *new_cl)
{
    if (last_cl == NULL) {
        // Adding the first entry is a special case
        new_cl->next = new_cl;
        new_cl->prev = new_cl;
    } else {
        new_cl->next = last_cl->next;
        new_cl->prev = last_cl;
        last_cl->next->prev = new_cl;
        last_cl->next = new_cl;
    }
}

void *
remove_cache_set(cache_ctx *ctx, void *ptr)
{
	return (void *) (((uintptr_t) ptr) & ~SET_MASK(ctx->sets));
}

void *
remove_cache_group_set(void *ptr)
{
	return (void *) (((uintptr_t) ptr) & ~SET_MASK(CACHE_GROUP_SIZE));
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
cacheline *build_cache_ds(cache_ctx *ctx, cacheline **cl_ptr_arr) {
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

	// Build doubly linked list for every set
	for (set = 0; set < ctx->sets; ++set) {
		set_offset = set * set_len;
		build_randomized_list_for_cache_set(ctx, cl_ptr_arr_sorted + set_offset);
	}

	// Relink the sets among each other
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
void build_randomized_list_for_cache_set(cache_ctx *ctx, cacheline **cacheline_ptr_arr)
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

	BUG_ON(ctx->addressing != VIRTUAL_ADDRESSING);

	// For virtual addressing, allocating a consecutive chunk of memory is enough
	cl_arr = cachepc_aligned_alloc(PAGE_SIZE, ctx->cache_size);
	BUG_ON(cl_arr == NULL);

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
	return (uint16_t) ((((uintptr_t) ptr) & SET_MASK(ctx->sets)) / CACHELINE_SIZE);
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


bool is_in_arr(uint32_t elem, uint32_t *arr, uint32_t arr_len) {
	uint32_t i;

	for (i = 0; i < arr_len; ++i) {
		if (arr[i] == elem)
			return true;
	}

	return false;
}
