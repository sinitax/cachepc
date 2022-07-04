#include "cachepc.h"

static cacheline *build_cache_ds(cache_ctx *ctx, cacheline **cacheline_ptr_arr);
static void build_randomized_list_for_cache_set(cache_ctx *ctx, cacheline **cacheline_ptr_arr);
static cacheline **allocate_cache_ds(cache_ctx *ctx);
static uint16_t get_virt_cache_set(cache_ctx *ctx, void *ptr);
static void *aligned_alloc(size_t alignment, size_t size);

cache_ctx *
get_cache_ctx(cache_level cache_level)
{
	cache_ctx *ctx;
       
	ctx = kzalloc(sizeof(cache_ctx), GFP_KERNEL);
	BUG_ON(ctx == NULL);

	if (cache_level == L1) {
		ctx->addressing = L1_ADDRESSING;
		ctx->sets = L1_SETS;
		ctx->associativity = L1_ASSOCIATIVITY;
		ctx->access_time = L1_ACCESS_TIME;
	} else if (cache_level == L2) {
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

/*
 * Initialises the complete cache data structure for the given context
 */
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
cachepc_save_msrmt(cacheline *head, const char *prefix, int index)
{
	char filename[256];

	snprintf(filename, sizeof(filename), "%s.%i", prefix, index);

}

void
cache_print_msrmts(cacheline *head)
{
	cacheline *curr_cl;

	curr_cl = head;
	do {
		if (IS_FIRST(curr_cl->flags)) {
			printk(KERN_WARNING "Count for cache set %i: %llu\n",
				curr_cl->cache_set, curr_cl->count);
		}

		curr_cl = curr_cl->prev;
	} while (curr_cl != head);
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
	cacheline **cl_ptr_arr_sorted;
	cacheline *curr_cl, *next_cl;
	cacheline *cache_ds;
	uint32_t *idx_per_set;
	uint32_t idx_curr_set, set_offset;
	uint32_t i, j, set, set_len;
	uint32_t *idx_map;

 	idx_per_set = kzalloc(ctx->sets * sizeof(uint32_t), GFP_KERNEL);
	BUG_ON(idx_per_set == NULL);

	cl_ptr_arr_sorted  = kmalloc(ctx->nr_of_cachelines * sizeof(cacheline *), GFP_KERNEL);
	BUG_ON(cl_ptr_arr_sorted == NULL);

	set_len = ctx->associativity;
	for (i = 0; i < ctx->nr_of_cachelines; ++i) {
		set_offset      = cl_ptr_arr[i]->cache_set * set_len;
		idx_curr_set    = idx_per_set[cl_ptr_arr[i]->cache_set];

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

	curr_cl = cl_ptr_arr_sorted[idx_map[0] * set_len]->prev;
	for (j = 0; j < ctx->sets; ++j) {
		curr_cl->next = cl_ptr_arr_sorted[idx_map[(j + 1) % ctx->sets] * set_len];
		next_cl = curr_cl->next->prev;
		curr_cl->next->prev = curr_cl;
		curr_cl = next_cl;
	}

	cache_ds = cl_ptr_arr_sorted[idx_map[0] * set_len];

	kfree(cl_ptr_arr_sorted);
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
		curr_cl->count = 0;

		if (curr_cl == cacheline_ptr_arr[0]) {
			curr_cl->flags       = SET_FIRST(DEFAULT_FLAGS);
			curr_cl->prev->flags = SET_LAST(DEFAULT_FLAGS);
		} else {
			curr_cl->flags = curr_cl->flags | DEFAULT_FLAGS;
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

	cl_ptr_arr = (cacheline **) kzalloc(ctx->nr_of_cachelines * sizeof(cacheline *), GFP_KERNEL);
	BUG_ON(cl_ptr_arr == NULL);

	BUG_ON(ctx->addressing != VIRTUAL);

	// For virtual addressing, allocating a consecutive chunk of memory is enough
	cl_arr = (cacheline *) aligned_alloc(PAGE_SIZE, ctx->cache_size);
	BUG_ON(cl_arr == NULL);

	for (i = 0; i < ctx->nr_of_cachelines; ++i) {
		cl_ptr_arr[i] = cl_arr + i;
		cl_ptr_arr[i]->cache_set = get_virt_cache_set(ctx, cl_ptr_arr[i]);
	}

	return cl_ptr_arr;
}

uint16_t
get_virt_cache_set(cache_ctx *ctx, void *ptr)
{
	return (uint16_t) ((((uintptr_t) ptr) & SET_MASK(ctx->sets)) / CACHELINE_SIZE);
}

void *
aligned_alloc(size_t alignment, size_t size)
{
	void *p;

	if (size % alignment != 0)
		size = size - (size % alignment) + alignment;
	p = kmalloc(size, GFP_KERNEL);
	BUG_ON(((uintptr_t) p) % alignment != 0);

	return p;
}


