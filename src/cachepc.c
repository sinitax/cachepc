#include "cachepc.h"

static void cl_insert(cacheline *last_cl, cacheline *new_cl);
static void *remove_cache_set(cache_ctx *ctx, void *ptr);
static void *remove_cache_group_set(void *ptr);

static cacheline *prepare_cache_set_ds(cache_ctx *ctx, uint32_t *set, uint32_t sets_len);
static cacheline *build_cache_ds(cache_ctx *ctx, cacheline **cacheline_ptr_arr);
static void build_randomized_list_for_cache_set(cache_ctx *ctx, cacheline **cacheline_ptr_arr);
static cacheline **allocate_cache_ds(cache_ctx *ctx);
static uint16_t get_virt_cache_set(cache_ctx *ctx, void *ptr);
static void *aligned_alloc(size_t alignment, size_t size);

void
cachepc_init_counters(void)
{
	uint64_t event, event_no, event_mask;
	uint64_t reg_addr;

	/* SEE: https://developer.amd.com/resources/developer-guides-manuals (PPR 17H 31H, P.166)
	 *
	 * performance event selection is done via 0xC001_020X with X = (0..A)[::2]
	 * performance event reading is done viea 0XC001_020X with X = (1..B)[::2]
	 *
	 * 6 slots total
	 */
       
	reg_addr = 0xc0010200;
	event_no = 0x64;
	event_mask = 0x08;
	event = event_no | (event_mask << 8);
	event |= (1ULL << 17); /* OS (kernel) events only */
	event |= (1ULL << 22); /* enable performance counter */
	event |= (1ULL << 40); /* Host events only */
	printk(KERN_WARNING "CachePC: Initialized event %llu\n", event);
	asm volatile ("wrmsr" : : "c"(reg_addr), "a"(event), "d"(0x00));

	reg_addr = 0xc0010202;
	event_no = 0x64;
	event_mask = 0xF0;
	event = event_no | (event_mask << 8); 
	event |= (1ULL << 17); /* OS (kernel) events only */
	event |= (1ULL << 22); /* enable performance counter */
	event |= (1ULL << 40); /* Host events only */
	printk(KERN_WARNING "CachePC: Initialized event %llu\n", event);
	asm volatile ("wrmsr" : : "c"(reg_addr), "a"(event), "d"(0x00));
}

cache_ctx *
cachepc_get_ctx(cache_level cache_level)
{
	cache_ctx *ctx;

	// printk(KERN_WARNING "CachePC: Getting ctx..\n");
       
	ctx = kzalloc(sizeof(cache_ctx), GFP_KERNEL);
	BUG_ON(ctx == NULL);

	BUG_ON(cache_level != L1);
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

	// printk(KERN_WARNING "CachePC: Getting ctx done\n");

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
	if (ctx->addressing == PHYSICAL) {
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

void
cachepc_save_msrmts(cacheline *head)
{
	cacheline *curr_cl;

	curr_cl = head;
	do {
		if (IS_FIRST(curr_cl->flags)) {
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
		if (IS_FIRST(curr_cl->flags)) {
			printk(KERN_WARNING "CachePC: Count for cache set %i: %llu\n",
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

		if (IS_FIRST(curr_cl->flags)) {
			first_cl_in_sets[curr_cl->cache_set] = curr_cl;
		}
		if (IS_LAST(curr_cl->flags)) {
			last_cl_in_sets[curr_cl->cache_set] = curr_cl;
		}

		if (ctx->addressing == PHYSICAL && !is_in_arr(
			curr_cl->cache_set / CACHE_GROUP_SIZE, cache_groups, cache_groups_len))
		{
			// Already free all unused blocks of the cache ds for physical
			// addressing, because we loose their refs
			cl_insert(to_del_cls, curr_cl);
			to_del_cls = curr_cl;
		}
		curr_cl = next_cl;

	} while(curr_cl != cache_ds);

	// Fix partial cache set ds
	for (i = 0; i < sets_len; ++i) {
		last_cl_in_sets[sets[i]]->next = first_cl_in_sets[sets[(i + 1) % sets_len]];
		first_cl_in_sets[sets[(i + 1) % sets_len]]->prev = last_cl_in_sets[sets[i]];
	}
	cache_set_ds = first_cl_in_sets[sets[0]];

	// Free unused cache lines
	if (ctx->addressing == PHYSICAL) {
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
	cacheline **cl_ptr_arr_sorted;
	cacheline *curr_cl, *next_cl;
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

		if (idx_map[i] == 0) {
			curr_cl->flags = SET_FIRST(DEFAULT_FLAGS);
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

	cl_ptr_arr = kzalloc(ctx->nr_of_cachelines * sizeof(cacheline *), GFP_KERNEL);
	BUG_ON(cl_ptr_arr == NULL);

	BUG_ON(ctx->addressing != VIRTUAL);

	// For virtual addressing, allocating a consecutive chunk of memory is enough
	cl_arr = aligned_alloc(PAGE_SIZE, ctx->cache_size);
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
	p = kzalloc(size, GFP_KERNEL);
	BUG_ON(((uintptr_t) p) % alignment != 0);

	return p;
}

