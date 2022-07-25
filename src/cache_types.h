#pragma once

#include "device_conf.h"

#include <linux/build_bug.h>

#define SET_MASK(SETS) (((((uintptr_t) SETS) * CACHELINE_SIZE) - 1) ^ (CACHELINE_SIZE - 1))

#define REMOVE_PAGE_OFFSET(ptr) ((void *) (((uintptr_t) ptr) & PAGE_MASK))

#define GET_BIT(b, i) (((b) >> (i)) & 1)
#define SET_BIT(b, i) ((b) | (1 << (i)))

/* Operate cacheline flags
 * Used flags:
 *  32                    2              1       0
 * |  | ... | cache group initialized | last | first |
 */
#define DEFAULT_FLAGS 0
#define SET_FIRST(flags) SET_BIT(flags, 0)
#define SET_LAST(flags) SET_BIT(flags, 1)
#define SET_CACHE_GROUP_INIT(flags) SET_BIT(flags, 2)
#define IS_FIRST(flags) GET_BIT(flags, 0)
#define IS_LAST(flags) GET_BIT(flags, 1)
#define IS_CACHE_GROUP_INIT(flags) GET_BIT(flags, 2)

// Offset of the next and prev field in the cacheline struct
#define CL_NEXT_OFFSET 0
#define CL_PREV_OFFSET 8

typedef enum cache_level cache_level;
typedef enum addressing_type addressing_type;
typedef struct cacheline cacheline;
typedef struct cache_ctx cache_ctx;

enum cache_level {L1, L2};
enum addressing_type {VIRTUAL, PHYSICAL};

struct cache_ctx {
    cache_level cache_level;
    addressing_type addressing;

    uint32_t sets;
    uint32_t associativity;
    uint32_t access_time;
    uint32_t nr_of_cachelines;
    uint32_t set_size;
    uint32_t cache_size;
};

struct cacheline {
    // Doubly linked list inside same set
    // Attention: CL_NEXT_OFFSET and CL_PREV_OFFSET
    // must be kept up to date
    cacheline *next;
    cacheline *prev;

    uint16_t cache_set;
    uint16_t flags;

    // Unused padding to fill cache line
    uint64_t count;
    char padding[32];
};

static_assert(sizeof(struct cacheline) == CACHELINE_SIZE, "Bad cache line struct size");
