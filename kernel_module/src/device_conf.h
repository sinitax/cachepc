#pragma once

// TODO: Read from kernel headers

// General settings
// #define PAGE_SIZE 4096
#define PROCESSOR_FREQ 2900000000

// Cache related settings
#define CACHELINE_SIZE 64
#define CACHE_GROUP_SIZE (PAGE_SIZE / CACHELINE_SIZE)

// Addressing:
// - virtual:   0
// - physical:  1
#define L1_ADDRESSING 0
#define L1_SETS 64
#define L1_ASSOCIATIVITY 8
#define L1_ACCESS_TIME 4

#define L2_ADDRESSING 1
#define L2_SETS 512
#define L2_ASSOCIATIVITY 8
#define L2_ACCESS_TIME 12

#define L3_ADDRESSING 1
#define L3_SETS 4096
#define L3_ASSOCIATIVITY 16
#define L3_ACCESS_TIME 30
