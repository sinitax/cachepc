#pragma once 

#include <linux/kernel.h>

void random_perm(uint32_t *arr, uint32_t arr_len);
void gen_random_indices(uint32_t *arr, uint32_t arr_len);

bool is_in_arr(uint32_t elem, uint32_t *arr, uint32_t arr_len);
