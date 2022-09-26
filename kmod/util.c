#include "util.h"

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
