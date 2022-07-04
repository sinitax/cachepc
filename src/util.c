#include "util.h"

#include <linux/random.h>

void
random_perm(uint32_t *arr, uint32_t arr_len)
{
	uint32_t i, idx, tmp;

	for (i = arr_len - 1; i > 0; --i) {
		get_random_bytes(&idx, 4);
		idx = idx % i;

		tmp = arr[idx];
		arr[i] = arr[idx];
		arr[idx] = tmp;
	}
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
