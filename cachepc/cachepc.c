#include "cachepc.h"
#include "uapi.h"

#include "../../include/asm/processor.h"

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/ioctl.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))

EXPORT_SYMBOL(cachepc_read_pmc);

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

	return false;
}
EXPORT_SYMBOL(cachepc_verify_topology);

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
EXPORT_SYMBOL(cachepc_write_msr);

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

	CPC_DBG("Initializing %i. PMC %02X:%02X (%016llx)\n",
		index, event_no, event_mask, event);
	cachepc_write_msr(0xc0010200 + index * 2, ~0ULL, event);
}
EXPORT_SYMBOL(cachepc_init_pmc);

void
cachepc_reset_pmc(uint8_t index)
{
	WARN_ON(index >= 6);
	if (index >= 6) return;

	cachepc_write_msr(0xc0010201 + index * 2, ~0ULL, 0);
}
EXPORT_SYMBOL(cachepc_reset_pmc);

struct cacheline *
cachepc_ds_alloc(struct cacheline **cl_arr_out)
{
	struct cacheline **cl_ptr_arr;
	struct cacheline *cl_arr, *ds;
	size_t i, idx;

	cl_arr = cachepc_aligned_alloc(PAGE_SIZE, L1_SIZE);

	cl_ptr_arr = kzalloc(L1_LINES * sizeof(struct cacheline *), GFP_KERNEL);
	BUG_ON(cl_ptr_arr == NULL);

	/* order cachelines by set then line number */
	for (i = 0; i < L1_LINES; i++) {
		idx = (i % L1_SETS) * L1_ASSOC + i / L1_SETS;
		cl_ptr_arr[idx] = cl_arr + i;
		cl_ptr_arr[idx]->cache_set = i % L1_SETS;
		cl_ptr_arr[idx]->cache_line = i / L1_SETS;
		cl_ptr_arr[idx]->first = (i / L1_SETS) == 0;
		cl_ptr_arr[idx]->count = 0;
	}

	/* create doubly linked-list */
	for (i = 0; i < L1_LINES; i++) {
		cl_ptr_arr[i]->next = cl_ptr_arr[(i + L1_LINES + 1) % L1_LINES];
		cl_ptr_arr[i]->prev = cl_ptr_arr[(i + L1_LINES - 1) % L1_LINES];
	}

	*cl_arr_out = cl_arr;

	ds = cl_ptr_arr[0];

	kfree(cl_ptr_arr);

	return ds;
}
EXPORT_SYMBOL(cachepc_ds_alloc);

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
EXPORT_SYMBOL(cachepc_aligned_alloc);

void
cachepc_save_msrmts(struct cacheline *head)
{
	struct cacheline *cl;
	size_t i;

	cl = head;
	do {
		if (cl->first) {
			BUG_ON(cl->cache_set >= L1_SETS);
			WARN_ON(cl->count > L1_ASSOC);
			cachepc_msrmts[cl->cache_set] = cl->count;
		} else {
			BUG_ON(cl->count != 0);
		}
		cl->count = 0;

		cl = cl->prev;
	} while (cl != head);

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
EXPORT_SYMBOL(cachepc_save_msrmts);

void
cachepc_print_msrmts(struct cacheline *head)
{
	struct cacheline *cl;

	cl = head;
	do {
		if (cl->first) {
			CPC_INFO("Count for cache set %i: %llu\n",
				cl->cache_set, cl->count);
		}

		cl = cl->prev;
	} while (cl != head);
}
EXPORT_SYMBOL(cachepc_print_msrmts);

void
cachepc_apic_oneshot_run(uint32_t interval)
{
	native_apic_mem_write(APIC_LVTT, LOCAL_TIMER_VECTOR | APIC_LVT_TIMER_ONESHOT);
	native_apic_mem_write(APIC_TDCR, APIC_TDR_DIV_1);
	native_apic_mem_write(APIC_TMICT, interval);
}
EXPORT_SYMBOL(cachepc_apic_oneshot_run);
