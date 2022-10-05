#include "sevstep.h"

#include "mmu/mmu_internal.h"
#include "mmu.h"

#include "irq.h"
#include "ioapic.h"
#include "mmu.h"
#include "mmu/tdp_mmu.h"
#include "x86.h"
#include "kvm_cache_regs.h"
#include "kvm_emulate.h"
#include "cpuid.h"
#include "mmu/spte.h"


#include <linux/kvm_host.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/moduleparam.h>
#include <linux/export.h>
#include <linux/swap.h>
#include <linux/hugetlb.h>
#include <linux/compiler.h>
#include <linux/srcu.h>
#include <linux/slab.h>
#include <linux/sched/signal.h>
#include <linux/uaccess.h>
#include <linux/hash.h>
#include <linux/kern_levels.h>
#include <linux/kthread.h>
#include <linux/sev.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/sched.h>

#include "kvm_cache_regs.h"
#include "svm/svm.h"

struct kvm* main_vm;
EXPORT_SYMBOL(main_vm);

// used to store performance counter values; 6 counters, 2 readings per counter
// TODO: static!
uint64_t perf_reads[6][2];
perf_ctl_config_t perf_configs[6];
int perf_cpu;


uint64_t
perf_ctl_to_u64(perf_ctl_config_t * config)
{
	uint64_t result;

	result = 0;
	result |= config->EventSelect & 0xffULL;
	result |= (config->UintMask & 0xffULL) << 8;
	result |= (config->OsUserMode & 0x3ULL) << 16;
	result |= (config->Edge & 0x1ULL ) << 18;
	result |= (config->Int & 0x1ULL ) << 20;
	result |= (config->En & 0x1ULL ) << 22;
	result |= (config->Inv & 0x1ULL ) << 23;
	result |= (config->CntMask & 0xffULL) << 24;
	result |= ((config->EventSelect & 0xf00ULL) >> 8) << 32;
	result |= (config->HostGuestOnly & 0x3ULL) << 40;

	return result;

}

void
write_ctl(perf_ctl_config_t * config, int cpu, uint64_t ctl_msr)
{
	wrmsrl_on_cpu(cpu, ctl_msr, perf_ctl_to_u64(config));
}

void
read_ctr(uint64_t ctr_msr, int cpu, uint64_t* result)
{
	uint64_t tmp;

	rdmsrl_on_cpu(cpu, ctr_msr, &tmp);
	*result = tmp & ( (0x1ULL << 48) - 1);
}

void
setup_perfs()
{
	int i;

	perf_cpu = smp_processor_id();

	for (i = 0; i < 6; i++) {
		perf_configs[i].HostGuestOnly = 0x1; /* count only guest */
		perf_configs[i].CntMask = 0x0;
		perf_configs[i].Inv = 0x0;
		perf_configs[i].En = 0x0;
		perf_configs[i].Int = 0x0;
		perf_configs[i].Edge = 0x0;
		perf_configs[i].OsUserMode = 0x3; /* count userland and kernel events */
	}

	perf_configs[0].EventSelect = 0x0c0;
	perf_configs[0].UintMask = 0x0;
	perf_configs[0].En = 0x1;
	write_ctl(&perf_configs[0],perf_cpu, CTL_MSR_0);

	/*
	 * programm l2d hit from data cache miss perf for
	 * cpu_probe_pointer_chasing_inplace without counting thread.
	 * N.B. that this time we count host events
	 */
	perf_configs[1].EventSelect = 0x064;
	perf_configs[1].UintMask = 0x70;
	perf_configs[1].En = 0x1;
	perf_configs[1].HostGuestOnly = 0x2; /* count only host events */
	write_ctl(&perf_configs[1],perf_cpu,CTL_MSR_1);
}
EXPORT_SYMBOL(setup_perfs);

int
sev_step_get_rip_kvm_vcpu(struct kvm_vcpu* vcpu,uint64_t *rip)
{
	return 0;
}
