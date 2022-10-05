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

static perf_ctl_config_t perf_configs[6];

uint64_t
perf_ctl_to_u64(perf_ctl_config_t * config)
{
	uint64_t result;

	result = 0;
	result |= config->EventSelect & 0xffULL;
	result |= (config->UintMask & 0xffULL) << 8;
	result |= (config->OsUserMode & 0x3ULL) << 16;
	result |= (config->Edge & 0x1ULL) << 18;
	result |= (config->Int & 0x1ULL) << 20;
	result |= (config->En & 0x1ULL) << 22;
	result |= (config->Inv & 0x1ULL) << 23;
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
sevstep_setup_pmcs(void)
{
	int perf_cpu;
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
	write_ctl(&perf_configs[0], perf_cpu, CTL_MSR_0);

	/*
	 * programm l2d hit from data cache miss perf for
	 * cpu_probe_pointer_chasing_inplace without counting thread.
	 * N.B. that this time we count host events
	 */
	perf_configs[1].EventSelect = 0x064;
	perf_configs[1].UintMask = 0x70;
	perf_configs[1].En = 0x1;
	perf_configs[1].HostGuestOnly = 0x2; /* count only host events */
	write_ctl(&perf_configs[1], perf_cpu, CTL_MSR_1);
}
EXPORT_SYMBOL(sevstep_setup_pmcs);

bool
sevstep_untrack_single_page(struct kvm_vcpu *vcpu, gfn_t gfn,
	enum kvm_page_track_mode mode)
{
	int idx;
	bool ret;
	struct kvm_memory_slot *slot;

	ret = false;
	idx = srcu_read_lock(&vcpu->kvm->srcu);
	if (mode == KVM_PAGE_TRACK_ACCESS) {
		//printk("Removing gfn: %016llx from acess page track pool\n", gfn);
	}
	if (mode == KVM_PAGE_TRACK_WRITE) {
		//printk("Removing gfn: %016llx from write page track pool\n", gfn);
	}
	slot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);

	if (slot != NULL && kvm_slot_page_track_is_active(vcpu->kvm, slot, gfn, mode)) {
		write_lock(&vcpu->kvm->mmu_lock);
		kvm_slot_page_track_remove_page(vcpu->kvm, slot, gfn, mode);
		write_unlock(&vcpu->kvm->mmu_lock);
		ret = true;
	} else {
		printk("Failed to untrack %016llx because ", gfn);
		if (slot == NULL) {
			printk(KERN_CONT "slot was	null");
		} else if (!kvm_slot_page_track_is_active(vcpu->kvm, slot, gfn, mode)) {
			printk(KERN_CONT "page track was not active");
		}
		printk(KERN_CONT "\n");
	}
	srcu_read_unlock(&vcpu->kvm->srcu, idx);
	return ret;
}
EXPORT_SYMBOL(sevstep_untrack_single_page);

bool
sevstep_reset_accessed_on_page(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	int idx;
	bool ret;
	struct kvm_memory_slot *slot;

	ret = false;
	idx = srcu_read_lock(&vcpu->kvm->srcu);
	slot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);
	if( slot != NULL ) {
		write_lock(&vcpu->kvm->mmu_lock);
		//Vincent: The kvm mmu function now requires min_level
		//We want all pages to protected so we do PG_LEVEL_4K
		//https://patchwork.kernel.org/project/kvm/patch/20210416082511.2856-2-zhukeqian1@huawei.com/
		sevstep_kvm_mmu_slot_gfn_protect(vcpu->kvm,slot,gfn,PG_LEVEL_4K,KVM_PAGE_TRACK_RESET_ACCESSED);
		write_unlock(&vcpu->kvm->mmu_lock);
		ret = true;
	}
	srcu_read_unlock(&vcpu->kvm->srcu, idx);
	return ret;
}
EXPORT_SYMBOL(sevstep_reset_accessed_on_page);

bool
sevstep_clear_nx_on_page(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	int idx;
	bool ret;
	struct kvm_memory_slot *slot;

	ret = false;
	idx = srcu_read_lock(&vcpu->kvm->srcu);
	slot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);
	if( slot != NULL ) {
		write_lock(&vcpu->kvm->mmu_lock);
		//Vincent: The kvm mmu function now requires min_level
		//We want all pages to protected so we do PG_LEVEL_4K
		//https://patchwork.kernel.org/project/kvm/patch/20210416082511.2856-2-zhukeqian1@huawei.com/
		sevstep_kvm_mmu_slot_gfn_protect(vcpu->kvm, slot, gfn,
			PG_LEVEL_4K, KVM_PAGE_TRACK_RESET_EXEC);
		write_unlock(&vcpu->kvm->mmu_lock);
		ret = true;
	}
	srcu_read_unlock(&vcpu->kvm->srcu, idx);
	return ret;
}
EXPORT_SYMBOL(sevstep_clear_nx_on_page);

bool
sevstep_track_single_page(struct kvm_vcpu *vcpu, gfn_t gfn,
	enum kvm_page_track_mode mode)
{
	int idx;
	bool ret;
	struct kvm_memory_slot *slot;

	ret = false;
	idx = srcu_read_lock(&vcpu->kvm->srcu);
	if (mode == KVM_PAGE_TRACK_ACCESS) {
		//printk_ratelimited("Adding gfn: %016llx to acess page track pool\n", gfn);
		//printk("Adding gfn: %016llx to acess page track pool\n", gfn);
	}
	if (mode == KVM_PAGE_TRACK_WRITE) {
		//printk_ratelimited("Adding gfn: %016llx to write page track pool\n", gfn);
	}
	slot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);
	if (slot != NULL && !kvm_slot_page_track_is_active(vcpu->kvm,slot, gfn, mode)) {

		write_lock(&vcpu->kvm->mmu_lock);
		kvm_slot_page_track_add_page(vcpu->kvm, slot, gfn, mode);
		write_unlock(&vcpu->kvm->mmu_lock);
		ret = true;

	} else {

		printk("Failed to track %016llx because ", gfn);
		if (slot == NULL) {
			printk(KERN_CONT "slot was	null");
		}
		if (kvm_slot_page_track_is_active(vcpu->kvm, slot, gfn, mode)) {
			printk(KERN_CONT "page is already tracked");
		}
		printk(KERN_CONT "\n");
	}
	srcu_read_unlock(&vcpu->kvm->srcu, idx);
	return ret;
}
EXPORT_SYMBOL(sevstep_track_single_page);

long
sevstep_start_tracking(struct kvm_vcpu *vcpu, enum kvm_page_track_mode mode)
{
	long count = 0;
	u64 iterator, iterat_max;
	struct kvm_memory_slot *slot;
	int idx;

	//Vincent: Memslots interface changed into a rb tree, see
	//here: https://lwn.net/Articles/856392/
	//and here: https://lore.kernel.org/all/cover.1632171478.git.maciej.szmigiero@oracle.com/T/#u
	//Thus we use instead of
	//iterat_max = vcpu->kvm->memslots[0]->memslots[0].base_gfn
	//	     + vcpu->kvm->memslots[0]->memslots[0].npages;
	struct rb_node *node;
	struct kvm_memory_slot *first_memslot;
	node = rb_last(&(vcpu->kvm->memslots[0]->gfn_tree));
	first_memslot = container_of(node, struct kvm_memory_slot, gfn_node[0]);
	iterat_max = first_memslot->base_gfn + first_memslot->npages;
	for (iterator = 0; iterator < iterat_max; iterator++)
	{
		idx = srcu_read_lock(&vcpu->kvm->srcu);
		slot = kvm_vcpu_gfn_to_memslot(vcpu, iterator);
		if (slot != NULL && !kvm_slot_page_track_is_active(vcpu->kvm, slot, iterator, mode)) {
			write_lock(&vcpu->kvm->mmu_lock);
			kvm_slot_page_track_add_page(vcpu->kvm, slot, iterator, mode);
			write_unlock(&vcpu->kvm->mmu_lock);
			count++;
		}
		srcu_read_unlock(&vcpu->kvm->srcu, idx);
	}

	return count;
}
EXPORT_SYMBOL(sevstep_start_tracking);

long
sevstep_stop_tracking(struct kvm_vcpu *vcpu, enum kvm_page_track_mode mode)
{
	long count = 0;
	u64 iterator, iterat_max;
	struct kvm_memory_slot *slot;
	int idx;


	//Vincent: Memslots interface changed into a rb tree, see
	//here: https://lwn.net/Articles/856392/
	//and here: https://lore.kernel.org/all/cover.1632171478.git.maciej.szmigiero@oracle.com/T/#u
	//Thus we use instead of
	//iterat_max = vcpu->kvm->memslots[0]->memslots[0].base_gfn
	//	     + vcpu->kvm->memslots[0]->memslots[0].npages;
	struct rb_node *node;
	struct kvm_memory_slot *first_memslot;
	node = rb_last(&(vcpu->kvm->memslots[0]->gfn_tree));
	first_memslot = container_of(node, struct kvm_memory_slot, gfn_node[0]);
	iterat_max = first_memslot->base_gfn + first_memslot->npages;
	for (iterator=0; iterator < iterat_max; iterator++)
	{
		idx = srcu_read_lock(&vcpu->kvm->srcu);
		slot = kvm_vcpu_gfn_to_memslot(vcpu, iterator);
			//Vincent: I think see here https://patchwork.kernel.org/project/kvm/patch/20210924163152.289027-22-pbonzini@redhat.com/
			if ( slot != NULL && kvm_slot_page_track_is_active(vcpu->kvm, slot, iterator, mode)) {
				write_lock(&vcpu->kvm->mmu_lock);
				kvm_slot_page_track_remove_page(vcpu->kvm, slot, iterator, mode);
				write_unlock(&vcpu->kvm->mmu_lock);
				count++;
		}
		srcu_read_unlock(&vcpu->kvm->srcu, idx);
	}

	return count;
}
EXPORT_SYMBOL(sevstep_stop_tracking);

int
sevstep_get_rip_kvm_vcpu(struct kvm_vcpu *vcpu, uint64_t *rip)
{
	return 0;
}
