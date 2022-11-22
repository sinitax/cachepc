#include "track.h"
#include "cachepc.h"

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

bool
cachepc_track_single(struct kvm_vcpu *vcpu, gfn_t gfn,
	enum kvm_page_track_mode mode)
{
	struct kvm_memory_slot *slot;
	int idx;

	idx = srcu_read_lock(&vcpu->kvm->srcu);

	slot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);
	if (slot != NULL && !kvm_slot_page_track_is_active(vcpu->kvm, slot, gfn, mode)) {
		write_lock(&vcpu->kvm->mmu_lock);
		kvm_slot_page_track_add_page(vcpu->kvm, slot, gfn, mode);
		write_unlock(&vcpu->kvm->mmu_lock);
	}

	srcu_read_unlock(&vcpu->kvm->srcu, idx);

	if (!slot) pr_err("Sevstep: Failed to track gfn %llu\n", gfn);

	return slot != NULL;
}
EXPORT_SYMBOL(cachepc_track_single);

bool
cachepc_untrack_single(struct kvm_vcpu *vcpu, gfn_t gfn,
	enum kvm_page_track_mode mode)
{
	struct kvm_memory_slot *slot;
	int idx;

	idx = srcu_read_lock(&vcpu->kvm->srcu);

	slot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);
	if (slot != NULL && kvm_slot_page_track_is_active(vcpu->kvm, slot, gfn, mode)) {
		write_lock(&vcpu->kvm->mmu_lock);
		kvm_slot_page_track_remove_page(vcpu->kvm, slot, gfn, mode);
		write_unlock(&vcpu->kvm->mmu_lock);
	}

	srcu_read_unlock(&vcpu->kvm->srcu, idx);

	if (!slot) pr_err("Sevstep: Failed to untrack gfn %llu\n", gfn);

	return slot != NULL;
}
EXPORT_SYMBOL(cachepc_untrack_single);

long
cachepc_track_all(struct kvm_vcpu *vcpu, enum kvm_page_track_mode mode)
{
	struct kvm_memory_slot *slot;
	struct kvm_memslots *slots;
	long count = 0;
	int bkt;
	u64 gfn;

	pr_warn("Sevstep: Start tracking (mode:%i)\n", mode);

	slots = kvm_vcpu_memslots(vcpu);
	kvm_for_each_memslot(slot, bkt, slots) {
		pr_warn("Sevstep: Slot page count: %lu\n", slot->npages);
		for (gfn = slot->base_gfn; gfn < slot->base_gfn + slot->npages; gfn++) {
			if (!kvm_slot_page_track_is_active(vcpu->kvm, slot, gfn, mode)) {
				write_lock(&vcpu->kvm->mmu_lock);
				kvm_slot_page_track_add_page(vcpu->kvm, slot, gfn, mode);
				write_unlock(&vcpu->kvm->mmu_lock);
				count++;
			}
		}
	}

	return count;
}
EXPORT_SYMBOL(cachepc_track_all);

long
cachepc_untrack_all(struct kvm_vcpu *vcpu, enum kvm_page_track_mode mode)
{
	struct kvm_memory_slot *slot;
	struct kvm_memslots *slots;
	long count = 0;
	int bkt;
	u64 gfn;

	pr_warn("Sevstep: Stop tracking (mode:%i)\n", mode);

	slots = kvm_vcpu_memslots(vcpu);
	kvm_for_each_memslot(slot, bkt, slots) {
		for (gfn = slot->base_gfn; gfn < slot->base_gfn + slot->npages; gfn++) {
			if (kvm_slot_page_track_is_active(vcpu->kvm, slot, gfn, mode)) {
				write_lock(&vcpu->kvm->mmu_lock);
				kvm_slot_page_track_remove_page(vcpu->kvm, slot, gfn, mode);
				write_unlock(&vcpu->kvm->mmu_lock);
				count++;
			}
		}
	}

	return count;
}
EXPORT_SYMBOL(cachepc_untrack_all);

