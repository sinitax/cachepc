#include "kvm.h"

#include <linux/types.h>

bool
__untrack_single_page(struct kvm_vcpu *vcpu, gfn_t gfn,
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
EXPORT_SYMBOL(__untrack_single_page);

bool
__reset_accessed_on_page(struct kvm_vcpu *vcpu, gfn_t gfn)
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
EXPORT_SYMBOL(__reset_accessed_on_page);

bool
__clear_nx_on_page(struct kvm_vcpu *vcpu, gfn_t gfn)
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
EXPORT_SYMBOL(__clear_nx_on_page);

bool
__track_single_page(struct kvm_vcpu *vcpu, gfn_t gfn,
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
EXPORT_SYMBOL(__track_single_page);

long
kvm_start_tracking(struct kvm_vcpu *vcpu,enum kvm_page_track_mode mode )
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
		if ( slot != NULL  && !kvm_slot_page_track_is_active(vcpu->kvm, slot, iterator, mode)) {
			write_lock(&vcpu->kvm->mmu_lock);
			kvm_slot_page_track_add_page(vcpu->kvm, slot, iterator, mode);
			write_unlock(&vcpu->kvm->mmu_lock);
			count++;
		}
		srcu_read_unlock(&vcpu->kvm->srcu, idx);
	}

	return count;
}
EXPORT_SYMBOL(kvm_start_tracking);

long
kvm_stop_tracking(struct kvm_vcpu *vcpu,enum kvm_page_track_mode mode)
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
EXPORT_SYMBOL(kvm_stop_tracking);

