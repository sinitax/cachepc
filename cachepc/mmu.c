#include "../cachepc/sevstep.h"
#include "../cachepc/uspt.h"

static void
sevstep_uspt_page_fault_handle(struct kvm_vcpu *vcpu,
	struct kvm_page_fault *fault)
{
	const int modes[] = {
		KVM_PAGE_TRACK_WRITE,
		KVM_PAGE_TRACK_ACCESS,
		KVM_PAGE_TRACK_EXEC
	};
	uint64_t current_rip;
	bool was_tracked;
	int have_rip, i;
	int send_err;

	was_tracked = false;
	for (i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
		if (kvm_slot_page_track_is_active(vcpu->kvm,
				fault->slot, fault->gfn, modes[i])) {
			sevstep_untrack_single_page(vcpu, fault->gfn, modes[i]);
			was_tracked = true;
		}
	}

	if (was_tracked) {
		have_rip = false;
		if (sevstep_uspt_should_get_rip())
			have_rip = sevstep_get_rip_kvm_vcpu(vcpu, &current_rip) == 0;
		if (sevstep_uspt_batch_tracking_in_progress()) {
			send_err = sevstep_uspt_batch_tracking_save(fault->gfn << PAGE_SHIFT,
				fault->error_code, have_rip, current_rip);
			if (send_err) {
				printk_ratelimited(
					"sevstep_uspt_batch_tracking_save failed with %d\n"
					"##########################\n", send_err);
			}
			sevstep_uspt_batch_tracking_handle_retrack(vcpu, fault->gfn);
			sevstep_uspt_batch_tracking_inc_event_idx();
		} else {
			send_err = sevstep_uspt_send_and_block(fault->gfn << PAGE_SHIFT,
				fault->error_code, have_rip, current_rip);
			if (send_err) {
				printk("sevstep_uspt_send_and_block failed with %d\n"
					"##########################\n", send_err);
			}
		}
	}
}

bool
sevstep_spte_protect(u64 *sptep, bool pt_protect, enum kvm_page_track_mode mode)
{
	u64 spte;
	bool flush;

	spte = *sptep;
	if (!is_writable_pte(spte) && !(pt_protect && is_mmu_writable_spte(spte)))
		return false;

	rmap_printk("spte %p %llx\n", sptep, *sptep);

	if (pt_protect)
		spte &= ~EPT_SPTE_MMU_WRITABLE;

	flush = false;
	if (mode == KVM_PAGE_TRACK_WRITE) {
		spte = spte & ~PT_WRITABLE_MASK;
		flush = true;
	} else if (mode == KVM_PAGE_TRACK_RESET_ACCESSED) {
		spte = spte & ~PT_ACCESSED_MASK;
	} else if (mode == KVM_PAGE_TRACK_ACCESS) {
		spte = spte & ~PT_PRESENT_MASK;
		spte = spte & ~PT_WRITABLE_MASK;
		spte = spte & ~PT_USER_MASK;
		spte = spte | (0x1ULL << PT64_NX_SHIFT);
		flush = true;
	} else if (mode == KVM_PAGE_TRACK_EXEC) {
		spte = spte | (0x1ULL << PT64_NX_SHIFT);
		flush = true;
	} else if (mode == KVM_PAGE_TRACK_RESET_EXEC) {
		spte = spte & ~(0x1ULL << PT64_NX_SHIFT);
		flush = true;
	} else {
		printk(KERN_WARNING "spte_protect was called with invalid mode"
			"parameter %d\n",mode);
	}
	flush |= mmu_spte_update(sptep, spte);

	return flush;
}
EXPORT_SYMBOL(sevstep_spte_protect);

bool sevstep_rmap_protect(struct kvm_rmap_head *rmap_head,
	bool pt_protect, enum kvm_page_track_mode mode)
{
	u64 *sptep;
	struct rmap_iterator iter;
	bool flush = false;

	for_each_rmap_spte(rmap_head, &iter, sptep) {
		flush |= sevstep_spte_protect(sptep, pt_protect, mode);
	}

	return flush;
}
EXPORT_SYMBOL(sevstep_rmap_protect);

bool
sevstep_kvm_mmu_slot_gfn_protect(struct kvm *kvm, struct kvm_memory_slot *slot,
	uint64_t gfn, int min_level, enum kvm_page_track_mode mode)
{
	struct kvm_rmap_head *rmap_head;
	bool protected;
	int i;

	protected = false;

	if (kvm_memslots_have_rmaps(kvm)) {
		for (i = min_level; i <= KVM_MAX_HUGEPAGE_LEVEL; ++i) {
			rmap_head = gfn_to_rmap(gfn, i, slot);
			protected |= sevstep_rmap_protect(rmap_head, true, mode);
		}
	}

	if (is_tdp_mmu_enabled(kvm)) {
		protected |= kvm_tdp_mmu_write_protect_gfn(kvm,
			slot, gfn, min_level);
	}

	return protected;
}
EXPORT_SYMBOL(sevstep_kvm_mmu_slot_gfn_protect);

