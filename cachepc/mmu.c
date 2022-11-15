#include "../cachepc/cachepc.h"
#include "../cachepc/track.h"
#include "../cachepc/event.h"

static void
cachepc_uspt_page_fault_handle(struct kvm_vcpu *vcpu,
	struct kvm_page_fault *fault)
{
	if (!kvm_slot_page_track_is_active(vcpu->kvm,
			fault->slot, fault->gfn, KVM_PAGE_TRACK_ACCESS))
		return;

	pr_warn("Sevstep: Tracked page fault (gfn:%llu err:%u)\n",
		fault->gfn, fault->error_code);
	//pr_warn("Sevstep: Tracked page fault attrs %i %i %i\n",
	//	fault->present, fault->write, fault->user);

	cachepc_untrack_single(vcpu, fault->gfn, KVM_PAGE_TRACK_ACCESS);

	if (cachepc_track_mode == CPC_TRACK_DATA_ACCESS) {
		if (cachepc_single_step && cachepc_inst_fault_avail) {
			/* second fault from data access */
			pr_warn("Sevstep: Got data fault gfn:%llu err:%u\n",
				fault->gfn, fault->error_code);

			cachepc_data_fault_gfn = fault->gfn;
			cachepc_data_fault_err = fault->error_code;
			cachepc_data_fault_avail = true;

			cachepc_apic_timer = 160;
		} else {
			/* first fault from instruction fetch */
			pr_warn("Sevstep: Got inst fault gfn:%llu err:%u\n",
				fault->gfn, fault->error_code);

			cachepc_inst_fault_gfn = fault->gfn;
			cachepc_inst_fault_err = fault->error_code;
			cachepc_inst_fault_avail = true;
			cachepc_data_fault_avail = false;

			cachepc_single_step = true;
			cachepc_apic_timer = 170;
		}
	} else if (cachepc_track_mode == CPC_TRACK_EXEC_PAGES) {
		/* TODO: skip if not exec */
		/* TODO: calculate retired instructions (save and subtract global counter) */
		if (cachepc_inst_fault_avail) {
			cachepc_track_single(vcpu, cachepc_inst_fault_gfn,
				KVM_PAGE_TRACK_ACCESS);
		}
		cachepc_inst_fault_gfn = fault->gfn;
		cachepc_inst_fault_err = fault->error_code;
		cachepc_send_tracking_event(fault->gfn, fault->error_code, 0, 0);
	} else if (cachepc_track_mode == CPC_TRACK_ACCESS) {
		cachepc_track_single(vcpu, fault->gfn, KVM_PAGE_TRACK_ACCESS);
		cachepc_send_tracking_event(fault->gfn, fault->error_code, 0, 0);
	}
}

bool
cachepc_spte_protect(u64 *sptep, bool pt_protect, enum kvm_page_track_mode mode)
{
	u64 spte;
	bool flush;

	// pr_warn("Sevstep: spte_protect\n");

	spte = *sptep;
	if (!is_writable_pte(spte) && !(pt_protect && is_mmu_writable_spte(spte)))
		return false;

	rmap_printk("spte %p %llx\n", sptep, *sptep);

	if (pt_protect)
		spte &= ~shadow_mmu_writable_mask;

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

	// pr_warn("Sevstep: spte_protect flush:%i\n", flush);

	return flush;
}
EXPORT_SYMBOL(cachepc_spte_protect);

bool cachepc_rmap_protect(struct kvm_rmap_head *rmap_head,
	bool pt_protect, enum kvm_page_track_mode mode)
{
	struct rmap_iterator iter;
	bool flush;
	u64 *sptep;

	flush = false;
	for_each_rmap_spte(rmap_head, &iter, sptep) {
		flush |= cachepc_spte_protect(sptep, pt_protect, mode);
	}

	return flush;
}
EXPORT_SYMBOL(cachepc_rmap_protect);

bool
cachepc_kvm_mmu_slot_gfn_protect(struct kvm *kvm, struct kvm_memory_slot *slot,
	uint64_t gfn, int min_level, enum kvm_page_track_mode mode)
{
	struct kvm_rmap_head *rmap_head;
	bool protected;
	int i;

	protected = false;

	// pr_warn("Sevstep: mmu_slot_gfn_protect gfn:%llu\n", gfn);

	if (kvm_memslots_have_rmaps(kvm)) {
		for (i = min_level; i <= KVM_MAX_HUGEPAGE_LEVEL; ++i) {
			rmap_head = gfn_to_rmap(gfn, i, slot);
			protected |= cachepc_rmap_protect(rmap_head, true, mode);
		}
	} else if (is_tdp_mmu_enabled(kvm)) {
		protected |= cachepc_tdp_protect_gfn(kvm,
			slot, gfn, min_level, mode);
	} else {
		pr_err("CachePC: Tracking unsupported!\n");
	}

	return true;
	//return protected;
}
EXPORT_SYMBOL(cachepc_kvm_mmu_slot_gfn_protect);

