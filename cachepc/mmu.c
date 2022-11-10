#include "../cachepc/sevstep.h"
#include "../cachepc/cachepc.h"
#include "../cachepc/uspt.h"

static void
sevstep_uspt_page_fault_handle(struct kvm_vcpu *vcpu,
	struct kvm_page_fault *fault)
{
	int err;

	if (kvm_slot_page_track_is_active(vcpu->kvm,
			fault->slot, fault->gfn, KVM_PAGE_TRACK_ACCESS)) {
		pr_warn("Sevstep: Tracked page fault (gfn:%llu err:%u)\n",
			fault->gfn, fault->error_code);
		//pr_warn("Sevstep: Tracked page fault attrs %i %i %i\n",
		//	fault->present, fault->write, fault->user);

		sevstep_untrack_single(vcpu, fault->gfn, KVM_PAGE_TRACK_ACCESS);

		if (cachepc_track_single_step) {
			if (cachepc_single_step && cachepc_inst_fault_avail) {
				/* second fault from data access */
				pr_warn("Sevstep: Got data fault gfn:%llu err:%u\n",
					fault->gfn, fault->error_code);

				cachepc_data_fault_gfn = fault->gfn;
				cachepc_data_fault_err = fault->error_code;
				cachepc_data_fault_avail = true;

				cachepc_apic_timer = 170;
			} else {
				/* first fault from instruction fetch */
				pr_warn("Sevstep: Got inst fault gfn:%llu err:%u\n",
					fault->gfn, fault->error_code);

				cachepc_inst_fault_gfn = fault->gfn;
				cachepc_inst_fault_err = fault->error_code;
				cachepc_inst_fault_avail = true;
				cachepc_data_fault_avail = false;

				cachepc_single_step = true; /* TODO try inverse */
				cachepc_apic_timer = 130;
			}
		} else {
			sevstep_track_single(vcpu, fault->gfn, KVM_PAGE_TRACK_ACCESS);
			if (sevstep_uspt_send_and_block(fault->gfn, fault->error_code, 0, 0))
				pr_warn("Sevstep: uspt_send_and_block failed (%d)\n", err);
		}
	}
}

bool
sevstep_spte_protect(u64 *sptep, bool pt_protect, enum kvm_page_track_mode mode)
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
EXPORT_SYMBOL(sevstep_spte_protect);

bool sevstep_rmap_protect(struct kvm_rmap_head *rmap_head,
	bool pt_protect, enum kvm_page_track_mode mode)
{
	struct rmap_iterator iter;
	bool flush;
	u64 *sptep;

	flush = false;
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

	// pr_warn("Sevstep: mmu_slot_gfn_protect gfn:%llu\n", gfn);

	if (kvm_memslots_have_rmaps(kvm)) {
		for (i = min_level; i <= KVM_MAX_HUGEPAGE_LEVEL; ++i) {
			rmap_head = gfn_to_rmap(gfn, i, slot);
			protected |= sevstep_rmap_protect(rmap_head, true, mode);
		}
	} else if (is_tdp_mmu_enabled(kvm)) {
		protected |= sevstep_tdp_protect_gfn(kvm,
			slot, gfn, min_level, mode);
	} else {
		pr_err("CachePC: Tracking unsupported!\n");
	}

	return true;
	//return protected;
}
EXPORT_SYMBOL(sevstep_kvm_mmu_slot_gfn_protect);

