#include "../cachepc/cachepc.h"
#include "../cachepc/track.h"
#include "../cachepc/event.h"
#include "svm/svm.h"

static bool
cachepc_page_fault_handle(struct kvm_vcpu *vcpu,
	struct kvm_page_fault *fault)
{
	int modes[] = {
		KVM_PAGE_TRACK_EXEC,
		KVM_PAGE_TRACK_ACCESS,
	};
	struct cpc_fault *tmp, *alloc;
	size_t count, i;
	bool inst_fetch;

	/* return true if the page fault was related to tracking and should not be handled,
	 * return false if the page fault should be handled */

	for (i = 0; i < 2; i++) {
		if (kvm_slot_page_track_is_active(vcpu->kvm,
				fault->slot, fault->gfn, modes[i]))
			break;
	}
	if (i == 2) {
		CPC_INFO("Untracked page fault (gfn:%llu err:%u)\n",
			fault->gfn, fault->error_code);
		return false;
	}

	CPC_DBG("Tracked page fault (gfn:%llu err:%u)\n",
		fault->gfn, fault->error_code);

	inst_fetch = fault->error_code & PFERR_FETCH_MASK;
	CPC_DBG("Tracked page fault attrs p:%i w:%i x:%i f:%i\n",
		fault->present, inst_fetch, fault->write, fault->exec);

	count = 0;
	list_for_each_entry(tmp, &cachepc_faults, list)
		count += 1;

	if (cachepc_track_mode == CPC_TRACK_FULL) {
		CPC_INFO("Got %lu. fault gfn:%llu err:%u\n", count + 1,
			fault->gfn, fault->error_code);

		cachepc_untrack_single(vcpu, fault->gfn, modes[i]);

		alloc = kmalloc(sizeof(struct cpc_fault), GFP_KERNEL);
		BUG_ON(!alloc);
		alloc->gfn = fault->gfn;
		alloc->err = fault->error_code;
		list_add_tail(&alloc->list, &cachepc_faults);

		cachepc_single_step = true;
		cachepc_apic_timer = 0;
	} else if (cachepc_track_mode == CPC_TRACK_EXEC) {
		if (!inst_fetch || !fault->present) return false;

		if (count == 1) {
			return false; /* dont untrack, but 'handle' */
		}

		CPC_INFO("Got %lu. fault gfn:%llu err:%u\n", count + 1,
			fault->gfn, fault->error_code);

		cachepc_untrack_single(vcpu, fault->gfn, modes[i]);

		if (modes[i] != KVM_PAGE_TRACK_EXEC)
			CPC_WARN("Wrong page track mode for TRACK_EXEC");

		alloc = kmalloc(sizeof(struct cpc_fault), GFP_KERNEL);
		BUG_ON(!alloc);
		alloc->gfn = fault->gfn;
		alloc->err = fault->error_code;
		list_add_tail(&alloc->list, &cachepc_faults);

		cachepc_single_step = true;
		cachepc_apic_timer = 0;
	} else if (cachepc_track_mode == CPC_TRACK_STUB) {
		cachepc_send_track_step_event(&cachepc_faults);
	}

	return true;
}

bool
cachepc_spte_protect(u64 *sptep, bool pt_protect, enum kvm_page_track_mode mode)
{
	u64 spte;

	spte = *sptep;
	if (!is_writable_pte(spte) && !(pt_protect && is_mmu_writable_spte(spte)))
		return false;

	if (pt_protect)
		spte &= ~shadow_mmu_writable_mask;

	if (mode == KVM_PAGE_TRACK_WRITE) {
		spte &= ~PT_WRITABLE_MASK;
	} else if (mode == KVM_PAGE_TRACK_RESET_ACCESS) {
		spte &= ~PT_ACCESSED_MASK;
	} else if (mode == KVM_PAGE_TRACK_ACCESS) {
		spte &= ~PT_PRESENT_MASK;
		spte &= ~PT_WRITABLE_MASK;
		spte &= ~PT_USER_MASK;
		spte |= (0x1ULL << PT64_NX_SHIFT);
	} else if (mode == KVM_PAGE_TRACK_EXEC) {
		spte |= (0x1ULL << PT64_NX_SHIFT);
	} else if (mode == KVM_PAGE_TRACK_RESET_EXEC) {
		spte &= ~(0x1ULL << PT64_NX_SHIFT);
	}

	mmu_spte_update(sptep, spte);

	return true;
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
	bool flush;
	int i;

	flush = false;

	if (kvm_memslots_have_rmaps(kvm)) {
		for (i = min_level; i <= KVM_MAX_HUGEPAGE_LEVEL; ++i) {
			rmap_head = gfn_to_rmap(gfn, i, slot);
			flush |= cachepc_rmap_protect(rmap_head, true, mode);
		}
	} else if (is_tdp_mmu_enabled(kvm)) {
		flush |= cachepc_tdp_protect_gfn(kvm, slot, gfn, min_level, mode);
	} else {
		CPC_ERR("Tracking unsupported!\n");
	}

	return flush;
}
EXPORT_SYMBOL(cachepc_kvm_mmu_slot_gfn_protect);

