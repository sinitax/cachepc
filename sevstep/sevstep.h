#pragma once

#include <linux/types.h>
#include <linux/spinlock_types.h>
#include <asm/atomic.h>
#include <linux/kvm_types.h>
#include <asm/kvm_page_track.h>

#include <linux/kvm_host.h>
#include <linux/pid.h>
#include <linux/psp-sev.h>

extern struct kvm* main_vm;

bool sevstep_spte_protect(u64 *sptep,
	bool pt_protect, enum kvm_page_track_mode mode);
bool sevstep_rmap_protect(struct kvm_rmap_head *rmap_head,
	bool pt_protect, enum kvm_page_track_mode mode);
bool sevstep_kvm_mmu_slot_gfn_protect(struct kvm *kvm, struct kvm_memory_slot *slot,
	uint64_t gfn, int min_level, enum kvm_page_track_mode mode);

bool sevstep_untrack_single_page(struct kvm_vcpu *vcpu, gfn_t gfn,
	enum kvm_page_track_mode mode);
bool sevstep_track_single_page(struct kvm_vcpu *vcpu, gfn_t gfn,
	enum kvm_page_track_mode mode);
bool sevstep_reset_accessed_on_page(struct kvm_vcpu *vcpu, gfn_t gfn);
bool sevstep_clear_nx_on_page(struct kvm_vcpu *vcpu, gfn_t gfn);

long sevstep_start_tracking(struct kvm_vcpu *vcpu, enum kvm_page_track_mode mode);
long sevstep_stop_tracking(struct kvm_vcpu *vcpu, enum kvm_page_track_mode mode);

void sevstep_setup_pmcs(void);

int sevstep_get_rip_kvm_vcpu(struct kvm_vcpu *vcpu, uint64_t *rip);
