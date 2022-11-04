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

/* defined in mmu.c as they rely on static mmu-internal functions */
bool sevstep_spte_protect(u64 *sptep,
	bool pt_protect, enum kvm_page_track_mode mode);
bool sevstep_rmap_protect(struct kvm_rmap_head *rmap_head,
	bool pt_protect, enum kvm_page_track_mode mode);
bool sevstep_kvm_mmu_slot_gfn_protect(struct kvm *kvm, struct kvm_memory_slot *slot,
	uint64_t gfn, int min_level, enum kvm_page_track_mode mode);

bool sevstep_tdp_protect_gfn(struct kvm *kvm, struct kvm_memory_slot *slot,
	gfn_t gfn, int min_level, int mode);

bool sevstep_track_single(struct kvm_vcpu *vcpu, gfn_t gfn,
	enum kvm_page_track_mode mode);
bool sevstep_untrack_single(struct kvm_vcpu *vcpu, gfn_t gfn,
	enum kvm_page_track_mode mode);

long sevstep_track_all(struct kvm_vcpu *vcpu, enum kvm_page_track_mode mode);
long sevstep_untrack_all(struct kvm_vcpu *vcpu, enum kvm_page_track_mode mode);
