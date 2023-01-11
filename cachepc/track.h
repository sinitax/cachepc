#pragma once

#include <linux/types.h>
#include <linux/spinlock_types.h>
#include <linux/srcu.h>
#include <linux/kvm_types.h>
#include <linux/kvm_host.h>
#include <linux/pid.h>
#include <linux/psp-sev.h>
#include <asm/kvm_page_track.h>
#include <asm/atomic.h>


extern struct kvm* main_vm;

bool cachepc_track_single(struct kvm_vcpu *vcpu, gfn_t gfn,
	enum kvm_page_track_mode mode);
bool cachepc_untrack_single(struct kvm_vcpu *vcpu, gfn_t gfn,
	enum kvm_page_track_mode mode);

long cachepc_track_all(struct kvm_vcpu *vcpu, enum kvm_page_track_mode mode);
long cachepc_untrack_all(struct kvm_vcpu *vcpu, enum kvm_page_track_mode mode);
