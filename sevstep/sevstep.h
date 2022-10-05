#pragma once

#include <linux/types.h>
#include <linux/spinlock_types.h>
#include <asm/atomic.h>
#include <linux/kvm_types.h>
#include <asm/kvm_page_track.h>

#include <linux/kvm_host.h>
#include <linux/pid.h>
#include <linux/psp-sev.h>

#define CTL_MSR_0  0xc0010200ULL
#define CTL_MSR_1  0xc0010202ULL
#define CTL_MSR_2  0xc0010204ULL
#define CTL_MSR_3  0xc0010206ULL
#define CTL_MSR_4  0xc0010208ULL
#define CTL_MSR_5  0xc001020aULL

#define CTR_MSR_0  0xc0010201ULL
#define CTR_MSR_1  0xc0010203ULL
#define CTR_MSR_2  0xc0010205ULL
#define CTR_MSR_3  0xc0010207ULL
#define CTR_MSR_4  0xc0010209ULL
#define CTR_MSR_5  0xc001020bULL

typedef struct {
	uint64_t HostGuestOnly;
	uint64_t CntMask;
	uint64_t Inv;
	uint64_t En;
	uint64_t Int;
	uint64_t Edge;
	uint64_t OsUserMode;
	uint64_t UintMask;
	uint64_t EventSelect; //12 bits in total split in [11:8] and [7:0]

} perf_ctl_config_t;

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

uint64_t perf_ctl_to_u64(perf_ctl_config_t *config);
void write_ctl(perf_ctl_config_t *config, int cpu, uint64_t ctl_msr);
void read_ctr(uint64_t ctr_msr, int cpu, uint64_t *result);

void sevstep_setup_pmcs(void);

int sevstep_get_rip_kvm_vcpu(struct kvm_vcpu *vcpu, uint64_t *rip);
