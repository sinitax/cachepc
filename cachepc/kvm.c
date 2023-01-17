#include "kvm.h"
#include "asm-generic/errno.h"
#include "uapi.h"
#include "cachepc.h"
#include "event.h"
#include "track.h"

#include "svm/svm.h"

#include <linux/psp-sev.h>
#include <linux/kvm_host.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/sev.h>
#include <linux/types.h>
#include <asm/uaccess.h>

bool cachepc_debug = false;
EXPORT_SYMBOL(cachepc_debug);

uint8_t *cachepc_msrmts = NULL;
EXPORT_SYMBOL(cachepc_msrmts);

uint8_t *cachepc_baseline = NULL;
bool cachepc_baseline_measure = false;
bool cachepc_baseline_active = false;
EXPORT_SYMBOL(cachepc_baseline);
EXPORT_SYMBOL(cachepc_baseline_measure);
EXPORT_SYMBOL(cachepc_baseline_active);

bool cachepc_pause_vm = false;
EXPORT_SYMBOL(cachepc_pause_vm);

uint64_t cachepc_retinst = 0;
uint64_t cachepc_retinst_prev = 0;
EXPORT_SYMBOL(cachepc_retinst);
EXPORT_SYMBOL(cachepc_retinst_prev);

uint64_t cachepc_rip = 0;
uint64_t cachepc_rip_prev = 0;
bool cachepc_rip_prev_set = false;
EXPORT_SYMBOL(cachepc_rip);
EXPORT_SYMBOL(cachepc_rip_prev);
EXPORT_SYMBOL(cachepc_rip_prev_set);

bool cachepc_single_step = false;
uint32_t cachepc_track_mode = false;
uint32_t cachepc_apic_timer = 0;
EXPORT_SYMBOL(cachepc_single_step);
EXPORT_SYMBOL(cachepc_track_mode);
EXPORT_SYMBOL(cachepc_apic_timer);

uint64_t cachepc_track_start_gfn = 0;
uint64_t cachepc_track_end_gfn = 0;
EXPORT_SYMBOL(cachepc_track_start_gfn);
EXPORT_SYMBOL(cachepc_track_end_gfn);

LIST_HEAD(cachepc_faults);
EXPORT_SYMBOL(cachepc_faults);

uint64_t cachepc_inst_fault_gfn = 0;
uint32_t cachepc_inst_fault_err = 0;
uint64_t cachepc_inst_fault_retinst = 0;
EXPORT_SYMBOL(cachepc_inst_fault_gfn);
EXPORT_SYMBOL(cachepc_inst_fault_err);
EXPORT_SYMBOL(cachepc_inst_fault_retinst);

cache_ctx *cachepc_ctx = NULL;
cacheline *cachepc_ds = NULL;
EXPORT_SYMBOL(cachepc_ctx);
EXPORT_SYMBOL(cachepc_ds);

uint64_t cachepc_regs_tmp[16];
uint64_t cachepc_regs_vm[16];
EXPORT_SYMBOL(cachepc_regs_tmp);
EXPORT_SYMBOL(cachepc_regs_vm);

uint64_t cachepc_last_event_sent;
uint64_t cachepc_last_event_acked;
DEFINE_RWLOCK(cachepc_event_lock);
EXPORT_SYMBOL(cachepc_last_event_sent);
EXPORT_SYMBOL(cachepc_last_event_acked);
EXPORT_SYMBOL(cachepc_event_lock);

struct cpc_event cachepc_event;
bool cachepc_event_avail;
EXPORT_SYMBOL(cachepc_event);
EXPORT_SYMBOL(cachepc_event_avail);

bool cachepc_events_init;
EXPORT_SYMBOL(cachepc_events_init);

static void cachepc_kvm_prime_probe_test(void *p);
static void cachepc_kvm_stream_hwpf_test(void *p);
static void cachepc_kvm_single_eviction_test(void *p);

static void cachepc_kvm_system_setup(void);

static int cachepc_kvm_reset_ioctl(void __user *arg_user);
static int cachepc_kvm_debug_ioctl(void __user *arg_user);

static int cachepc_kvm_test_eviction_ioctl(void __user *arg_user);

static int cachepc_kvm_read_counts_ioctl(void __user *arg_user);

static int cachepc_kvm_reset_baseline_ioctl(void __user *arg_user);
static int cachepc_kvm_calc_baseline_ioctl(void __user *arg_user);
static int cachepc_kvm_read_baseline_ioctl(void __user *arg_user);
static int cachepc_kvm_apply_baseline_ioctl(void __user *arg_user);

//static int cachepc_kvm_single_step_ioctl(void __user *arg_user);

static int cachepc_kvm_vmsa_read_ioctl(void __user *arg_user);
static int cachepc_kvm_svme_read_ioctl(void __user *arg_user);

static int cachepc_kvm_track_mode_ioctl(void __user *arg_user);
// static int cachepc_kvm_track_page_ioctl(void __user *arg_user);
// static int cachepc_kvm_track_all_ioctl(void __user *arg_user);
// static int cachepc_kvm_untrack_all_ioctl(void __user *arg_user);
static int cachepc_kvm_reset_tracking_ioctl(void __user *arg_user);
// static int cachepc_kvm_track_range_start_ioctl(void __user *arg_user);
// static int cachepc_kvm_track_range_end_ioctl(void __user *arg_user);
// static int cachepc_kvm_track_exec_cur_ioctl(void __user *arg_user);

static int cachepc_kvm_vm_pause_ioctl(void __user *arg_user);
static int cachepc_kvm_vm_resume_ioctl(void __user *arg_user);

static int cachepc_kvm_poll_event_ioctl(void __user *arg_user);
static int cachepc_kvm_ack_event_ioctl(void __user *arg_user);

void
cachepc_kvm_prime_probe_test(void *p)
{
	cacheline *lines;
	cacheline *cl, *head;
	uint32_t count;
	uint32_t *arg;
	int i, max;

	arg = p;

	/* l2 data cache hit & miss */
	cachepc_init_pmc(CPC_L1MISS_PMC, 0x64, 0xD8, PMC_HOST, PMC_KERNEL);

	lines = cachepc_aligned_alloc(PAGE_SIZE, cachepc_ctx->cache_size);

	max = cachepc_ctx->nr_of_cachelines;

	cachepc_cpuid();
	cachepc_mfence();

	for (i = 0; i < max; i++)
		asm volatile ("mov (%0), %%rbx" : : "r"(lines + i) : "rbx");

	head = cachepc_prime(cachepc_ds);
	cachepc_probe(head);

	count = 0;
	cl = head = cachepc_ds;
	do {
		count += cl->count;
		cl = cl->next;
	} while (cl != head);

	CPC_WARN("Prime-probe test done (%u vs. %u => %s)\n",
		count, 0, (count == 0) ? "passed" : "failed");

	if (arg) *arg = (count == 0);

	kfree(lines);
}

void
cachepc_kvm_stream_hwpf_test(void *p)
{
	cacheline *lines;
	uint32_t count;
	uint32_t *arg;
	uint32_t max;

	arg = p;

	/* l2 data cache hit & miss */
	cachepc_init_pmc(CPC_L1MISS_PMC, 0x64, 0xD8, PMC_HOST, PMC_KERNEL);

	lines = cachepc_aligned_alloc(PAGE_SIZE, cachepc_ctx->cache_size);

	max = 10;
	count = 0;
	cachepc_prime(cachepc_ds);

	count -= cachepc_read_pmc(CPC_L1MISS_PMC);
	asm volatile ("mov (%0), %%rbx" : : "r"(lines + 0) : "rbx");
	asm volatile ("mov (%0), %%rbx" : : "r"(lines + 1) : "rbx");
	asm volatile ("mov (%0), %%rbx" : : "r"(lines + 2) : "rbx");
	asm volatile ("mov (%0), %%rbx" : : "r"(lines + 3) : "rbx");
	asm volatile ("mov (%0), %%rbx" : : "r"(lines + 4) : "rbx");
	asm volatile ("mov (%0), %%rbx" : : "r"(lines + 5) : "rbx");
	asm volatile ("mov (%0), %%rbx" : : "r"(lines + 6) : "rbx");
	asm volatile ("mov (%0), %%rbx" : : "r"(lines + 7) : "rbx");
	asm volatile ("mov (%0), %%rbx" : : "r"(lines + 8) : "rbx");
	asm volatile ("mov (%0), %%rbx" : : "r"(lines + 9) : "rbx");
	count += cachepc_read_pmc(CPC_L1MISS_PMC);

	CPC_WARN("HWPF test done (%u vs. %u => %s)\n",
		count, max, count == max ? "passed" : "failed");

	if (arg) *arg = (count == max);

	kfree(lines);
}

void
cachepc_kvm_single_eviction_test(void *p)
{
	cacheline *head, *cl, *evicted;
        cacheline *ptr;
	uint32_t target;
	uint32_t *arg;
	int count;

	arg = p;

	/* l2 data cache hit & miss */
	cachepc_init_pmc(CPC_L1MISS_PMC, 0x64, 0xD8, PMC_HOST, PMC_KERNEL);

	WARN_ON(arg && *arg >= L1_SETS);
	if (arg && *arg >= L1_SETS) return;
	target = arg ? *arg : 48;

	ptr = cachepc_prepare_victim(cachepc_ctx, target);

	head = cachepc_prime(cachepc_ds);
	cachepc_victim(ptr);
	cachepc_probe(head);

	count = 0;
	evicted = NULL;
	cl = head = cachepc_ds;
	do {
		if (CL_IS_FIRST(cl->flags) && cl->count > 0) {
			evicted = cl;
			count += cl->count;
		}
		cl = cl->next;
	} while (cl != head);

	CPC_WARN("Single eviction test done (%u vs %u => %s)\n",
		count, 1, (count == 1 && evicted->cache_set == target)
			? "passed" : "failed");
	cachepc_save_msrmts(head);

	if (arg) *arg = count;

	cachepc_release_victim(cachepc_ctx, ptr);
}

void
cachepc_kvm_system_setup(void)
{
	uint64_t reg_addr, val;
	uint32_t lo, hi;

	/* NOTE: since most of these MSRs are poorly documented and some
	 * guessing work was involved, it is likely that one or more of
	 * these operations are not needed */

	/* disable streaming store */
	reg_addr = 0xc0011020;
	asm volatile ("rdmsr" : "=a"(lo), "=d"(hi) : "c"(reg_addr));
	val = (uint64_t) lo | ((uint64_t) hi << 32);
	val |= 1 << 13;
	CPC_WARN("Disabling streaming store (MSR %08llX: %016llX)\n",
		reg_addr, val);
	asm volatile ("wrmsr" : : "c"(reg_addr), "a"(val), "d"(0x00));

	/* disable speculative data cache tlb reloads */
	reg_addr = 0xc0011022;
	asm volatile ("rdmsr" : "=a"(lo), "=d"(hi) : "c"(reg_addr));
	val = (uint64_t) lo | ((uint64_t) hi << 32);
	val |= 1 << 4;
	CPC_WARN("Disabling speculative reloads (MSR %08llX: %016llX)\n",
		reg_addr, val);
	asm volatile ("wrmsr" : : "c"(reg_addr), "a"(val), "d"(0x00));

	/* disable data cache hw prefetchers */
	reg_addr = 0xc0011022;
	asm volatile ("rdmsr" : "=a"(lo), "=d"(hi) : "c"(reg_addr));
	val = (uint64_t) lo | ((uint64_t) hi << 32);
	val |= 1 << 13;
	CPC_WARN("Disabling DATA HWPF (MSR %08llX: %016llX)\n",
		reg_addr, val);
	asm volatile ("wrmsr" : : "c"(reg_addr), "a"(val), "d"(0x00));

	/* disable inst cache hw prefetchers */
	reg_addr = 0xc0011021;
	asm volatile ("rdmsr" : "=a"(lo), "=d"(hi) : "c"(reg_addr));
	val = (uint64_t) lo | ((uint64_t) hi << 32);
	val |= 1 << 13;
	CPC_WARN("Disabling INST HWPF (MSR %08llX: %016llX)\n",
		reg_addr, val);
	asm volatile ("wrmsr" : : "c"(reg_addr), "a"(val), "d"(0x00));

	/* REF: https://arxiv.org/pdf/2204.03290.pdf
	 * Paper "Memory Performance of AMD EPYC Rome and Intel Cascade
	 * Lake SP Server Processors"
	 * disable L1 & L2 prefetchers */

	reg_addr = 0xc0011022;
	asm volatile ("rdmsr" : "=a"(lo), "=d"(hi) : "c"(reg_addr));
	val = (uint64_t) lo | ((uint64_t) hi << 32);
	val |= 1 << 16;
	printk("CachePC: Disabling L1 & L2 prefetchers (MSR %08llX: %016llX)\n",
		reg_addr, val);
	asm volatile ("wrmsr" : : "c"(reg_addr), "a"(val), "d"(0x00));

	reg_addr = 0xc001102b;
	asm volatile ("rdmsr" : "=a"(lo), "=d"(hi) : "c"(reg_addr));
	val = (uint64_t) lo | ((uint64_t) hi << 32);
	val &= ~1ULL;
	printk("CachePC: Disabling L1 & L2 prefetchers (MSR %08llX: %016llX)\n",
		reg_addr, val);
	asm volatile ("wrmsr" : : "c"(reg_addr), "a"(val), "d"(0x00));
}

int
cachepc_kvm_reset_ioctl(void __user *arg_user)
{
	int cpu;

	if (arg_user) return -EINVAL;

	cpu = get_cpu();

	if (cpu != CPC_ISOLCPU) {
		put_cpu();
		return -EFAULT;
	}

	/* L1 misses in host kernel */
	cachepc_init_pmc(CPC_L1MISS_PMC, 0x64, 0xD8,
		PMC_HOST, PMC_KERNEL);

	/* retired instructions in guest */
	cachepc_init_pmc(CPC_RETINST_PMC, 0xC0, 0x00,
		PMC_GUEST, PMC_KERNEL | PMC_USER);

	put_cpu();

	cachepc_kvm_reset_tracking_ioctl(NULL);
	cachepc_kvm_reset_baseline_ioctl(NULL);

	return 0;
}

int
cachepc_kvm_debug_ioctl(void __user *arg_user)
{
	uint32_t debug;

	if (!arg_user) return -EINVAL;

	if (copy_from_user(&debug, arg_user, sizeof(uint32_t)))
		return -EFAULT;

	cachepc_debug = debug;

	return 0;
}

int
cachepc_kvm_test_eviction_ioctl(void __user *arg_user)
{
	uint32_t u32;
	int ret;

	if (!arg_user) return -EINVAL;

	if (copy_from_user(&u32, arg_user, sizeof(u32)))
		return -EFAULT;

	ret = smp_call_function_single(2,
		cachepc_kvm_single_eviction_test, &u32, true);
	WARN_ON(ret != 0);

	if (copy_to_user(arg_user, &u32, sizeof(u32)))
		return -EFAULT;

	return 0;
}

int
cachepc_kvm_read_counts_ioctl(void __user *arg_user)
{
	if (!arg_user) return -EINVAL;

	if (copy_to_user(arg_user, cachepc_msrmts, L1_SETS))
		return -EFAULT;

	return 0;
}

int
cachepc_kvm_reset_baseline_ioctl(void __user *arg_user)
{
	if (arg_user) return -EINVAL;

	cachepc_baseline_active = false;
	cachepc_baseline_measure = false;
	memset(cachepc_baseline, 0xff, L1_SETS);

	return 0;
}

int
cachepc_kvm_calc_baseline_ioctl(void __user *arg_user)
{
	uint32_t state;

	if (!arg_user) return -EINVAL;

	if (copy_from_user(&state, arg_user, sizeof(state)))
		return -EFAULT;

	cachepc_baseline_measure = state;

	return 0;
}

int
cachepc_kvm_read_baseline_ioctl(void __user *arg_user)
{
	if (!arg_user) return -EINVAL;

	if (copy_to_user(arg_user, cachepc_baseline, L1_SETS))
		return -EFAULT;

	return 0;
}

int
cachepc_kvm_apply_baseline_ioctl(void __user *arg_user)
{
	uint32_t state;

	if (!arg_user) return -EINVAL;

	if (copy_from_user(&state, arg_user, sizeof(state)))
		return -EFAULT;

	cachepc_baseline_active = state;

	return 0;
}

int
cachepc_kvm_single_step_ioctl(void __user *arg_user)
{
	cachepc_single_step = true;

	return 0;
}

int
cachepc_kvm_track_mode_ioctl(void __user *arg_user)
{
	struct kvm_vcpu *vcpu;
	uint32_t mode;

	if (!arg_user) return -EINVAL;

	if (copy_from_user(&mode, arg_user, sizeof(mode)))
		return -EFAULT;

	cachepc_single_step = false;
	cachepc_track_mode = mode;

	BUG_ON(!main_vm || xa_empty(&main_vm->vcpu_array));
	vcpu = xa_load(&main_vm->vcpu_array, 0);

	cachepc_untrack_all(vcpu, KVM_PAGE_TRACK_EXEC);
	cachepc_untrack_all(vcpu, KVM_PAGE_TRACK_ACCESS);
	cachepc_untrack_all(vcpu, KVM_PAGE_TRACK_WRITE);

	switch (mode) {
	case CPC_TRACK_FULL:
		cachepc_track_all(vcpu, KVM_PAGE_TRACK_ACCESS);
		mode = CPC_TRACK_FULL;
		break;
	case CPC_TRACK_EXEC:
		cachepc_track_all(vcpu, KVM_PAGE_TRACK_EXEC);
		mode = CPC_TRACK_EXEC;
		break;
	default:
		mode = CPC_TRACK_NONE;
		break;
	}

	return 0;
}

int
cachepc_kvm_track_page_ioctl(void __user *arg_user)
{
	struct cpc_track_config cfg;
	struct kvm_vcpu *vcpu;

	if (!main_vm || !arg_user) return -EINVAL;

	if (copy_from_user(&cfg, arg_user, sizeof(cfg)))
		return -EFAULT;

	if (cfg.mode < 0 || cfg.mode >= KVM_PAGE_TRACK_MAX)
		return -EINVAL;

	BUG_ON(xa_empty(&main_vm->vcpu_array));
	vcpu = xa_load(&main_vm->vcpu_array, 0);
	if (!cachepc_track_single(vcpu, cfg.gfn, cfg.mode))
		return -EFAULT;

	return 0;
}

int
cachepc_kvm_vmsa_read_ioctl(void __user *arg_user)
{
	struct kvm_vcpu *vcpu;
	struct vcpu_svm *svm;

	if (!main_vm || !arg_user) return -EINVAL;

	BUG_ON(xa_empty(&main_vm->vcpu_array));
	vcpu = xa_load(&main_vm->vcpu_array, 0);
	svm = to_svm(vcpu);

	if (copy_to_user(arg_user, svm->sev_es.vmsa, PAGE_SIZE))
		return -EFAULT;

	return 0;
}

int
cachepc_kvm_svme_read_ioctl(void __user *arg_user)
{
	uint32_t lo, hi;
	uint64_t res;
	uint32_t svme;

	if (!arg_user) return -EINVAL;

	asm volatile (
		"rdmsr"
		: "=a" (lo), "=d" (hi)
		: "c" (0xC0000080)
	);
	res = (((uint64_t) hi) << 32) | (uint64_t) lo;

	svme = (res >> 12) & 1;
	if (copy_to_user(arg_user, &svme, sizeof(uint32_t)))
		return -EFAULT;

	return 0;
}

// int
// cachepc_kvm_track_all_ioctl(void __user *arg_user)
// {
// 	struct kvm_vcpu *vcpu;
// 	uint32_t mode;
// 
// 	if (!main_vm || !arg_user) return -EINVAL;
// 
// 	if (copy_from_user(&mode, arg_user, sizeof(mode)))
// 		return -EFAULT;
// 
// 	if (mode < 0 || mode >= KVM_PAGE_TRACK_MAX)
// 		return -EINVAL;
// 
// 	BUG_ON(xa_empty(&main_vm->vcpu_array));
// 	vcpu = xa_load(&main_vm->vcpu_array, 0);
// 	if (!cachepc_track_all(vcpu, mode))
// 		return -EFAULT;
// 
// 	return 0;
// }
// 
// int
// cachepc_kvm_untrack_all_ioctl(void __user *arg_user)
// {
// 	struct kvm_vcpu *vcpu;
// 	uint32_t mode;
// 
// 	if (!main_vm || !arg_user) return -EINVAL;
// 
// 	if (copy_from_user(&mode, arg_user, sizeof(mode)))
// 		return -EFAULT;
// 
// 	if (mode < 0 || mode >= KVM_PAGE_TRACK_MAX)
// 		return -EINVAL;
// 
// 	BUG_ON(xa_empty(&main_vm->vcpu_array));
// 	vcpu = xa_load(&main_vm->vcpu_array, 0);
// 	if (!cachepc_untrack_all(vcpu, mode))
// 		return -EFAULT;
// 
// 	return 0;
// }

int
cachepc_kvm_reset_tracking_ioctl(void __user *arg_user)
{
	struct kvm_vcpu *vcpu;
	struct cpc_fault *fault, *next;

	BUG_ON(!main_vm || xa_empty(&main_vm->vcpu_array));
	vcpu = xa_load(&main_vm->vcpu_array, 0);
	cachepc_untrack_all(vcpu, KVM_PAGE_TRACK_EXEC);
	cachepc_untrack_all(vcpu, KVM_PAGE_TRACK_ACCESS);
	cachepc_untrack_all(vcpu, KVM_PAGE_TRACK_WRITE);

	cachepc_track_mode = CPC_TRACK_NONE;

	cachepc_inst_fault_gfn = 0;
	cachepc_inst_fault_err = 0;

	cachepc_track_start_gfn = 0;
	cachepc_track_end_gfn = 0;

	cachepc_single_step = false;

	list_for_each_entry_safe(fault, next, &cachepc_faults, list) {
		list_del(&fault->list);
		kfree(fault);
	}

	return 0;
}

int
cachepc_kvm_poll_event_ioctl(void __user *arg_user)
{
	if (!cachepc_events_init)
		return -EINVAL;

	return cachepc_handle_poll_event_ioctl(arg_user);
}

int
cachepc_kvm_ack_event_ioctl(void __user *arg_user)
{
	uint64_t eventid;

	if (!arg_user) return -EINVAL;

	if (!cachepc_events_init)
		return -EINVAL;

	if (copy_from_user(&eventid, arg_user, sizeof(eventid)))
		return -EFAULT;

	return cachepc_handle_ack_event_ioctl(eventid);
}

// int
// cachepc_kvm_track_range_start_ioctl(void __user *arg_user)
// {
// 	if (!arg_user) return -EINVAL;
// 
// 	if (copy_from_user(&cachepc_track_start_gfn, arg_user, sizeof(uint64_t)))
// 		return -EFAULT;
// 
// 	return 0;
// }
// 
// int
// cachepc_kvm_track_range_end_ioctl(void __user *arg_user)
// {
// 	if (!arg_user) return -EINVAL;
// 
// 	if (copy_from_user(&cachepc_track_end_gfn, arg_user, sizeof(uint64_t)))
// 		return -EFAULT;
// 
// 	return 0;
// }
// 
// int
// cachepc_kvm_track_exec_cur_ioctl(void __user *arg_user)
// {
// 	struct cpc_fault *fault;
// 
// 	if (!arg_user) return -EINVAL;
// 
// 	fault = list_first_entry(&cachepc_faults, struct cpc_fault, list);
// 	if (!fault) return -EFAULT;
// 
// 	if (copy_to_user(arg_user, &fault->gfn, sizeof(uint64_t)))
// 		return -EFAULT;
// 
// 	return 0;
// }

int
cachepc_kvm_vm_pause_ioctl(void __user *arg_user)
{
	uint64_t deadline;
	int err;

	if (!arg_user) return -EINVAL;

	if (!cachepc_events_init)
		return -EINVAL;

	cachepc_pause_vm = true;

	deadline = ktime_get_ns() + 20000000000ULL; /* 20s in ns */
	while (true) {
		write_lock(&cachepc_event_lock);
		if (cachepc_event_avail) {
			err = copy_to_user(arg_user, &cachepc_event,
				sizeof(struct cpc_event));
			cachepc_event_avail = false;
			write_unlock(&cachepc_event_lock);
			return 0;
		}
		write_unlock(&cachepc_event_lock);
		if (ktime_get_ns() > deadline) {
			CPC_WARN("Timeout waiting for pause event\n");
			cachepc_pause_vm = false;
			return -EFAULT;
		}
	}

	return err;
}

int
cachepc_kvm_vm_resume_ioctl(void __user *arg_user)
{
	uint64_t eventid;

	if (!arg_user) return -EINVAL;

	if (!cachepc_events_init)
		return -EINVAL;

	if (copy_from_user(&eventid, arg_user, sizeof(eventid)))
		return -EFAULT;

	cachepc_pause_vm = false;

	return cachepc_handle_ack_event_ioctl(eventid);
}

long
cachepc_kvm_ioctl(struct file *file, unsigned int ioctl, unsigned long arg)
{
	void __user *arg_user;

	arg_user = (void __user *)arg;
	switch (ioctl) {
	case KVM_CPC_RESET:
		return cachepc_kvm_reset_ioctl(arg_user);
	case KVM_CPC_DEBUG:
		return cachepc_kvm_debug_ioctl(arg_user);
	case KVM_CPC_TEST_EVICTION:
		return cachepc_kvm_test_eviction_ioctl(arg_user);
	case KVM_CPC_READ_COUNTS:
		return cachepc_kvm_read_counts_ioctl(arg_user);
	case KVM_CPC_RESET_BASELINE:
		return cachepc_kvm_reset_baseline_ioctl(arg_user);
	case KVM_CPC_READ_BASELINE:
		return cachepc_kvm_read_baseline_ioctl(arg_user);
	case KVM_CPC_CALC_BASELINE:
		return cachepc_kvm_calc_baseline_ioctl(arg_user);
	case KVM_CPC_APPLY_BASELINE:
		return cachepc_kvm_apply_baseline_ioctl(arg_user);
	// case KVM_CPC_SINGLE_STEP:
	// 	return cachepc_kvm_single_step_ioctl(arg_user);
	case KVM_CPC_VMSA_READ:
		return cachepc_kvm_vmsa_read_ioctl(arg_user);
	case KVM_CPC_SVME_READ:
		return cachepc_kvm_svme_read_ioctl(arg_user);
	case KVM_CPC_TRACK_MODE:
		return cachepc_kvm_track_mode_ioctl(arg_user);
	// case KVM_CPC_TRACK_PAGE:
	// 	return cachepc_kvm_track_page_ioctl(arg_user);
	// case KVM_CPC_TRACK_ALL:
	// 	return cachepc_kvm_track_all_ioctl(arg_user);
	// case KVM_CPC_UNTRACK_ALL:
	// 	return cachepc_kvm_untrack_all_ioctl(arg_user);
	case KVM_CPC_RESET_TRACKING:
		return cachepc_kvm_reset_tracking_ioctl(arg_user);
	case KVM_CPC_POLL_EVENT:
		return cachepc_kvm_poll_event_ioctl(arg_user);
	case KVM_CPC_ACK_EVENT:
		return cachepc_kvm_ack_event_ioctl(arg_user);
	// case KVM_CPC_TRACK_RANGE_START:
	// 	return cachepc_kvm_track_range_start_ioctl(arg_user);
	// case KVM_CPC_TRACK_RANGE_END:
	// 	return cachepc_kvm_track_range_end_ioctl(arg_user);
	// case KVM_CPC_TRACK_EXEC_CUR:
	// 	return cachepc_kvm_track_exec_cur_ioctl(arg_user);
	case KVM_CPC_VM_PAUSE:
		return cachepc_kvm_vm_pause_ioctl(arg_user);
	case KVM_CPC_VM_RESUME:
		return cachepc_kvm_vm_resume_ioctl(arg_user);
	default:
		return kvm_arch_dev_ioctl(file, ioctl, arg);
	}
}

void
cachepc_kvm_setup_test(void *p)
{
	int cpu;

	cpu = get_cpu();

	CPC_WARN("Running on core %i\n", cpu);

	if (cachepc_verify_topology())
		goto exit;

	cachepc_ctx = cachepc_get_ctx(L1_CACHE);
	cachepc_ds = cachepc_prepare_ds(cachepc_ctx);

	cachepc_kvm_system_setup();

	cachepc_kvm_prime_probe_test(NULL);
	cachepc_kvm_single_eviction_test(NULL);
	cachepc_kvm_stream_hwpf_test(NULL);

exit:
	put_cpu();
}

void
cachepc_kvm_init(void)
{
	int ret;

	cachepc_ctx = NULL;
	cachepc_ds = NULL;

	cachepc_retinst = 0;
	cachepc_debug = false;

	cachepc_single_step = false;
	cachepc_track_mode = CPC_TRACK_NONE;

	cachepc_inst_fault_gfn = 0;
	cachepc_inst_fault_err = 0;

	INIT_LIST_HEAD(&cachepc_faults);

	cachepc_msrmts = kzalloc(L1_SETS, GFP_KERNEL);
	BUG_ON(!cachepc_msrmts);

	cachepc_baseline_active = false;
	cachepc_baseline_measure = false;
	cachepc_baseline = kzalloc(L1_SETS, GFP_KERNEL);
	BUG_ON(!cachepc_baseline);

	cachepc_events_reset();

	ret = smp_call_function_single(2, cachepc_kvm_setup_test, NULL, true);
	WARN_ON(ret != 0);
}

void
cachepc_kvm_exit(void)
{
	kfree(cachepc_msrmts);

	if (cachepc_ds)
		cachepc_release_ds(cachepc_ctx, cachepc_ds);

	if (cachepc_ctx)
		cachepc_release_ctx(cachepc_ctx);
}
