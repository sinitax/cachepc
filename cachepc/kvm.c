#include "kvm.h"
#include "uapi.h"
#include "cachepc.h"
#include "event.h"
#include "track.h"

#include "svm/svm.h"

#include <linux/kvm_host.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/sev.h>
#include <asm/uaccess.h>

cpc_msrmt_t *cachepc_msrmts = NULL;
size_t cachepc_msrmts_count = 0;
EXPORT_SYMBOL(cachepc_msrmts);
EXPORT_SYMBOL(cachepc_msrmts_count);

cpc_msrmt_t *cachepc_baseline = NULL;
bool cachepc_baseline_measure = false;
bool cachepc_baseline_active = false;
EXPORT_SYMBOL(cachepc_baseline);
EXPORT_SYMBOL(cachepc_baseline_measure);
EXPORT_SYMBOL(cachepc_baseline_active);

uint64_t cachepc_retinst = 0;
EXPORT_SYMBOL(cachepc_retinst);

bool cachepc_single_step = false;
uint32_t cachepc_track_mode = false;
uint32_t cachepc_apic_timer = 0;
EXPORT_SYMBOL(cachepc_single_step);
EXPORT_SYMBOL(cachepc_track_mode);
EXPORT_SYMBOL(cachepc_apic_timer);

uint32_t cachepc_track_state;
uint32_t cachepc_track_state_next;
EXPORT_SYMBOL(cachepc_track_state);
EXPORT_SYMBOL(cachepc_track_state_next);

bool cachepc_inst_fault_avail = false;
uint64_t cachepc_inst_fault_gfn = 0;
uint32_t cachepc_inst_fault_err = 0;
EXPORT_SYMBOL(cachepc_inst_fault_avail);
EXPORT_SYMBOL(cachepc_inst_fault_gfn);
EXPORT_SYMBOL(cachepc_inst_fault_err);

bool cachepc_data_fault_avail = false;
uint64_t cachepc_data_fault_gfn = 0;
uint32_t cachepc_data_fault_err = 0;
EXPORT_SYMBOL(cachepc_data_fault_avail);
EXPORT_SYMBOL(cachepc_data_fault_gfn);
EXPORT_SYMBOL(cachepc_data_fault_err);

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

struct cpc_track_event cachepc_event;
bool cachepc_event_avail;
EXPORT_SYMBOL(cachepc_event);
EXPORT_SYMBOL(cachepc_event_avail);

bool cachepc_events_init;
EXPORT_SYMBOL(cachepc_events_init);

static void cachepc_kvm_prime_probe_test(void *p);
static void cachepc_kvm_stream_hwpf_test(void *p);
static void cachepc_kvm_single_access_test(void *p);
static void cachepc_kvm_single_eviction_test(void *p);

static void cachepc_kvm_system_setup(void);

static int cachepc_kvm_test_access_ioctl(void __user *arg_user);
static int cachepc_kvm_test_eviction_ioctl(void __user *arg_user);
static int cachepc_kvm_init_pmc_ioctl(void __user *arg_user);
static int cachepc_kvm_read_pmc_ioctl(void __user *arg_user);
static int cachepc_kvm_read_counts_ioctl(void __user *arg_user);
static int cachepc_kvm_setup_pmc_ioctl(void __user *arg_user);
static int cachepc_kvm_measure_baseline_ioctl(void __user *arg_user);
static int cachepc_kvm_read_baseline_ioctl(void __user *arg_user);
static int cachepc_kvm_sub_baseline_ioctl(void __user *arg_user);
static int cachepc_kvm_single_step_ioctl(void __user *arg_user);
static int cachepc_kvm_track_mode_ioctl(void __user *arg_user);

static int cachepc_kvm_track_page_ioctl(void __user *arg_user);
static int cachepc_kvm_track_all_ioctl(void __user *arg_user);
static int cachepc_kvm_untrack_all_ioctl(void __user *arg_user);
static int cachepc_kvm_uspt_reset_ioctl(void __user *arg_user);
static int cachepc_kvm_poll_event_ioctl(void __user *arg_user);
static int cachepc_kvm_uscpt_ack_event_ioctl(void __user *arg_user);

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
	BUG_ON(lines == NULL);

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

	printk(KERN_WARNING "CachePC: Prime-probe test done (%u vs. %u => %s)\n",
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
	uint32_t i, max;
	bool pass;

	arg = p;

	/* l2 data cache hit & miss */
	cachepc_init_pmc(CPC_L1MISS_PMC, 0x64, 0xD8, PMC_HOST, PMC_KERNEL);

	lines = cachepc_aligned_alloc(PAGE_SIZE, cachepc_ctx->cache_size);
	BUG_ON(lines == NULL);

	max = cachepc_ctx->nr_of_cachelines;

	count = 0;
	cachepc_prime(cachepc_ds);

	count -= cachepc_read_pmc(CPC_L1MISS_PMC);
	for (i = 0; i < max; i++)
		asm volatile ("mov (%0), %%rbx" : : "r"(lines + i) : "rbx");
	count += cachepc_read_pmc(CPC_L1MISS_PMC);

	pass = (count == max) || (count == max + 1); /* +1 for pot. counter miss */
	printk(KERN_WARNING "CachePC: HWPF test done (%u vs. %u => %s)\n",
		count, max, pass ? "passed" : "failed");

	if (arg) *arg = (count == max);

	kfree(lines);
}

void
cachepc_kvm_single_access_test(void *p)
{
	cacheline *ptr;
	uint64_t pre, post;
	uint32_t *arg;

	/* l2 data cache hit & miss */
	cachepc_init_pmc(CPC_L1MISS_PMC, 0x64, 0xD8, PMC_HOST, PMC_KERNEL);

	arg = p;
	
	WARN_ON(arg && *arg >= L1_SETS);
	if (arg && *arg >= L1_SETS) return;	
	ptr = cachepc_prepare_victim(cachepc_ctx, arg ? *arg : 48);

	cachepc_prime(cachepc_ds);

	pre = cachepc_read_pmc(CPC_L1MISS_PMC);
	cachepc_victim(ptr);
	post = cachepc_read_pmc(CPC_L1MISS_PMC);

	printk(KERN_WARNING "CachePC: Single access test done (%llu vs %u => %s)",
		post - pre, 1, (post - pre == 1) ? "passed" : "failed");

	if (arg) *arg = post - pre;

	cachepc_release_victim(cachepc_ctx, ptr);
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

	printk(KERN_WARNING "CachePC: Single eviction test done (%u vs %u => %s)\n",
		count, 1, (count == 1 && evicted->cache_set == target) ? "passed" : "failed");
	cachepc_save_msrmts(head);

	if (arg) *arg = count;

	cachepc_release_victim(cachepc_ctx, ptr);
}

void
cachepc_kvm_system_setup(void)
{
	uint64_t reg_addr, val;
	uint32_t lo, hi;

	/* disable streaming store */
	reg_addr = 0xc0011020;
	asm volatile ("rdmsr" : "=a"(lo), "=d"(hi) : "c"(reg_addr));
	val = (uint64_t) lo | ((uint64_t) hi << 32);
	val |= 1 << 13;
	asm volatile ("wrmsr" : : "c"(reg_addr), "a"(val), "d"(0x00));
	printk("CachePC: Disabling streaming store (MSR %08llX: %016llX)\n",
		reg_addr, val);

	/* disable speculative data cache tlb reloads */
	reg_addr = 0xc0011022;
	asm volatile ("rdmsr" : "=a"(lo), "=d"(hi) : "c"(reg_addr));
	val = (uint64_t) lo | ((uint64_t) hi << 32);
	val |= 1 << 4;
	asm volatile ("wrmsr" : : "c"(reg_addr), "a"(val), "d"(0x00));
	printk("CachePC: Disabling speculative reloads (MSR %08llX: %016llX)\n",
		reg_addr, val);

	/* disable data cache hardware prefetcher */
	reg_addr = 0xc0011022;
	asm volatile ("rdmsr" : "=a"(lo), "=d"(hi) : "c"(reg_addr));
	val = (uint64_t) lo | ((uint64_t) hi << 32);
	val |= 1 << 13;
	asm volatile ("wrmsr" : : "c"(reg_addr), "a"(val), "d"(0x00));
	printk("CachePC: Disabling HWPF (MSR %08llX: %016llX)\n",
		reg_addr, val);
}

int
cachepc_kvm_test_access_ioctl(void __user *arg_user)
{
	uint32_t u32;
	int ret;

	if (!arg_user) return -EINVAL;

	if (copy_from_user(&u32, arg_user, sizeof(u32)))
		return -EFAULT;

	ret = smp_call_function_single(2,
		cachepc_kvm_single_access_test, &u32, true);
	WARN_ON(ret != 0);

	if (copy_to_user(arg_user, &u32, sizeof(u32)))
		return -EFAULT;

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
cachepc_kvm_init_pmc_ioctl(void __user *arg_user)
{
	uint8_t index, event_no, event_mask;
	uint8_t host_guest, kernel_user;
	uint32_t event;
	int cpu;

	if (!arg_user) return -EINVAL;

	cpu = get_cpu();
	if (cpu != CPC_ISOLCPU) {
		put_cpu();
		return -EFAULT;
	}

	if (copy_from_user(&event, arg_user, sizeof(event))) {
		put_cpu();
		return -EFAULT;
	}

	index       = (event & 0xFF000000) >> 24;
	host_guest  = (event & 0x00300000) >> 20;
	kernel_user = (event & 0x00030000) >> 16;
	event_no    = (event & 0x0000FF00) >> 8;
	event_mask  = (event & 0x000000FF) >> 0;

	cachepc_init_pmc(index, event_no, event_mask,
		host_guest, kernel_user);
	cachepc_reset_pmc(index);

	put_cpu();

	return 0;
}

int
cachepc_kvm_read_pmc_ioctl(void __user *arg_user)
{
	uint64_t count;
	uint32_t event;

	if (!arg_user) return -EINVAL;

	if (copy_from_user(&event, arg_user, sizeof(event)))
		return -EFAULT;

	count = cachepc_read_pmc(event);
	if (copy_to_user(arg_user, &count, sizeof(count)))
		return -EFAULT;

	return 0;
}

int
cachepc_kvm_read_counts_ioctl(void __user *arg_user)
{
	if (!arg_user) return -EINVAL;

	if (copy_to_user(arg_user, cachepc_msrmts,
			cachepc_msrmts_count * sizeof(cpc_msrmt_t)))
		return -EFAULT;

	return 0;
}

int
cachepc_kvm_setup_pmc_ioctl(void __user *arg_user)
{
	int cpu;

	cpu = get_cpu();

	if (cpu != CPC_ISOLCPU) {
		put_cpu();
		return -EFAULT;
	}

	/* L1 Misses in Host Kernel */
	cachepc_init_pmc(CPC_L1MISS_PMC, 0x64, 0xD8,
		PMC_HOST, PMC_KERNEL);

	/* Retired Instructions in Guest */
	cachepc_init_pmc(CPC_RETINST_PMC, 0xC0, 0x00,
		PMC_GUEST, PMC_KERNEL | PMC_USER);

	put_cpu();

	return 0;
}

int
cachepc_kvm_measure_baseline_ioctl(void __user *arg_user)
{
	uint32_t state;
	size_t i;

	if (!arg_user) return -EINVAL;

	if (copy_from_user(&state, arg_user, sizeof(state)))
		return -EFAULT;

	if (state) {
		for (i = 0; i < cachepc_msrmts_count; i++)
			cachepc_baseline[i] = CPC_MSRMT_MAX;
	}

	cachepc_baseline_measure = state;


	return 0;
}

int
cachepc_kvm_read_baseline_ioctl(void __user *arg_user)
{
	if (!arg_user) return -EINVAL;

	if (copy_to_user(arg_user, cachepc_baseline,
			cachepc_msrmts_count * sizeof(cpc_msrmt_t)))
		return -EFAULT;

	return 0;
}

int
cachepc_kvm_sub_baseline_ioctl(void __user *arg_user)
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
	uint32_t mode;

	if (!arg_user) return -EINVAL;

	if (copy_from_user(&mode, arg_user, sizeof(mode)))
		return -EFAULT;

	cachepc_track_mode = mode;

	return 0;
}

int
cachepc_kvm_track_page_ioctl(void __user *arg_user)
{
	struct cpc_track_config cfg;
	struct kvm_vcpu *vcpu;

	if (!arg_user) return -EINVAL;

	if (copy_from_user(&cfg, arg_user, sizeof(cfg)))
		return -EFAULT;

	if (main_vm == NULL)
		return -EFAULT;

	if (cfg.mode < 0 || cfg.mode >= KVM_PAGE_TRACK_MAX)
		return -EINVAL;

	vcpu = xa_load(&main_vm->vcpu_array, 0);
	if (!cachepc_track_single(vcpu, cfg.gfn, cfg.mode)) {
		printk("KVM_TRACK_PAGE: cachepc_track_single failed");
		return -EFAULT;
	}

	return 0;
}

int
cachepc_kvm_vmsa_read_ioctl(void __user *arg_user)
{
	struct kvm_vcpu *vcpu;
	struct vcpu_svm *svm;

	if (!main_vm || !arg_user) return -EINVAL;

	vcpu = xa_load(&main_vm->vcpu_array, 0);
	svm = to_svm(vcpu);

	if (copy_to_user(arg_user, svm->sev_es.vmsa, PAGE_SIZE))
		return -EFAULT;

	return 0;
}

int
cachepc_kvm_track_all_ioctl(void __user *arg_user)
{
	struct kvm_vcpu *vcpu;
	uint64_t mode;

	if (!arg_user) return -EINVAL;

	if (copy_from_user(&mode, arg_user, sizeof(mode)))
		return -EFAULT;

	if (main_vm == NULL)
		return -EFAULT;

	if (mode < 0 || mode >= KVM_PAGE_TRACK_MAX)
		return -EINVAL;

	vcpu = xa_load(&main_vm->vcpu_array, 0);
	if (!cachepc_track_all(vcpu, mode))
		return -EFAULT;

	return 0;
}

int
cachepc_kvm_untrack_all_ioctl(void __user *arg_user)
{
	struct kvm_vcpu *vcpu;
	uint64_t mode;

	if (!arg_user) return -EINVAL;

	if (copy_from_user(&mode, arg_user, sizeof(mode)))
		return -EFAULT;

	if (main_vm == NULL)
		return -EFAULT;

	if (mode < 0 || mode >= KVM_PAGE_TRACK_MAX)
		return -EINVAL;

	vcpu = xa_load(&main_vm->vcpu_array, 0);
	if (!cachepc_untrack_all(vcpu, mode))
		return -EFAULT;

	return 0;
}

int
cachepc_kvm_uspt_reset_ioctl(void __user *arg_user)
{
	struct kvm_vcpu *vcpu;

	cachepc_events_reset();
	vcpu = xa_load(&main_vm->vcpu_array, 0);
	cachepc_untrack_all(vcpu, KVM_PAGE_TRACK_EXEC);
	cachepc_untrack_all(vcpu, KVM_PAGE_TRACK_ACCESS);
	cachepc_untrack_all(vcpu, KVM_PAGE_TRACK_WRITE);

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
cachepc_kvm_uscpt_ack_event_ioctl(void __user *arg_user)
{
	uint64_t eventid;

	if (!arg_user) return -EINVAL;

	if (!cachepc_events_init)
		return -EINVAL;

	if (copy_from_user(&eventid, arg_user, sizeof(eventid)))
		return -EINVAL;

	return cachepc_handle_ack_event_ioctl(eventid);
}

long
cachepc_kvm_ioctl(struct file *file, unsigned int ioctl, unsigned long arg)
{
	void __user *arg_user;

	arg_user = (void __user *)arg;
	switch (ioctl) {
	case KVM_CPC_TEST_ACCESS:
		return cachepc_kvm_test_access_ioctl(arg_user);
	case KVM_CPC_TEST_EVICTION:
		return cachepc_kvm_test_eviction_ioctl(arg_user);
	case KVM_CPC_INIT_PMC:
		return cachepc_kvm_init_pmc_ioctl(arg_user);
	case KVM_CPC_READ_PMC:
		return cachepc_kvm_read_pmc_ioctl(arg_user);
	case KVM_CPC_READ_COUNTS:
		return cachepc_kvm_read_counts_ioctl(arg_user);
	case KVM_CPC_SETUP_PMC:
		return cachepc_kvm_setup_pmc_ioctl(arg_user);
	case KVM_CPC_MEASURE_BASELINE:
		return cachepc_kvm_measure_baseline_ioctl(arg_user);
	case KVM_CPC_READ_BASELINE:
		return cachepc_kvm_read_baseline_ioctl(arg_user);
	case KVM_CPC_SUB_BASELINE:
		return cachepc_kvm_sub_baseline_ioctl(arg_user);
	case KVM_CPC_SINGLE_STEP:
		return cachepc_kvm_single_step_ioctl(arg_user);
	case KVM_CPC_TRACK_MODE:
		return cachepc_kvm_track_mode_ioctl(arg_user);
	case KVM_CPC_VMSA_READ:
		return cachepc_kvm_vmsa_read_ioctl(arg_user);
	case KVM_CPC_TRACK_PAGE:
		return cachepc_kvm_track_page_ioctl(arg_user);
	case KVM_CPC_TRACK_ALL:
		return cachepc_kvm_track_all_ioctl(arg_user);
	case KVM_CPC_UNTRACK_ALL:
		return cachepc_kvm_untrack_all_ioctl(arg_user);
	case KVM_CPC_RESET_TRACKING:
		return cachepc_kvm_uspt_reset_ioctl(arg_user);
	case KVM_CPC_POLL_EVENT:
		return cachepc_kvm_poll_event_ioctl(arg_user);
	case KVM_CPC_ACK_EVENT:
		return cachepc_kvm_uscpt_ack_event_ioctl(arg_user);
	default:
		return kvm_arch_dev_ioctl(file, ioctl, arg);
	}
}

void
cachepc_kvm_setup_test(void *p)
{
	int cpu;

	cpu = get_cpu();

	pr_warn("CachePC: Running on core %i\n", cpu);

	if (cachepc_verify_topology())
		goto exit;

	cachepc_ctx = cachepc_get_ctx(L1_CACHE);
	cachepc_ds = cachepc_prepare_ds(cachepc_ctx);

	cachepc_kvm_system_setup();

	cachepc_kvm_prime_probe_test(NULL);
	cachepc_kvm_single_access_test(NULL);
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

	cachepc_single_step = false;
	cachepc_track_mode = CPC_TRACK_ACCESS;

	cachepc_track_state = CPC_TRACK_AWAIT_INST_FAULT;

	cachepc_data_fault_avail = false;
	cachepc_inst_fault_avail = false;

	cachepc_msrmts_count = L1_SETS;
	cachepc_msrmts = kzalloc(cachepc_msrmts_count * sizeof(cpc_msrmt_t), GFP_KERNEL);
	BUG_ON(cachepc_msrmts == NULL);

	cachepc_baseline_measure = false;
	cachepc_baseline = kzalloc(cachepc_msrmts_count * sizeof(cpc_msrmt_t), GFP_KERNEL);
	BUG_ON(cachepc_baseline == NULL);

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
