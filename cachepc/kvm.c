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

#define TEST_REPEAT_MAX 1000

bool cpc_debug = false;
EXPORT_SYMBOL(cpc_debug);

uint8_t *cpc_msrmts = NULL;
EXPORT_SYMBOL(cpc_msrmts);

uint8_t *cpc_baseline = NULL;
bool cpc_baseline_measure = false;
bool cpc_baseline_active = false;
EXPORT_SYMBOL(cpc_baseline);
EXPORT_SYMBOL(cpc_baseline_measure);
EXPORT_SYMBOL(cpc_baseline_active);

uint32_t cpc_svm_exitcode = false;
EXPORT_SYMBOL(cpc_svm_exitcode);

bool cpc_pause_vm = false;
EXPORT_SYMBOL(cpc_pause_vm);

bool cpc_prime_probe = false;
EXPORT_SYMBOL(cpc_prime_probe);

uint64_t cpc_retinst = 0;
uint64_t cpc_retinst_prev = 0;
EXPORT_SYMBOL(cpc_retinst);
EXPORT_SYMBOL(cpc_retinst_prev);

uint64_t cpc_rip = 0;
uint64_t cpc_rip_prev = 0;
bool cpc_rip_prev_set = false;
EXPORT_SYMBOL(cpc_rip);
EXPORT_SYMBOL(cpc_rip_prev);
EXPORT_SYMBOL(cpc_rip_prev_set);

bool cpc_singlestep = false;
bool cpc_singlestep_reset = false;
bool cpc_long_step = false;
EXPORT_SYMBOL(cpc_singlestep);
EXPORT_SYMBOL(cpc_singlestep_reset);
EXPORT_SYMBOL(cpc_long_step);

bool cpc_apic_oneshot = false;
uint32_t cpc_apic_timer = 0;
EXPORT_SYMBOL(cpc_apic_oneshot);
EXPORT_SYMBOL(cpc_apic_timer);

uint32_t cpc_track_mode = false;
uint64_t cpc_track_start_gfn = 0;
uint64_t cpc_track_end_gfn = 0;
EXPORT_SYMBOL(cpc_track_mode);
EXPORT_SYMBOL(cpc_track_start_gfn);
EXPORT_SYMBOL(cpc_track_end_gfn);

LIST_HEAD(cpc_faults);
EXPORT_SYMBOL(cpc_faults);

struct cpc_track_steps cpc_track_steps;
struct cpc_track_pages cpc_track_pages;
EXPORT_SYMBOL(cpc_track_steps);
EXPORT_SYMBOL(cpc_track_pages);

struct cpc_cl *cpc_ds_ul = NULL;
struct cpc_cl *cpc_ds = NULL;
EXPORT_SYMBOL(cpc_ds);

uint64_t cpc_regs_tmp[16];
uint64_t cpc_regs_vm[16];
EXPORT_SYMBOL(cpc_regs_tmp);
EXPORT_SYMBOL(cpc_regs_vm);

void cpc_prime_probe_test_asm(void);
static noinline void cpc_prime_probe_test(void);

uint64_t cpc_stream_hwpf_test_asm(void *lines);
static noinline void cpc_stream_hwpf_test(void);

void cpc_single_eviction_test_asm(void *ptr);
static noinline void cpc_single_eviction_test(void *p);

static void cpc_pmc_setup(void *p);
static void cpc_system_setup(void);

static int cpc_reset_ioctl(void __user *arg_user);
static int cpc_debug_ioctl(void __user *arg_user);

static int cpc_memory_encrypt_op_ioctl(void __user *arg_user);

static int cpc_test_eviction_ioctl(void __user *arg_user);

static int cpc_read_counts_ioctl(void __user *arg_user);

static int cpc_reset_baseline_ioctl(void __user *arg_user);
static int cpc_calc_baseline_ioctl(void __user *arg_user);
static int cpc_read_baseline_ioctl(void __user *arg_user);
static int cpc_apply_baseline_ioctl(void __user *arg_user);

static int cpc_reset_tracking_ioctl(void __user *arg_user);
static int cpc_track_mode_ioctl(void __user *arg_user);
// static int cpc_track_page_ioctl(void __user *arg_user);
// static int cpc_track_range_start_ioctl(void __user *arg_user);
// static int cpc_track_range_end_ioctl(void __user *arg_user);
// static int cpc_track_exec_cur_ioctl(void __user *arg_user);

static int cpc_req_pause_ioctl(void __user *arg_user);

void
cpc_prime_probe_test(void)
{
	int i, n, count;

	/* l2 data cache hit & miss */
	cpc_init_pmc(CPC_L1MISS_PMC, 0x64, 0xD8, 0, PMC_KERNEL);

	for (n = 0; n < TEST_REPEAT_MAX; n++) {
		memset(cpc_msrmts, 0, L1_SETS);
		cpc_prime_probe_test_asm();
		cpc_save_msrmts(cpc_ds);

		count = 0;
		for (i = 0; i < L1_SETS; i++)
			count += cpc_msrmts[i];

		if (count != 0) {
			CPC_ERR("Prime-probe %i. test failed (%u vs. %u)\n",
				n, count, 0);
			break;
		}
	}

	if (n == TEST_REPEAT_MAX)
		CPC_INFO("Prime-probe test ok (%u vs. %u)\n", count, 0);
}

void
cpc_stream_hwpf_test(void)
{
	const uint32_t max = 10;
	struct cpc_cl *lines;
	uint32_t count;
	int n;

	/* l2 data cache hit & miss */
	cpc_init_pmc(CPC_L1MISS_PMC, 0x64, 0xD8, 0, PMC_KERNEL);

	lines = cpc_aligned_alloc(L1_SIZE, L1_SIZE);

	count = 0;
	for (n = 0; n < TEST_REPEAT_MAX; n++) {
		count = cpc_stream_hwpf_test_asm(lines);
		if (count != max) {
			CPC_ERR("HWPF %i. test failed (%u vs. %u)\n",
				n, count, max);
			break;
		}
	}

	if (n == TEST_REPEAT_MAX)
		CPC_INFO("HWPF test ok (%u vs. %u)\n", count, max);

	kfree(lines);
}

void
cpc_single_eviction_test(void *p)
{
	struct cpc_cl *victim_ul;
	struct cpc_cl *victim;
	uint32_t target, *arg;
	int n, i, count;

	arg = p;

	/* l2 data cache hit & miss */
	cpc_init_pmc(CPC_L1MISS_PMC, 0x64, 0xD8, 0, PMC_KERNEL);

	WARN_ON(arg && *arg >= L1_SETS);
	if (arg && *arg >= L1_SETS) return;
	target = arg ? *arg : 48;

	victim_ul = cpc_aligned_alloc(PAGE_SIZE, L1_SIZE);
	victim = &victim_ul[target];

	for (n = 0; n < TEST_REPEAT_MAX; n++) {
		memset(cpc_msrmts, 0, L1_SETS);
		cpc_single_eviction_test_asm(victim);
		cpc_save_msrmts(cpc_ds);

		count = 0;
		for (i = 0; i < L1_SETS; i++)
			count += cpc_msrmts[i];

		if (count != 1 || cpc_msrmts[target] != 1) {
			CPC_ERR("Single eviction %i. test failed (%u vs %u)\n",
				n, count, 1);
			if (arg) *arg = count;
			break;
		}
	}

	if (n == TEST_REPEAT_MAX) {
		CPC_INFO("Single eviction test ok (%u vs %u)\n", count, 1);
		if (arg) *arg = count;
	}

	kfree(victim_ul);
}

void
cpc_pmc_setup(void *p)
{
	/* L1 misses in host kernel */
	cpc_init_pmc(CPC_L1MISS_PMC, 0x64, 0xD8,
		PMC_HOST, PMC_KERNEL);

	/* retired instructions in guest */
	cpc_init_pmc(CPC_RETINST_PMC, 0xC0, 0x00,
		PMC_GUEST, PMC_KERNEL | PMC_USER);
}

void
cpc_system_setup(void)
{
	/* NOTE: since most of these MSRs are poorly documented and some
	 * guessing work was involved, it is likely that one or more of
	 * these operations are not needed */

	/* REF: BKDG Family 15h Model 00h-0Fh Rev 3.14 January 23, 2013 P.38 */
	/* disable streaming store */
	cpc_write_msr(0xc0011020, 0, 1ULL << 28);
	/* disable data cache hw prefetcher */
	cpc_write_msr(0xc0011022, 0, 1ULL << 13);

	/* REF: https://arxiv.org/pdf/2204.03290.pdf */
	/* l1 and l2 prefetchers */
	cpc_write_msr(0xc0011022, 0, 1ULL << 16);
	cpc_write_msr(0xc001102b, 1ULL << 0, 0);

	/* REF: https://community.amd.com/t5/archives-discussions/modifying-msr-to-disable-the-prefetcher/td-p/143443 */
	cpc_write_msr(0xc001102b, 0, 1ULL << 18);

	/* REF: PPR Family 19h Model 01h Vol 1/2 Rev 0.50 May 27.2021 P.168 */
	/* disable L1 and L2 prefetcher */
	cpc_write_msr(0xC0000108, 0, 0b00101111);

	/* REF: PPR Family 19h Model 01h Vol 1/2 Rev 0.50 May 27.2021 P.111 */
	/* disable speculation */
	cpc_write_msr(0x00000048, 0, 0b10000111);
}

int
cpc_reset_ioctl(void __user *arg_user)
{
	int ret;

	ret = smp_call_function_single(CPC_ISOLCPU,
		cpc_pmc_setup, NULL, true);
	if (ret) return -EFAULT;

	cpc_events_reset();

	cpc_reset_tracking_ioctl(NULL);
	cpc_reset_baseline_ioctl(NULL);

	cpc_pause_vm = false;

	cpc_singlestep = false;
	cpc_singlestep_reset = false;

	cpc_apic_oneshot = false;
	cpc_apic_timer = 0;

	cpc_prime_probe = false;

	cpc_retinst = 0;
	cpc_rip_prev_set = false;

	return 0;
}

int
cpc_debug_ioctl(void __user *arg_user)
{
	uint32_t debug;

	if (!arg_user) return -EINVAL;

	if (copy_from_user(&debug, arg_user, sizeof(uint32_t)))
		return -EFAULT;

	cpc_debug = debug;

	return 0;
}

int
cpc_memory_encrypt_op_ioctl(void __user *arg_user)
{
	if (!arg_user || !main_vm) return -EFAULT;

	return static_call(kvm_x86_mem_enc_ioctl)(main_vm, arg_user);
}

int
cpc_test_eviction_ioctl(void __user *arg_user)
{
	uint32_t u32;
	int ret;

	if (!arg_user) return -EINVAL;

	if (copy_from_user(&u32, arg_user, sizeof(u32)))
		return -EFAULT;

	ret = smp_call_function_single(CPC_ISOLCPU,
		cpc_single_eviction_test, &u32, true);
	WARN_ON(ret != 0);

	if (copy_to_user(arg_user, &u32, sizeof(u32)))
		return -EFAULT;

	return 0;
}

int
cpc_read_counts_ioctl(void __user *arg_user)
{
	if (!arg_user) return -EINVAL;

	if (copy_to_user(arg_user, cpc_msrmts, L1_SETS))
		return -EFAULT;

	return 0;
}

int
cpc_reset_baseline_ioctl(void __user *arg_user)
{
	if (arg_user) return -EINVAL;

	cpc_baseline_active = false;
	cpc_baseline_measure = false;
	memset(cpc_baseline, 0xff, L1_SETS);

	return 0;
}

int
cpc_calc_baseline_ioctl(void __user *arg_user)
{
	uint32_t state;

	if (!arg_user) return -EINVAL;

	if (copy_from_user(&state, arg_user, sizeof(state)))
		return -EFAULT;

	cpc_baseline_measure = state;

	return 0;
}

int
cpc_read_baseline_ioctl(void __user *arg_user)
{
	if (!arg_user) return -EINVAL;

	if (copy_to_user(arg_user, cpc_baseline, L1_SETS))
		return -EFAULT;

	return 0;
}

int
cpc_apply_baseline_ioctl(void __user *arg_user)
{
	uint32_t state;

	if (!arg_user) return -EINVAL;

	if (copy_from_user(&state, arg_user, sizeof(state)))
		return -EFAULT;

	cpc_baseline_active = state;

	return 0;
}

int
cpc_long_step_ioctl(void __user *arg_user)
{
	if (arg_user) return -EINVAL;

	cpc_long_step = true;

	return 0;
}

int
cpc_reset_tracking_ioctl(void __user *arg_user)
{
	struct kvm_vcpu *vcpu;
	struct cpc_fault *fault, *next;

	if (!main_vm || xa_empty(&main_vm->vcpu_array))
		return -EFAULT;

	vcpu = xa_load(&main_vm->vcpu_array, 0);
	cpc_untrack_all(vcpu, KVM_PAGE_TRACK_EXEC);
	cpc_untrack_all(vcpu, KVM_PAGE_TRACK_ACCESS);
	cpc_untrack_all(vcpu, KVM_PAGE_TRACK_WRITE);

	cpc_track_start_gfn = 0;
	cpc_track_end_gfn = 0;

	cpc_singlestep = false;
	cpc_singlestep_reset = false;

	cpc_long_step = false;

	cpc_track_mode = CPC_TRACK_NONE;

	list_for_each_entry_safe(fault, next, &cpc_faults, list) {
		list_del(&fault->list);
		kfree(fault);
	}

	return 0;
}

int
cpc_track_mode_ioctl(void __user *arg_user)
{
	struct kvm_vcpu *vcpu;
	struct cpc_track_cfg cfg;

	if (!arg_user) return -EINVAL;

	if (copy_from_user(&cfg, arg_user, sizeof(cfg)))
		return -EFAULT;

	if (!main_vm || xa_empty(&main_vm->vcpu_array))
		return -EFAULT;

	vcpu = xa_load(&main_vm->vcpu_array, 0);

	cpc_untrack_all(vcpu, KVM_PAGE_TRACK_EXEC);
	cpc_untrack_all(vcpu, KVM_PAGE_TRACK_ACCESS);
	cpc_untrack_all(vcpu, KVM_PAGE_TRACK_WRITE);

	cpc_apic_timer = 0;
	cpc_apic_oneshot = false;
	cpc_prime_probe = false;
	cpc_singlestep = false;
	cpc_singlestep_reset = false;
	cpc_long_step = false;

	switch (cfg.mode) {
	case CPC_TRACK_FAULT_NO_RUN:
		cpc_prime_probe = true;
		cpc_track_all(vcpu, KVM_PAGE_TRACK_ACCESS);
		break;
	case CPC_TRACK_EXIT_EVICTIONS:
		cpc_prime_probe = true;
		cpc_long_step = true;
		break;
	case CPC_TRACK_PAGES:
		memset(&cpc_track_pages, 0, sizeof(cpc_track_pages));
		cpc_track_all(vcpu, KVM_PAGE_TRACK_EXEC);
		break;
	case CPC_TRACK_STEPS:
		cpc_track_steps.use_target = cfg.steps.use_target;
		cpc_track_steps.target_gfn = cfg.steps.target_gfn;
		cpc_track_steps.with_data = cfg.steps.with_data;
		cpc_track_steps.use_filter = cfg.steps.use_filter;
		if (!cpc_track_steps.use_target
				&& cpc_track_steps.with_data) {
			cpc_track_all(vcpu, KVM_PAGE_TRACK_ACCESS);
			cpc_prime_probe = true;
			cpc_singlestep_reset = true;
			cpc_track_steps.stepping = true;
		} else if (!cpc_track_steps.use_target
				&& !cpc_track_steps.with_data) {
			cpc_track_all(vcpu, KVM_PAGE_TRACK_EXEC);
			cpc_singlestep_reset = true;
			cpc_track_steps.stepping = true;
		} else {
			cpc_track_all(vcpu, KVM_PAGE_TRACK_EXEC);
			cpc_track_steps.stepping = false;
		}
		break;
	case CPC_TRACK_NONE:
		break;
	default:
		return -EINVAL;
	}

	cpc_track_mode = cfg.mode;

	return 0;
}

// int
// cpc_track_page_ioctl(void __user *arg_user)
// {
// 	struct cpc_track_config cfg;
// 	struct kvm_vcpu *vcpu;
// 
// 	if (!main_vm || !arg_user) return -EINVAL;
// 
// 	if (copy_from_user(&cfg, arg_user, sizeof(cfg)))
// 		return -EFAULT;
// 
// 	if (cfg.mode < 0 || cfg.mode >= KVM_PAGE_TRACK_MAX)
// 		return -EINVAL;
// 
// 	BUG_ON(xa_empty(&main_vm->vcpu_array));
// 	vcpu = xa_load(&main_vm->vcpu_array, 0);
// 	if (!cpc_track_single(vcpu, cfg.gfn, cfg.mode))
// 		return -EFAULT;
// 
// 	return 0;
// }
//
// int
// cpc_track_range_start_ioctl(void __user *arg_user)
// {
// 	if (!arg_user) return -EINVAL;
// 
// 	if (copy_from_user(&cpc_track_start_gfn, arg_user, sizeof(uint64_t)))
// 		return -EFAULT;
// 
// 	return 0;
// }
// 
// int
// cpc_track_range_end_ioctl(void __user *arg_user)
// {
// 	if (!arg_user) return -EINVAL;
// 
// 	if (copy_from_user(&cpc_track_end_gfn, arg_user, sizeof(uint64_t)))
// 		return -EFAULT;
// 
// 	return 0;
// }
// 
// int
// cpc_track_exec_cur_ioctl(void __user *arg_user)
// {
// 	struct cpc_fault *fault;
// 
// 	if (!arg_user) return -EINVAL;
// 
// 	fault = list_first_entry(&cpc_faults, struct cpc_fault, list);
// 	if (!fault) return -EFAULT;
// 
// 	if (copy_to_user(arg_user, &fault->gfn, sizeof(uint64_t)))
// 		return -EFAULT;
// 
// 	return 0;
// }

int
cpc_req_pause_ioctl(void __user *arg_user)
{
	if (arg_user) return -EINVAL;

	cpc_pause_vm = true;

	return 0;
}

long
cpc_kvm_ioctl(struct file *file, unsigned int ioctl, unsigned long arg)
{
	void __user *arg_user;

	arg_user = (void __user *)arg;
	switch (ioctl) {
	case KVM_CPC_RESET:
		return cpc_reset_ioctl(arg_user);
	case KVM_CPC_DEBUG:
		return cpc_debug_ioctl(arg_user);
	case KVM_CPC_MEMORY_ENCRYPT_OP:
		return cpc_memory_encrypt_op_ioctl(arg_user);
	case KVM_CPC_TEST_EVICTION:
		return cpc_test_eviction_ioctl(arg_user);
	case KVM_CPC_READ_COUNTS:
		return cpc_read_counts_ioctl(arg_user);
	case KVM_CPC_RESET_BASELINE:
		return cpc_reset_baseline_ioctl(arg_user);
	case KVM_CPC_READ_BASELINE:
		return cpc_read_baseline_ioctl(arg_user);
	case KVM_CPC_CALC_BASELINE:
		return cpc_calc_baseline_ioctl(arg_user);
	case KVM_CPC_APPLY_BASELINE:
		return cpc_apply_baseline_ioctl(arg_user);
	case KVM_CPC_LONG_STEP:
		return cpc_long_step_ioctl(arg_user);
	case KVM_CPC_RESET_TRACKING:
		return cpc_reset_tracking_ioctl(arg_user);
	case KVM_CPC_TRACK_MODE:
		return cpc_track_mode_ioctl(arg_user);
	case KVM_CPC_POLL_EVENT:
		return cpc_poll_event_ioctl(arg_user);
	case KVM_CPC_ACK_EVENT:
		return cpc_ack_event_ioctl(arg_user);
	case KVM_CPC_READ_EVENTS:
		return cpc_read_events_ioctl(arg_user);
	// case KVM_CPC_TRACK_PAGE:
	// 	return cpc_track_page_ioctl(arg_user);
	// case KVM_CPC_TRACK_RANGE_START:
	// 	return cpc_track_range_start_ioctl(arg_user);
	// case KVM_CPC_TRACK_RANGE_END:
	// 	return cpc_track_range_end_ioctl(arg_user);
	// case KVM_CPC_TRACK_EXEC_CUR:
	// 	return cpc_track_exec_cur_ioctl(arg_user);
	case KVM_CPC_VM_REQ_PAUSE:
		return cpc_req_pause_ioctl(arg_user);
	default:
		return kvm_arch_dev_ioctl(file, ioctl, arg);
	}
}

void
cpc_setup_test(void *p)
{
	spinlock_t lock;
	int cpu;

	spin_lock_init(&lock);

	cpu = get_cpu();

	CPC_INFO("Running on core %i\n", cpu);

	if (cpc_verify_topology())
		goto exit;

	cpc_ds = cpc_ds_alloc(&cpc_ds_ul);

	cpc_system_setup();

	spin_lock_irq(&lock);
	cpc_prime_probe_test();
	cpc_stream_hwpf_test();
	cpc_single_eviction_test(NULL);
	spin_unlock_irq(&lock);

exit:
	put_cpu();
}

void
cpc_kvm_init(void)
{
	int ret;

	cpc_debug = false;

	cpc_ds = NULL;
	cpc_ds_ul = NULL;

	cpc_retinst = 0;
	cpc_long_step = false;
	cpc_singlestep = false;
	cpc_singlestep_reset = false;
	cpc_prime_probe = false;
	cpc_track_mode = CPC_TRACK_NONE;

	cpc_apic_oneshot = false;
	cpc_apic_timer = 0;

	INIT_LIST_HEAD(&cpc_faults);

	cpc_msrmts = kzalloc(L1_SETS, GFP_KERNEL);
	BUG_ON(!cpc_msrmts);

	cpc_baseline_active = false;
	cpc_baseline_measure = false;
	cpc_baseline = kzalloc(L1_SETS, GFP_KERNEL);
	BUG_ON(!cpc_baseline);

	cpc_events_reset();

	ret = smp_call_function_single(CPC_ISOLCPU,
		cpc_setup_test, NULL, true);
	WARN_ON(ret != 0);
}

void
cpc_kvm_exit(void)
{
	kfree(cpc_msrmts);

	kfree(cpc_baseline);

	if (cpc_ds_ul)
		kfree(cpc_ds_ul);
}
