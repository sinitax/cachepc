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

bool cachepc_debug = false;
EXPORT_SYMBOL(cachepc_debug);

struct cacheline *cachepc_victim;
EXPORT_SYMBOL(cachepc_victim);

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

bool cachepc_singlestep = false;
bool cachepc_singlestep_reset = false;
bool cachepc_long_step = false;
EXPORT_SYMBOL(cachepc_singlestep);
EXPORT_SYMBOL(cachepc_singlestep_reset);
EXPORT_SYMBOL(cachepc_long_step);

bool cachepc_apic_oneshot = false;
uint32_t cachepc_apic_timer = 0;
EXPORT_SYMBOL(cachepc_apic_oneshot);
EXPORT_SYMBOL(cachepc_apic_timer);

uint32_t cachepc_track_mode = false;
uint64_t cachepc_track_start_gfn = 0;
uint64_t cachepc_track_end_gfn = 0;
EXPORT_SYMBOL(cachepc_track_mode);
EXPORT_SYMBOL(cachepc_track_start_gfn);
EXPORT_SYMBOL(cachepc_track_end_gfn);

LIST_HEAD(cachepc_faults);
EXPORT_SYMBOL(cachepc_faults);

struct cpc_track_exec cachepc_track_exec;
EXPORT_SYMBOL(cachepc_track_exec);

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

void cachepc_prime_probe_test_asm(void);
static noinline void cachepc_prime_probe_test(void);

uint64_t cachepc_stream_hwpf_test_asm(void *lines);
static noinline void cachepc_stream_hwpf_test(void);

void cachepc_single_eviction_test_asm(void *ptr);
static noinline void cachepc_single_eviction_test(void *p);

static void cachepc_kvm_system_setup(void);

static int cachepc_kvm_reset_ioctl(void __user *arg_user);
static int cachepc_kvm_debug_ioctl(void __user *arg_user);

static int cachepc_kvm_test_eviction_ioctl(void __user *arg_user);

static int cachepc_kvm_read_counts_ioctl(void __user *arg_user);

static int cachepc_kvm_reset_baseline_ioctl(void __user *arg_user);
static int cachepc_kvm_calc_baseline_ioctl(void __user *arg_user);
static int cachepc_kvm_read_baseline_ioctl(void __user *arg_user);
static int cachepc_kvm_apply_baseline_ioctl(void __user *arg_user);

static int cachepc_kvm_reset_tracking_ioctl(void __user *arg_user);
static int cachepc_kvm_track_mode_ioctl(void __user *arg_user);
// static int cachepc_kvm_track_page_ioctl(void __user *arg_user);
// static int cachepc_kvm_track_range_start_ioctl(void __user *arg_user);
// static int cachepc_kvm_track_range_end_ioctl(void __user *arg_user);
// static int cachepc_kvm_track_exec_cur_ioctl(void __user *arg_user);

static int cachepc_kvm_poll_event_ioctl(void __user *arg_user);
static int cachepc_kvm_ack_event_ioctl(void __user *arg_user);

static int cachepc_kvm_req_pause_ioctl(void __user *arg_user);

void
cachepc_prime_probe_test(void)
{
	int i, n, count;

	/* l2 data cache hit & miss */
	cachepc_init_pmc(CPC_L1MISS_PMC, 0x64, 0xD8, 0, PMC_KERNEL);

	for (n = 0; n < TEST_REPEAT_MAX; n++) {
		memset(cachepc_msrmts, 0, L1_SETS);
		cachepc_prime_probe_test_asm();
		cachepc_save_msrmts(cachepc_ds);

		count = 0;
		for (i = 0; i < L1_SETS; i++)
			count += cachepc_msrmts[i];

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
cachepc_stream_hwpf_test(void)
{
	const uint32_t max = 10;
	cacheline *lines;
	uint32_t count;
	int n;

	/* l2 data cache hit & miss */
	cachepc_init_pmc(CPC_L1MISS_PMC, 0x64, 0xD8, 0, PMC_KERNEL);

	lines = cachepc_aligned_alloc(L1_SIZE, L1_SIZE);

	count = 0;
	for (n = 0; n < TEST_REPEAT_MAX; n++) {
		count = cachepc_stream_hwpf_test_asm(lines);
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
cachepc_single_eviction_test(void *p)
{
	cacheline *victim;
	uint32_t target;
	uint32_t *arg;
	int n, i, count;

	arg = p;

	/* l2 data cache hit & miss */
	cachepc_init_pmc(CPC_L1MISS_PMC, 0x64, 0xD8, 0, PMC_KERNEL);

	WARN_ON(arg && *arg >= L1_SETS);
	if (arg && *arg >= L1_SETS) return;
	target = arg ? *arg : 48;

	victim = cachepc_prepare_victim(cachepc_ctx, target);

	for (n = 0; n < TEST_REPEAT_MAX; n++) {
		memset(cachepc_msrmts, 0, L1_SETS);
		cachepc_single_eviction_test_asm(victim);
		cachepc_save_msrmts(cachepc_ds);

		count = 0;
		for (i = 0; i < L1_SETS; i++)
			count += cachepc_msrmts[i];

		if (count != 1 || cachepc_msrmts[target] != 1) {
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

	cachepc_release_victim(cachepc_ctx, victim);
}

void
cachepc_kvm_system_setup(void)
{
	/* NOTE: since most of these MSRs are poorly documented and some
	 * guessing work was involved, it is likely that one or more of
	 * these operations are not needed */

	/* REF: BKDG Family 15h Model 00h-0Fh Rev 3.14 January 23, 2013 P.38 */
	/* disable streaming store */
	cachepc_write_msr(0xc0011020, 0, 1ULL << 28);
	/* disable data cache hw prefetcher */
	cachepc_write_msr(0xc0011022, 0, 1ULL << 13);

	/* REF: https://arxiv.org/pdf/2204.03290.pdf */
	/* l1 and l2 prefetchers */
	cachepc_write_msr(0xc0011022, 0, 1ULL << 16);
	cachepc_write_msr(0xc001102b, 1ULL << 0, 0);

	/* REF: https://community.amd.com/t5/archives-discussions/modifying-msr-to-disable-the-prefetcher/td-p/143443 */
	cachepc_write_msr(0xc001102b, 0, 1ULL << 18);

	/* REF: PPR Family 19h Model 01h Vol 1/2 Rev 0.50 May 27.2021 P.168 */
	/* disable L1 and L2 prefetcher */
	cachepc_write_msr(0xC0000108, 0, 0b00101111);

	/* REF: PPR Family 19h Model 01h Vol 1/2 Rev 0.50 May 27.2021 P.111 */
	/* disable speculation */
	cachepc_write_msr(0x00000048, 0, 0b10000111);
}

int
cachepc_kvm_reset_ioctl(void __user *arg_user)
{
	int cpu;

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

	cachepc_events_reset();

	cachepc_kvm_reset_tracking_ioctl(NULL);
	cachepc_kvm_reset_baseline_ioctl(NULL);

	cachepc_singlestep = false;
	cachepc_singlestep_reset = false;

	cachepc_apic_oneshot = false;
	cachepc_apic_timer = 0;

	cachepc_retinst = 0;
	cachepc_rip_prev_set = false;

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
cachepc_kvm_get_regs_ioctl(void __user *arg_user)
{
	struct kvm_regs *regs;
	struct kvm_vcpu *vcpu;

	if (!arg_user) return -EINVAL;

	if (!main_vm || xa_empty(&main_vm->vcpu_array))
		return -EFAULT;

	vcpu = xa_load(&main_vm->vcpu_array, 0);

	regs = kzalloc(sizeof(struct kvm_regs), GFP_KERNEL_ACCOUNT);
	if (!regs) return -ENOMEM;

	regs->rax = kvm_rax_read(vcpu);
	regs->rbx = kvm_rbx_read(vcpu);
	regs->rcx = kvm_rcx_read(vcpu);
	regs->rdx = kvm_rdx_read(vcpu);
	regs->rsi = kvm_rsi_read(vcpu);
	regs->rdi = kvm_rdi_read(vcpu);
	regs->rsp = kvm_rsp_read(vcpu);
	regs->rbp = kvm_rbp_read(vcpu);
#ifdef CONFIG_X86_64
	regs->r8 = kvm_r8_read(vcpu);
	regs->r9 = kvm_r9_read(vcpu);
	regs->r10 = kvm_r10_read(vcpu);
	regs->r11 = kvm_r11_read(vcpu);
	regs->r12 = kvm_r12_read(vcpu);
	regs->r13 = kvm_r13_read(vcpu);
	regs->r14 = kvm_r14_read(vcpu);
	regs->r15 = kvm_r15_read(vcpu);
#endif

	regs->rip = kvm_rip_read(vcpu);
	regs->rflags = kvm_get_rflags(vcpu);

	if (copy_to_user(arg_user, regs, sizeof(struct kvm_regs))) {
		kfree(regs);
		return -EFAULT;
	}

	kfree(regs);

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

	ret = smp_call_function_single(CPC_ISOLCPU,
		cachepc_single_eviction_test, &u32, true);
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
cachepc_kvm_long_step_ioctl(void __user *arg_user)
{
	if (arg_user) return -EINVAL;

	cachepc_long_step = true;

	return 0;
}

int
cachepc_kvm_reset_tracking_ioctl(void __user *arg_user)
{
	struct kvm_vcpu *vcpu;
	struct cpc_fault *fault, *next;

	if (!main_vm || xa_empty(&main_vm->vcpu_array))
		return -EFAULT;

	vcpu = xa_load(&main_vm->vcpu_array, 0);
	cachepc_untrack_all(vcpu, KVM_PAGE_TRACK_EXEC);
	cachepc_untrack_all(vcpu, KVM_PAGE_TRACK_ACCESS);
	cachepc_untrack_all(vcpu, KVM_PAGE_TRACK_WRITE);

	cachepc_track_start_gfn = 0;
	cachepc_track_end_gfn = 0;

	memset(&cachepc_track_exec, 0, sizeof(cachepc_track_exec));

	cachepc_singlestep = false;
	cachepc_singlestep_reset = false;

	cachepc_track_mode = CPC_TRACK_NONE;

	list_for_each_entry_safe(fault, next, &cachepc_faults, list) {
		list_del(&fault->list);
		kfree(fault);
	}

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

	if (!main_vm || xa_empty(&main_vm->vcpu_array))
		return -EFAULT;

	vcpu = xa_load(&main_vm->vcpu_array, 0);

	cachepc_untrack_all(vcpu, KVM_PAGE_TRACK_EXEC);
	cachepc_untrack_all(vcpu, KVM_PAGE_TRACK_ACCESS);
	cachepc_untrack_all(vcpu, KVM_PAGE_TRACK_WRITE);

	cachepc_apic_oneshot = false;
	cachepc_singlestep = false;
	cachepc_singlestep_reset = false;
	cachepc_long_step = false;

	switch (mode) {
	case CPC_TRACK_FULL:
		cachepc_track_all(vcpu, KVM_PAGE_TRACK_ACCESS);
		cachepc_singlestep_reset = true;
		break;
	case CPC_TRACK_EXEC:
		cachepc_track_all(vcpu, KVM_PAGE_TRACK_EXEC);
		cachepc_singlestep_reset = true;
		break;
	case CPC_TRACK_FAULT_NO_RUN:
		cachepc_track_all(vcpu, KVM_PAGE_TRACK_ACCESS);
		break;
	case CPC_TRACK_NONE:
		break;
	default:
		return -EINVAL;
	}

	cachepc_track_mode = mode;

	return 0;
}

// int
// cachepc_kvm_track_page_ioctl(void __user *arg_user)
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
// 	if (!cachepc_track_single(vcpu, cfg.gfn, cfg.mode))
// 		return -EFAULT;
// 
// 	return 0;
// }
//
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

int
cachepc_kvm_req_pause_ioctl(void __user *arg_user)
{
	if (arg_user) return -EINVAL;

	cachepc_pause_vm = true;

	return 0;
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
	case KVM_CPC_GET_REGS:
		return cachepc_kvm_get_regs_ioctl(arg_user);
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
	case KVM_CPC_LONG_STEP:
		return cachepc_kvm_long_step_ioctl(arg_user);
	case KVM_CPC_RESET_TRACKING:
		return cachepc_kvm_reset_tracking_ioctl(arg_user);
	case KVM_CPC_TRACK_MODE:
		return cachepc_kvm_track_mode_ioctl(arg_user);
	case KVM_CPC_POLL_EVENT:
		return cachepc_kvm_poll_event_ioctl(arg_user);
	case KVM_CPC_ACK_EVENT:
		return cachepc_kvm_ack_event_ioctl(arg_user);
	// case KVM_CPC_TRACK_PAGE:
	// 	return cachepc_kvm_track_page_ioctl(arg_user);
	// case KVM_CPC_TRACK_RANGE_START:
	// 	return cachepc_kvm_track_range_start_ioctl(arg_user);
	// case KVM_CPC_TRACK_RANGE_END:
	// 	return cachepc_kvm_track_range_end_ioctl(arg_user);
	// case KVM_CPC_TRACK_EXEC_CUR:
	// 	return cachepc_kvm_track_exec_cur_ioctl(arg_user);
	case KVM_CPC_VM_REQ_PAUSE:
		return cachepc_kvm_req_pause_ioctl(arg_user);
	default:
		return kvm_arch_dev_ioctl(file, ioctl, arg);
	}
}

void
cachepc_kvm_setup_test(void *p)
{
	spinlock_t lock;
	int cpu;

	cpu = get_cpu();

	CPC_INFO("Running on core %i\n", cpu);

	if (cachepc_verify_topology())
		goto exit;

	cachepc_ctx = cachepc_get_ctx();
	cachepc_ds = cachepc_prepare_ds(cachepc_ctx);

	cachepc_victim = cachepc_prepare_victim(cachepc_ctx, 15);

	cachepc_kvm_system_setup();

	spin_lock_irq(&lock);
	cachepc_prime_probe_test();
	cachepc_stream_hwpf_test();
	cachepc_single_eviction_test(NULL);
	spin_unlock_irq(&lock);

exit:
	put_cpu();
}

void
cachepc_kvm_init(void)
{
	int ret;

	cachepc_ctx = NULL;
	cachepc_ds = NULL;

	cachepc_debug = false;
	cachepc_victim = NULL;

	cachepc_retinst = 0;
	cachepc_long_step = false;
	cachepc_singlestep = false;
	cachepc_singlestep_reset = false;
	cachepc_track_mode = CPC_TRACK_NONE;

	cachepc_apic_oneshot = false;
	cachepc_apic_timer = 0;

	memset(&cachepc_track_exec, 0, sizeof(cachepc_track_exec));

	INIT_LIST_HEAD(&cachepc_faults);

	cachepc_msrmts = kzalloc(L1_SETS, GFP_KERNEL);
	BUG_ON(!cachepc_msrmts);

	cachepc_baseline_active = false;
	cachepc_baseline_measure = false;
	cachepc_baseline = kzalloc(L1_SETS, GFP_KERNEL);
	BUG_ON(!cachepc_baseline);

	cachepc_events_reset();

	ret = smp_call_function_single(CPC_ISOLCPU,
		cachepc_kvm_setup_test, NULL, true);
	WARN_ON(ret != 0);
}

void
cachepc_kvm_exit(void)
{
	kfree(cachepc_msrmts);
	kfree(cachepc_baseline);
	kfree(cachepc_victim);

	if (cachepc_ds)
		cachepc_release_ds(cachepc_ctx, cachepc_ds);

	if (cachepc_ctx)
		cachepc_release_ctx(cachepc_ctx);
}
