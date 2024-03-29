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

#define TEST_REPEAT_MAX 50

uint32_t cpc_loglevel = 0;
EXPORT_SYMBOL(cpc_loglevel);

uint8_t *cpc_msrmts = NULL;
uint8_t *cpc_baseline = NULL;
bool cpc_baseline_measure = false;
bool cpc_baseline_active = false;
EXPORT_SYMBOL(cpc_msrmts);
EXPORT_SYMBOL(cpc_baseline);
EXPORT_SYMBOL(cpc_baseline_measure);
EXPORT_SYMBOL(cpc_baseline_active);

uint32_t cpc_guest_misses = 0;
uint32_t cpc_baseline_guest_misses = 0;
EXPORT_SYMBOL(cpc_guest_misses);
EXPORT_SYMBOL(cpc_baseline_guest_misses);

uint32_t cpc_svm_exitcode = false;
EXPORT_SYMBOL(cpc_svm_exitcode);

bool cpc_pause_vm = false;
EXPORT_SYMBOL(cpc_pause_vm);

bool cpc_prime_probe = false;
EXPORT_SYMBOL(cpc_prime_probe);

uint64_t cpc_retinst = 0;
uint64_t cpc_retinst_user = 0;
uint64_t cpc_retinst_prev = 0;
EXPORT_SYMBOL(cpc_retinst);
EXPORT_SYMBOL(cpc_retinst_user);
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
int32_t cpc_apic_timer = 0;
EXPORT_SYMBOL(cpc_apic_oneshot);
EXPORT_SYMBOL(cpc_apic_timer);

int32_t cpc_apic_timer_softdiv = 1;
int32_t cpc_apic_timer_min = 0;
int32_t cpc_apic_timer_dec_npf = 0;
int32_t cpc_apic_timer_dec_intr = 0;
EXPORT_SYMBOL(cpc_apic_timer_softdiv);
EXPORT_SYMBOL(cpc_apic_timer_min);
EXPORT_SYMBOL(cpc_apic_timer_dec_npf);
EXPORT_SYMBOL(cpc_apic_timer_dec_intr);

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
struct cpc_cl *cpc_ds_probe = NULL;
EXPORT_SYMBOL(cpc_ds);
EXPORT_SYMBOL(cpc_ds_probe);

uint64_t cpc_stream_hwpf_test_asm(struct cpc_cl *lines);
static noinline void cpc_stream_hwpf_test(void);

uint64_t cpc_prime_test1_asm(void);
static noinline void cpc_prime_test1(void);

uint64_t cpc_prime_test2_asm(struct cpc_cl *lines);
static noinline void cpc_prime_test2(void);

uint64_t cpc_prime_test3_asm(struct cpc_cl *cl, struct cpc_cl *lines);
static noinline void cpc_prime_test3(void);

uint64_t cpc_eviction_prio_test_asm(struct cpc_cl *access, struct cpc_cl *cl);
static noinline void cpc_eviction_prio_test(void);

void cpc_prime_probe_test_asm(void);
static noinline void cpc_prime_probe_test(void);

uint64_t cpc_single_eviction_test_asm(void *ptr);
static noinline void cpc_single_eviction_test(void *p);

static void cpc_pmc_setup(void *p);
static void cpc_system_setup(void);

static int cpc_reset_ioctl(void __user *arg_user);
static int cpc_deinit_ioctl(void __user *arg_user);

static int cpc_loglevel_ioctl(void __user *arg_user);

static int cpc_memory_encrypt_op_ioctl(void __user *arg_user);

static int cpc_test_eviction_ioctl(void __user *arg_user);

static int cpc_read_counts_ioctl(void __user *arg_user);

static int cpc_reset_baseline_ioctl(void __user *arg_user);
static int cpc_calc_baseline_ioctl(void __user *arg_user);
static int cpc_read_baseline_ioctl(void __user *arg_user);
static int cpc_apply_baseline_ioctl(void __user *arg_user);

static int cpc_reset_tracking_ioctl(void __user *arg_user);
static int cpc_track_mode_ioctl(void __user *arg_user);

static int cpc_req_pause_ioctl(void __user *arg_user);


void
cpc_stream_hwpf_test(void)
{
	const uint32_t max = 0;
	struct cpc_cl *lines;
	uint32_t count;
	int n;

	/* l1 hardware prefetches */
	cpc_init_pmc(0, 0x70, 0xE0, 0, PMC_KERNEL);
	cpc_init_pmc(1, 0x71, 0xE0, 0, PMC_KERNEL);
	cpc_init_pmc(2, 0x72, 0xE0, 0, PMC_KERNEL);

	/* l2 hardware prefetches */
	cpc_init_pmc(3, 0x70, 0x1F, 0, PMC_KERNEL);
	cpc_init_pmc(4, 0x71, 0x1F, 0, PMC_KERNEL);
	cpc_init_pmc(5, 0x72, 0x1F, 0, PMC_KERNEL);

	lines = cpc_aligned_alloc(L1_SIZE, L1_SIZE);

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
cpc_prime_test1(void)
{
	const uint64_t max = L1_SETS * L1_ASSOC;
	uint64_t ret;
	int n;

	CPC_L1MISS_PMC_INIT(0);

	for (n = 0; n < TEST_REPEAT_MAX; n++) {
		ret = cpc_prime_test1_asm();
		if (ret != max) {
			CPC_ERR("Prime (1) %i. test failed (%llu vs. %llu)\n",
				n, ret, max);
			break;
		}
	}

	if (n == TEST_REPEAT_MAX)
		CPC_INFO("Prime (1) test ok (%llu vs. %llu)\n", ret, max);
}

void
cpc_prime_test2(void)
{
	const uint64_t max = 0;
	struct cpc_cl *lines;
	uint64_t ret;
	int n;

	CPC_L1MISS_PMC_INIT(0);

	lines = cpc_aligned_alloc(PAGE_SIZE, L1_SIZE);

	for (n = 0; n < TEST_REPEAT_MAX; n++) {
		ret = cpc_prime_test2_asm(lines);
		if (ret != max) {
			CPC_ERR("Prime (2) %i. test failed (%llu vs. %llu)\n",
				n, ret, max);
			break;
		}
	}

	if (n == TEST_REPEAT_MAX)
		CPC_INFO("Prime (2) test ok (%llu vs. %llu)\n", ret, max);

	kfree(lines);
}

void
cpc_prime_test3(void)
{
	uint64_t count;
	struct cpc_cl *lines;
	struct cpc_cl *cl;
	int n, set, line;

	CPC_L1MISS_PMC_INIT(0);

	lines = cpc_aligned_alloc(PAGE_SIZE, L1_SIZE);

	for (n = 0; n < TEST_REPEAT_MAX; n++) {
		cl = cpc_ds;
		for (set = 0; set < L1_SETS; set++) {
			count = cpc_prime_test3_asm(cl, &lines[set]);
			for (line = 0; line < L1_ASSOC; line++)
				cl = cl->next;
			if (count) {
				CPC_ERR("Prime (3) %u. test failed "
					"(set %u, count %llu)\n",
					n, set, count);
				goto exit;
			}
		}
	}

exit:
	if (n == TEST_REPEAT_MAX)
		CPC_INFO("Prime (3) test ok\n");

	kfree(lines);
}

void
cpc_eviction_prio_test(void)
{
	uint64_t ret, count;
	struct cpc_cl *access_ul, *access;
	struct cpc_cl *cl;
	int n, set, line, evic;

	CPC_L1MISS_PMC_INIT(0);

	access_ul = cpc_aligned_alloc(L1_SIZE, L1_SIZE);

	for (n = 0; n < TEST_REPEAT_MAX / 2; n++) {
		cl = cpc_ds;
		for (set = 0; set < L1_SETS; set++) {
			access = &access_ul[set];
			count = 0;
			evic = -1;
			for (line = 0; line < L1_ASSOC; line++) {
				ret = cpc_eviction_prio_test_asm(access, cl);
				if (ret) {
					evic = line;
					count++;
				}
				cl = cl->next;
			}
			if (!count) {
				CPC_ERR("Eviction prio %u. test failed "
					"(set %u, count %llu)\n",
					n, set, count);
				break;
			}
			if (count > 1 || evic != 0) {
				CPC_ERR("Eviction prio %u. test failed "
					"(set %u, count %llu, evic %u vs %u)\n",
					n, set, count, evic, 0);
				break;
			}
		}
		if (set != L1_SETS) break;
	}

	if (n == TEST_REPEAT_MAX)
		CPC_INFO("Eviction prio test ok\n");

	kfree(access_ul);
}

void
cpc_prime_probe_test(void)
{
	int i, n, count;

	CPC_L1MISS_PMC_INIT(0);

	for (n = 0; n < TEST_REPEAT_MAX; n++) {
		memset(cpc_msrmts, 0, L1_SETS);
		cpc_prime_probe_test_asm();
		cpc_save_msrmts(cpc_ds);

		count = 0;
		for (i = 0; i < L1_SETS; i++)
			count += cpc_msrmts[i];

		if (count != 0) {
			CPC_ERR("Prime+Probe %i. test failed (%u vs. %u)\n",
				n, count, 0);
			break;
		}
	}

	if (n == TEST_REPEAT_MAX)
		CPC_INFO("Prime+Probe test ok (%u vs. %u)\n", count, 0);
}

void
cpc_single_eviction_test(void *p)
{
	struct cpc_cl *victim_ul;
	struct cpc_cl *victim;
	uint32_t target, *arg;
	uint64_t ret;
	int n, i, count;

	arg = p;

	CPC_L1MISS_PMC_INIT(0);

	/* interrupts taken */
	cpc_init_pmc(1, 0x2C, 0x00, 0, 0);

	WARN_ON(arg && *arg >= L1_SETS);
	if (arg && *arg >= L1_SETS) return;
	target = arg ? *arg : 48;

	victim_ul = cpc_aligned_alloc(PAGE_SIZE, L1_SIZE);
	victim = &victim_ul[target];

	for (n = 0; n < TEST_REPEAT_MAX; n++) {
		memset(cpc_msrmts, 0, L1_SETS);
		ret = cpc_single_eviction_test_asm(victim);
		cpc_save_msrmts(cpc_ds);

		count = 0;
		for (i = 0; i < L1_SETS; i++)
			count += cpc_msrmts[i];

		if (count != 1 || cpc_msrmts[target] != 1) {
			CPC_ERR("Single eviction %i. test failed (%u vs %u) (intr %llu)\n",
				n, count, 1, ret);
			if (arg) *arg = 1;
			break;
		}

		if (ret != 0)
			CPC_INFO("Single eviction %llu interrupts but no issue\n", ret);
	}

	if (n == TEST_REPEAT_MAX) {
		CPC_INFO("Single eviction test ok (%u vs %u)\n", count, 1);
		if (arg) *arg = 0;
	}

	kfree(victim_ul);
}

void
cpc_pmc_setup(void *p)
{
	/* L1 misses in host kernel */
	CPC_L1MISS_PMC_INIT(CPC_L1MISS_PMC);

	/* L1 misses in guest */
	CPC_L1MISS_GUEST_PMC_INIT(CPC_L1MISS_GUEST_PMC);

	/* retired instructions in guest */
	CPC_RETINST_PMC_INIT(CPC_RETINST_PMC);

	/* retired instructions in guest userspace */
	CPC_RETINST_USER_PMC_INIT(CPC_RETINST_USER_PMC);
}

void
cpc_system_setup(void)
{
	uint32_t n;

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

	//for (n = 0; n < 8; n++)
	//	CPC_INFO("MASK %u: %08llx\n", n, __rdmsr(0x848 + n) & 0xffffffff);
	(void)n;
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
cpc_deinit_ioctl(void __user *arg_user)
{
	cpc_events_skip();
	return 0;
}

int
cpc_loglevel_ioctl(void __user *arg_user)
{
	uint32_t level;

	if (!arg_user) return -EINVAL;

	if (copy_from_user(&level, arg_user, sizeof(uint32_t)))
		return -EFAULT;

	cpc_loglevel = level;

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
	cpc_baseline_guest_misses = 0xffffffff;

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

	cpc_apic_timer_softdiv = 3;
	if (sev_es_guest(vcpu->kvm)) {
		cpc_apic_timer_min = 200;
		cpc_apic_timer_dec_npf = 25;
		cpc_apic_timer_dec_intr = 50;
	} else {
		cpc_apic_timer_min = 15;
		cpc_apic_timer_dec_npf = 5;
		cpc_apic_timer_dec_intr = 10;
	}

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
		cpc_track_pages.singlestep_resolve = cfg.pages.singlestep_resolve;
		cpc_track_all(vcpu, KVM_PAGE_TRACK_EXEC);
		break;
	case CPC_TRACK_STEPS:
		cpc_track_steps.use_target = cfg.steps.use_target;
		cpc_track_steps.target_user = cfg.steps.target_user;
		cpc_track_steps.target_gfn = cfg.steps.target_gfn;
		cpc_track_steps.with_data = cfg.steps.with_data;
		cpc_track_steps.use_filter = cfg.steps.use_filter;
		cpc_track_steps.in_target = false;
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
			cpc_track_single(vcpu, cpc_track_steps.target_gfn,
				KVM_PAGE_TRACK_EXEC);
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
	case KVM_CPC_DEINIT:
		return cpc_deinit_ioctl(arg_user);
	case KVM_CPC_LOGLEVEL:
		return cpc_loglevel_ioctl(arg_user);
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
	case KVM_CPC_BATCH_EVENTS:
		return cpc_batch_events_ioctl(arg_user);
	case KVM_CPC_READ_BATCH:
		return cpc_read_batch_ioctl(arg_user);
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
	uint64_t intr_count;
	uint64_t shared_l2;
	uint32_t taskpri;
	uint32_t prev_ctrl, ctrl;
	uint32_t prev_mask[8];
	int n, cpu;

	spin_lock_init(&lock);

	cpu = get_cpu();

	CPC_INFO("Running on core %i\n", cpu);

	if (cpc_verify_topology())
		goto exit;

	cpc_system_setup();

	(void) taskpri;
	//taskpri = native_apic_mem_read(APIC_TASKPRI);
	//CPC_INFO("TASK PRI %u\n", taskpri);
	//native_apic_mem_write(APIC_TASKPRI, 0xff);

	(void) prev_ctrl;
	(void) ctrl;
	(void) prev_mask;
	// prev_ctrl = native_apic_mem_read(APIC_ECTRL);
	// ctrl = prev_ctrl | 1;
	// native_apic_mem_write(APIC_ECTRL, ctrl);

	(void) n;
	// for (n = 0; n < 8; n++) {
	// 	prev_mask[n] = native_apic_mem_read(0x480 + 0x10 * n);
	// 	native_apic_mem_write(0x480 + 0x10 * n, 0x00);
	// }

	cpc_init_pmc(4, 0x60, 0b100000, 0, 0);
	cpc_init_pmc(5, 0x2C, 0x00, 0, 0);

	spin_lock_irq(&lock);

	shared_l2 = cpc_read_pmc(4);
	intr_count = cpc_read_pmc(5);

	cpc_stream_hwpf_test();
	cpc_prime_test1();
	cpc_prime_test2();
	cpc_prime_test3();
	cpc_eviction_prio_test();
	cpc_prime_probe_test();
	cpc_single_eviction_test(NULL);

	shared_l2 = cpc_read_pmc(4) - shared_l2;
	intr_count = cpc_read_pmc(5) - intr_count;
	CPC_INFO("Shared L2 accesses: %llu\n", shared_l2);
	CPC_INFO("Interrupts during test: %llu\n", intr_count);

	spin_unlock_irq(&lock);

	// native_apic_mem_write(APIC_ECTRL, prev_ctrl);
	// for (n = 0; n < 8; n++) {
	// 	native_apic_mem_write(0x480 + 0x10 * n, prev_mask[n]);
	// }

	//native_apic_mem_write(APIC_TASKPRI, taskpri);

exit:
	put_cpu();
}

void
cpc_kvm_init(void)
{
	int ret;

	cpc_loglevel = 1;

	cpc_ds = cpc_ds_alloc(&cpc_ds_ul);
	cpc_ds_probe = cpc_ds->prev;

	cpc_retinst = 0;
	cpc_retinst_user = 0;
	cpc_long_step = false;
	cpc_singlestep = false;
	cpc_singlestep_reset = false;
	cpc_prime_probe = false;
	cpc_track_mode = CPC_TRACK_NONE;

	cpc_apic_oneshot = false;
	cpc_apic_timer = 0;

	cpc_apic_timer_softdiv = 1;
	cpc_apic_timer_min = 0;
	cpc_apic_timer_dec_npf = 0;
	cpc_apic_timer_dec_intr = 0;

	INIT_LIST_HEAD(&cpc_faults);

	cpc_msrmts = kzalloc(L1_SETS, GFP_KERNEL);
	BUG_ON(!cpc_msrmts);

	cpc_baseline_active = false;
	cpc_baseline_measure = false;
	cpc_baseline = kzalloc(L1_SETS, GFP_KERNEL);
	BUG_ON(!cpc_baseline);

	cpc_events_init();

	ret = smp_call_function_single(CPC_ISOLCPU,
		cpc_setup_test, NULL, true);
	WARN_ON(ret != 0);
}

void
cpc_kvm_exit(void)
{
	cpc_events_deinit();

	kfree(cpc_msrmts);

	kfree(cpc_baseline);

	if (cpc_ds_ul)
		kfree(cpc_ds_ul);
}
