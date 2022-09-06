#include "kvm.h"

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <asm/uaccess.h>

struct proc_ops cachepc_proc_ops;

uint16_t *cachepc_msrmts;
size_t cachepc_msrmts_count;
EXPORT_SYMBOL(cachepc_msrmts);
EXPORT_SYMBOL(cachepc_msrmts_count);

cache_ctx *cachepc_ctx;
cacheline *cachepc_ds;
EXPORT_SYMBOL(cachepc_ctx);
EXPORT_SYMBOL(cachepc_ds);

int
cachepc_kvm_proc_open(struct inode *inode, struct file *file)
{
	try_module_get(THIS_MODULE);

	return 0;
}

int
cachepc_kvm_proc_close(struct inode *inode, struct file *file)
{
	module_put(THIS_MODULE);

	return 0;
}

ssize_t
cachepc_kvm_proc_read(struct file *file, char *buf, size_t buflen, loff_t *off)
{
	size_t len, left;
	size_t size;

	printk(KERN_WARNING "CachePC: Reading entries (%lu:%lli)\n",
		buflen, off ? *off : 0);

	size = cachepc_msrmts_count * sizeof(uint16_t);
	if (!off || *off >= size || *off < 0)
		return 0;

	len = size - *off;
	if (len > buflen) len = buflen;

	left = copy_to_user(buf, (uint8_t *) cachepc_msrmts + *off, len);

	len -= left;
	*off += len;

	return len;
}

ssize_t
cachepc_kvm_proc_write(struct file *file, const char *buf, size_t buflen, loff_t *off)
{
	return 0;
}

void
cachepc_kvm_prime_probe_test(void *p)
{
	cacheline *lines;
	cacheline *cl, *head;
	uint32_t count;
	uint32_t *arg;
	int i, max;

	arg = p;

	/* l2 data cache, hit or miss */
	cachepc_init_pmc(0, 0x64, 0xD8);

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

	arg = p;

	/* TODO: accurately detect hwpf */

	/* l2 data cache, hit or miss */
	cachepc_init_pmc(0, 0x64, 0xD8);

	lines = cachepc_aligned_alloc(PAGE_SIZE, cachepc_ctx->cache_size);
	BUG_ON(lines == NULL);

	max = cachepc_ctx->nr_of_cachelines;

	cachepc_prime(cachepc_ds);

	count -= cachepc_read_pmc(0);
	for (i = 0; i < max; i++)
		asm volatile ("mov (%0), %%rbx" : : "r"(lines + i) : "rbx");
	count += cachepc_read_pmc(0);

	printk(KERN_WARNING "CachePC: HWPF test done (%u vs. %u => %s)\n",
		count, max, (count == max) ? "passed" : "failed");

	if (arg) *arg = (count == max);

	kfree(lines);
}

void
cachepc_kvm_single_access_test(void *p)
{
	cacheline *ptr;
	uint64_t pre, post;
	uint32_t *arg;

	/* l2 data cache, hit or miss */
	cachepc_init_pmc(0, 0x64, 0xD8);

	arg = p;
	
	WARN_ON(arg && *arg >= L1_SETS);
	if (arg && *arg >= L1_SETS) return;	
	ptr = cachepc_prepare_victim(cachepc_ctx, arg ? *arg : 48);

	cachepc_prime(cachepc_ds);

	pre = cachepc_read_pmc(0);
	cachepc_victim(ptr);
	post = cachepc_read_pmc(0);

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

	/* l2 data cache, hit or miss */
	cachepc_init_pmc(0, 0x64, 0xD8);

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
		if (IS_FIRST(cl->flags) && cl->count > 0) {
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
	printk("CachePC: Writing MSR %08llX: %016llX\n", reg_addr, val);

	/* disable speculative data cache tlb reloads */
	reg_addr = 0xc0011022;
	asm volatile ("rdmsr" : "=a"(lo), "=d"(hi) : "c"(reg_addr));
	val = (uint64_t) lo | ((uint64_t) hi << 32);
	val |= 1 << 4;
	asm volatile ("wrmsr" : : "c"(reg_addr), "a"(val), "d"(0x00));
	printk("CachePC: Writing MSR %08llX: %016llX\n", reg_addr, val);

	/* disable data cache hardware prefetcher */
	reg_addr = 0xc0011022;
	asm volatile ("rdmsr" : "=a"(lo), "=d"(hi) : "c"(reg_addr));
	val = (uint64_t) lo | ((uint64_t) hi << 32);
	val |= 1 << 13;
	asm volatile ("wrmsr" : : "c"(reg_addr), "a"(val), "d"(0x00));
	printk("CachePC: Writing MSR %08llX: %016llX\n", reg_addr, val);
}

void
cachepc_kvm_init_pmc_ioctl(void *p)
{
	uint32_t event;
	uint8_t index, event_no, event_mask;

	WARN_ON(p == NULL);
	if (!p) return;

	event = *(uint32_t *)p;

	index = (event & 0xFF000000) >> 24;
	event_no = (event & 0x0000FF00) >> 8;
	event_mask = (event & 0x000000FF) >> 0;

	cachepc_init_pmc(index, event_no, event_mask);
}

long
cachepc_kvm_ioctl(struct file *file, unsigned int cmd, unsigned long argp)
{
	void __user *arg_user;
	uint32_t u32;
	int r;

	arg_user = (void __user *)argp;
	switch (cmd) {
	case CACHEPC_IOCTL_TEST_ACCESS:
		printk(KERN_WARNING "CachePC: Called ioctl access test\n");
		if (!arg_user) return -EINVAL;
		if (copy_from_user(&u32, arg_user, sizeof(uint32_t)))
			return -EFAULT;
		r = smp_call_function_single(2,
			cachepc_kvm_single_access_test, &u32, true);
		WARN_ON(r != 0);
		if (copy_to_user(arg_user, &u32, sizeof(uint32_t)))
			return -EFAULT;
		break;
	case CACHEPC_IOCTL_TEST_EVICTION:
		printk(KERN_WARNING "CachePC: Called ioctl eviction test\n");
		if (!arg_user) return -EINVAL;
		if (copy_from_user(&u32, arg_user, sizeof(uint32_t)))
			return -EFAULT;
		r = smp_call_function_single(2,
			cachepc_kvm_single_eviction_test, &u32, true);
		WARN_ON(r != 0);
		if (copy_to_user(arg_user, &u32, sizeof(uint32_t)))
			return -EFAULT;
		break;
	case CACHEPC_IOCTL_INIT_PMC:
		printk(KERN_WARNING "CachePC: Called ioctl init counter\n");
		if (!arg_user) return -EINVAL;
		if (copy_from_user(&u32, arg_user, sizeof(uint32_t)))
			return -EFAULT;
		r = smp_call_function_single(2,
			cachepc_kvm_init_pmc_ioctl, &u32, true);
		WARN_ON(r != 0);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

void
cachepc_kvm_setup_test(void *p)
{
	int cpu;

	cpu = get_cpu();

	printk(KERN_WARNING "CachePC: Running on core %i\n", cpu);

	cachepc_ctx = cachepc_get_ctx(L1);
	cachepc_ds = cachepc_prepare_ds(cachepc_ctx);

	cachepc_kvm_system_setup();

	cachepc_kvm_prime_probe_test(NULL);
	cachepc_kvm_single_access_test(NULL);
	cachepc_kvm_single_eviction_test(NULL);
	cachepc_kvm_stream_hwpf_test(NULL);

	put_cpu();
}

void
cachepc_kvm_init(void)
{
	int ret;

	cachepc_msrmts_count = L1_SETS;
	cachepc_msrmts = kzalloc(cachepc_msrmts_count * sizeof(uint16_t), GFP_KERNEL);
	BUG_ON(cachepc_msrmts == NULL);

	ret = smp_call_function_single(2, cachepc_kvm_setup_test, NULL, true);
	WARN_ON(ret != 0);

	memset(&cachepc_proc_ops, 0, sizeof(cachepc_proc_ops));
	cachepc_proc_ops.proc_open = cachepc_kvm_proc_open;
	cachepc_proc_ops.proc_read = cachepc_kvm_proc_read;
	cachepc_proc_ops.proc_write = cachepc_kvm_proc_write;
	cachepc_proc_ops.proc_release = cachepc_kvm_proc_close;
	cachepc_proc_ops.proc_ioctl = cachepc_kvm_ioctl;
	proc_create("cachepc", 0644, NULL, &cachepc_proc_ops);
}

void
cachepc_kvm_exit(void)
{
	remove_proc_entry("cachepc", NULL);
	kfree(cachepc_msrmts);

	cachepc_release_ds(cachepc_ctx, cachepc_ds);
	cachepc_release_ctx(cachepc_ctx);
}


