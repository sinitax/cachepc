#include "kvm.h"
#include "uspt.h"
#include "cachepc.h"
#include "sevstep.h"
#include "uapi.h"

#include <linux/kvm_host.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <asm/uaccess.h>

uint16_t *cachepc_msrmts = NULL;
size_t cachepc_msrmts_count = 0;
EXPORT_SYMBOL(cachepc_msrmts);
EXPORT_SYMBOL(cachepc_msrmts_count);

cache_ctx *cachepc_ctx = NULL;
cacheline *cachepc_ds = NULL;
EXPORT_SYMBOL(cachepc_ctx);
EXPORT_SYMBOL(cachepc_ds);

uint64_t cachepc_regs_tmp[16];
uint64_t cachepc_regs_vm[16];
EXPORT_SYMBOL(cachepc_regs_tmp);
EXPORT_SYMBOL(cachepc_regs_vm);

static long
get_user_pages_remote_unlocked(struct mm_struct *mm,
	unsigned long start, unsigned long nr_pages,
	unsigned int gup_flags, struct page **pages)
{
	struct vm_area_struct **vmas = NULL;
	int locked = 1;
	long ret;

	down_read(&mm->mmap_lock);
	ret = get_user_pages_remote( mm, start, nr_pages,
		gup_flags, pages, vmas, &locked);
	if (locked) up_read(&mm->mmap_lock);

	return ret;
}

// static int
// get_hpa_for_gpa(struct kvm *kvm, gpa_t gpa, hpa_t *hpa)
// {
// 	int ec;
// 	unsigned long hva;
// 	struct page *page = NULL;
// 
// 	ec = 0;
// 
// 	hva = gfn_to_hva(kvm, gpa_to_gfn(gpa));
// 	if (kvm_is_error_hva(hva)) {
// 		pr_warn("in %s line %d get_hpa_for_gpa: translation to hva failed\n",
// 			 __FILE__, __LINE__);
// 		ec = -100;
// 		goto out;
// 	}
// 	if (get_user_pages_remote_unlocked(kvm->mm, hva, 1, 0, &page) != 1) {
// 		pr_warn("in %s line %d get_hpa_for_gpa: failed to get page struct from mm",
// 			__FILE__, __LINE__);
// 		ec = -KVM_EINVAL;
// 		goto out;
// 	}
// 
// 	(*hpa) = (page_to_pfn(page) << 12) + (gpa & 0xfff);
// 
// out:
// 	put_page(page);
// 
// 	return ec;
// }

int
read_physical(struct kvm *kvm, u64 gpa, void *buff, u64 size,
		bool decrypt_at_host)
{
	unsigned long hva;
	struct page *page = NULL;
	void *ptr_page = NULL;
	uint64_t offset;
	int ec;

	offset = (gpa & 0xFFF);

	if ((offset + size - 1) > 0xFFF) {
		printk("read_phyiscal: trying to read "
			"beyond page (offset+size=%016llx)\n",
			offset + size);
		return -EINVAL;
	}

	ec = 0;

	hva = gfn_to_hva(kvm, gpa_to_gfn(gpa));

	// TODO: test change
	/*
	if (kvm_is_error_hva(hva)) {
		printk(KERN_CRIT "Luca: read_physical: translation to hva failed( gpa was "
										 "%016llx hva is %016lx\n",
					 gpa, hva);
		ec = -100;
		goto out;
	}
	*/

	if (get_user_pages_remote_unlocked(kvm->mm, hva, 1, 0, &page) != 1) {
		pr_warn("read_physical: failed to get page struct from mm\n");
		// ec = -KVM_EINVAL;
		ec = -100;
		goto out;
	}

	if (decrypt_at_host) {
		// map with encryption bit. Content is decrypted with host key. If sev is
		// disabled but sme is enable this allows to read the plaintext.
		ptr_page = vmap(&page, 1, 0, PAGE_KERNEL_NOCACHE);
	} else {
		// map without encryption bit to read ciphertexts
		ptr_page = vmap(&page, 1, 0, __pgprot(__PAGE_KERNEL_NOCACHE));
	}

	/*printk("value of buff ptr = %p\t value of ptr_page=%p\n", buff,
				 ptr_page + offset);*/
	memcpy(buff, ptr_page + offset, size);

out:
	if (ptr_page)
		vunmap(ptr_page);
	if (page)
		put_page(page);

	return ec;
}

int
print_physical(struct kvm *kvm, u64 gpa, u64 size, bool decrypt_at_host)
{
	u8 *buffer;
	int i, err;

	buffer = kmalloc(size, GFP_ATOMIC);

	err = read_physical(kvm, gpa, buffer, size, decrypt_at_host);
	if (err != 0) {
		pr_warn("at %s line %d: read_physical "
			"failed with: %d\n", __FILE__, __LINE__, err);
	}
	for (i = 0; i < size; i++) {
		// print bytewise with line break every 16 bytes
		if (i % 16 == 0) {
			printk("%02x ", buffer[i]);
		} else {
			printk(KERN_CONT " %02x ", buffer[i]);
		}
	}
	printk("\n");

	kfree(buffer);

	return err;
}

int
map_physical(struct kvm *kvm, u64 gpa, bool decrypt_at_host,
	void **mapping, struct page **page)
{

	int ec;
	unsigned long hva;
	uint64_t offset;

	offset = (gpa & 0xFFF);

	ec = 0;

	hva = gfn_to_hva(kvm, gpa_to_gfn(gpa));

	if (get_user_pages_remote_unlocked(kvm->mm, hva, 1, 0, page) != 1) {
		pr_warn("map_physical: failed to get page struct from mm");
		// ec = -KVM_EINVAL;
		ec = -100;
		return ec;
	}

	if (decrypt_at_host) {
		// map with encryption bit. Content is decrypted with host key. If sev is
		// disabled but sme is enable this allows to read the plaintext.
		(*mapping) = vmap(page, 1, 0, PAGE_KERNEL);
	} else {
		// map without encryption bit to read ciphertexts
		(*mapping) = vmap(page, 1, 0, __pgprot(__PAGE_KERNEL));
	}

	return ec;
}

void
unmap_physical(void **mapping, struct page **page)
{
	if (*mapping)
		vunmap(*mapping);
	if (*page)
		put_page(*page);
}

int
read_mapped(u64 gpa, void *buff, u64 size, void *mapping)
{
	uint64_t offset;
	offset = (gpa & 0xFFF);

	if ((offset + size - 1) > 0xFFF) {
		pr_warn("read_mapped: trying to read "
			"beyond page (offset+size=%016llx)\n",
			offset + size);
		return -EINVAL;
	}
	memcpy(buff, mapping + offset, size);

	return 0;
}

int
write_mapped(u64 gpa, u64 size, const void *buf, void *mapping)
{
	uint64_t offset;

	offset = (gpa & 0xFFF);

	if ((offset + size - 1) > 0xFFF) {
		printk("write_physical: trying to write beyond page(offset+size=%016llx)\n",
					 offset + size);
		return -EINVAL;
	}
	memcpy(mapping + offset, buf, size);

	return 0;
}

int
write_physical(struct kvm *kvm, u64 gpa, u64 size,
		const void *buf, bool write_plaintexts)
{
	int ec;
	unsigned long hva;
	struct page *page;
	void *ptr_page;
	uint64_t offset;

	offset = (gpa & 0xFFF);

	if ((offset + size - 1) > 0xFFF) {
		pr_warn("write_physical: trying to write "
			"beyond page(offset+size=%016llx)\n",
			offset + size);
		return -EINVAL;
	}

	ec = 0;
	hva = gfn_to_hva(kvm, gpa_to_gfn(gpa));

	if (kvm_is_error_hva(hva))
		return -KVM_EINVAL;

	if (get_user_pages_remote_unlocked(kvm->mm, hva, 1, FOLL_WRITE, &page) != 1)
		return -KVM_EINVAL;

	if (write_plaintexts) {
		// map with encrytpion bit to aplly host encryption. Usefull if sev is
		// disabled but sme is enabled and we want to write a certain value into a
		// page
		ptr_page = vmap(&page, 1, 0, PAGE_KERNEL_NOCACHE);
	} else {
		// map without encryption bit to write ciphertexts
		ptr_page = vmap(&page, 1, 0, __pgprot(__PAGE_KERNEL_NOCACHE));
	}

	memcpy(ptr_page + offset, buf, size);

	vunmap(ptr_page);
	put_page(page);
	return ec;
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

	/* l2 data cache hit & miss */
	cachepc_init_pmc(0, 0x64, 0xD8, PMC_HOST, PMC_KERNEL);

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

	/* TODO: improve detection */

	/* l2 data cache hit & miss */
	cachepc_init_pmc(0, 0x64, 0xD8, PMC_HOST, PMC_KERNEL);

	lines = cachepc_aligned_alloc(PAGE_SIZE, cachepc_ctx->cache_size);
	BUG_ON(lines == NULL);

	max = cachepc_ctx->nr_of_cachelines;

	count = 0;
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

	/* l2 data cache hit & miss */
	cachepc_init_pmc(0, 0x64, 0xD8, PMC_HOST, PMC_KERNEL);

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

	/* l2 data cache hit & miss */
	cachepc_init_pmc(0, 0x64, 0xD8, PMC_HOST, PMC_KERNEL);

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
	uint8_t index, event_no, event_mask;
	uint8_t host_guest, kernel_user;
	uint32_t event;

	WARN_ON(p == NULL);
	if (!p) return;

	event = *(uint32_t *)p;

	index       = (event & 0xFF000000) >> 24;
	host_guest  = (event & 0x00300000) >> 20;
	kernel_user = (event & 0x00030000) >> 16;
	event_no    = (event & 0x0000FF00) >> 8;
	event_mask  = (event & 0x000000FF) >> 0;

	cachepc_init_pmc(index, event_no, event_mask,
		host_guest, kernel_user);
}

int
cachepc_kvm_track_page_ioctl(void __user *arg_user)
{
	track_page_param_t param;
	struct kvm_vcpu *vcpu;

	if (!arg_user) return -EINVAL;

	if (copy_from_user(&param, arg_user, sizeof(param))) {
		pr_warn("KVM_TRACK_PAGE: error copying arguments, exiting\n");
		return -EFAULT;
	}

	if (main_vm == NULL) {
		pr_warn("KVM_TRACK_PAGE: main_vm is not initialized, aborting!\n");
		return -EFAULT;
	}

	if (param.track_mode < 0 || param.track_mode >= KVM_PAGE_TRACK_MAX) {
		pr_warn("KVM_TRACK_PAGE track_mode %d invalid, "
			"must be in range [%d,%d]", param.track_mode,
			0, KVM_PAGE_TRACK_MAX);
		return -EFAULT;
	}

	vcpu = xa_load(&main_vm->vcpu_array, 0);
	if (!sevstep_track_single_page(vcpu,
			param.gpa >> PAGE_SHIFT, param.track_mode)) {
		printk("KVM_TRACK_PAGE: sevstep_track_single_page failed");
	}

	return 0;
}

int
cachepc_kvm_batch_track_start_ioctl(void __user *arg_user)
{
	batch_track_config_t param;
	int ret;

	if (!arg_user) return -EINVAL;

	if (copy_from_user(&param, arg_user, sizeof(param))) {
		pr_warn("KVM_USPT_BATCH_TRACK_START: "
			"error copying arguments, exiting\n");
		return -EFAULT;
	}

	ret = sevstep_uspt_batch_tracking_start(param.tracking_type,
		param.expected_events, param.perf_cpu, param.retrack);
	if (ret != 0) {
		pr_warn("KVM_USPT_BATCH_TRACK_START: failed\n");
		return ret;
	}

	return 0;
}

int
cachepc_kvm_batch_track_count_ioctl(void __user *arg_user)
{
	batch_track_event_count_t result;

	if (!arg_user) return -EINVAL;

	result.event_count = sevstep_uspt_batch_tracking_get_events_count();

	if (copy_to_user(arg_user, &result, sizeof(result))) {
		pr_warn("KVM_USPT_BATCH_TRACK_EVENT_COUNT: "
			"error copying result to user, exiting\n");
		return -EFAULT;
	}

	return 0;
}

int
cachepc_kvm_batch_track_stop_ioctl(void __user *arg_user)
{
	batch_track_stop_and_get_t param;
	page_fault_event_t* buf;
	uint64_t buf_bytes;
	void __user* inner_user_out_buf;
	int ret;

	if (!arg_user) return -EINVAL;

	if (copy_from_user(&param, arg_user, sizeof(param))) {
		pr_warn("KVM_USPT_BATCH_TRACK_STOP: "
			"error copying arguments, exiting\n");
		return -EFAULT;
	}
	inner_user_out_buf = param.out_buf;

	buf_bytes = sizeof(page_fault_event_t)*param.len;
	pr_warn("KVM_USPT_BATCH_TRACK_STOP: "
		"allocating %llu bytes for tmp buf\n", buf_bytes);

	buf = vmalloc(buf_bytes);
	if (buf == NULL) {
		pr_warn("KVM_USPT_BATCH_TRACK_STOP: "
			"failed to alloc tmp buf\n");
		return -EFAULT;
	}
	param.out_buf = buf;

	ret = sevstep_uspt_batch_tracking_stop(buf, param.len,
		&param.error_during_batch);
	if (ret != 0) {
		pr_warn("KVM_USPT_BATCH_TRACK_STOP: failed\n");
		vfree(buf);
		return -EFAULT;
	}

	if (copy_to_user(arg_user, &param, sizeof(param))) {
		pr_warn("KVM_USPT_BATCH_TRACK_STOP: "
			"error copying result to user, exiting\n");
		vfree(buf);
		return -EFAULT;
	}

	if (copy_to_user(inner_user_out_buf, buf,buf_bytes)) {
		pr_warn("KVM_USPT_BATCH_TRACK_STOP: "
			"error copying result to user, exiting\n");
		vfree(buf);
		return -EFAULT;
	}

	vfree(buf);

	return 0;
}

int
cachepc_kvm_track_all_ioctl(void __user *arg_user)
{
	track_all_pages_t param;
	struct kvm_vcpu *vcpu;
	long tracked_pages;

	if (!arg_user) return -EINVAL;

	if (copy_from_user(&param, arg_user, sizeof(param))) {
		pr_warn("KVM_USPT_TRACK_ALL: error copying arguments, exiting\n");
		return -EFAULT;
	}

	if (main_vm == NULL) {
		pr_warn("KVM_USPT_TRACK_ALL: main_vm is not initialized, aborting!\n");
		return -EFAULT;
	}

	if (param.track_mode < 0 || param.track_mode >= KVM_PAGE_TRACK_MAX) {
		pr_warn("KVM_USPT_TRACK_ALL: "
			"track_mode %d invalid, must be in range [%d,%d]\n",
			param.track_mode, 0, KVM_PAGE_TRACK_MAX);
		return -EFAULT;
	}

	vcpu = xa_load(&main_vm->vcpu_array, 0);
	tracked_pages = sevstep_start_tracking(vcpu, param.track_mode);

	return 0;
}

int
cachepc_kvm_untrack_all_ioctl(void __user *arg_user)
{
	track_all_pages_t param;
	struct kvm_vcpu *vcpu;
	long untrack_count;

	if (!arg_user) return -EINVAL;

	if (copy_from_user(&param, arg_user, sizeof(param))) {
		printk(KERN_CRIT "KVM_USPT_UNTRACK_ALL: error copying arguments, exiting\n");
		return -EFAULT;
	}

	if (main_vm == NULL) {
		printk("KVM_USPT_UNTRACK_ALL: main_vm is not initialized, aborting!\n");
		return -EFAULT;
	}

	if (param.track_mode < 0 || param.track_mode >= KVM_PAGE_TRACK_MAX) {
		printk("KVM_USPT_UNTRACK_ALL: track_mode %d invalid, "
			"must be in range [%d,%d]", param.track_mode,
			0, KVM_PAGE_TRACK_MAX);
		return -EFAULT;
	}

	vcpu = xa_load(&main_vm->vcpu_array, 0);
	untrack_count = sevstep_stop_tracking(vcpu, param.track_mode);

	return 0;
}

int
cachepc_kvm_read_guest_memory_ioctl(void __user *arg_user)
{
	read_guest_memory_t param;
	void * buf;
	int res;

	if (!arg_user) return -EINVAL;

	if (copy_from_user(&param, arg_user, sizeof(read_guest_memory_t))) {
			printk(KERN_CRIT
			"KVM_READ_GUEST_MEMORY: error copying arguments, exiting\n");
			return -EFAULT;
	}

	if (param.len > PAGE_SIZE) {
		printk("KVM_READ_GUEST_MEMORY len may be at most page size");
	}

	buf = kmalloc(param.len, GFP_KERNEL);
	if (buf == NULL) {
		printk("KVM_READ_GUEST_MEMORY: failed to alloc memory");
		return -ENOMEM;
	}

	if (param.wbinvd_cpu >= 0) {
		wbinvd_on_cpu(param.wbinvd_cpu);
	}
	wbinvd_on_all_cpus();

	res = read_physical(main_vm, param.gpa, buf,
		param.len, param.decrypt_with_host_key);
	if (res) {
		printk("KVM_READ_GUEST_MEMORY: read_physical failed with %d\n", res);
		return -EINVAL;
	}

	if (copy_to_user(param.output_buffer, buf, param.len)) {
		printk("KVM_READ_GUEST_MEMORY: failed to copy buf to userspace");
	}

	return 0;
}

int
cachepc_kvm_uspt_reset(void __user *arg_user)
{
	struct kvm_vcpu *vcpu;

	sevstep_uspt_clear();
	vcpu = xa_load(&main_vm->vcpu_array, 0);
	sevstep_stop_tracking(vcpu, KVM_PAGE_TRACK_EXEC);
	sevstep_stop_tracking(vcpu, KVM_PAGE_TRACK_ACCESS);
	sevstep_stop_tracking(vcpu, KVM_PAGE_TRACK_WRITE);

	return 0;
}

int
cachepc_kvm_register_pid(void __user *arg_user)
{
	userspace_ctx_t ctx;
	struct kvm_vcpu *vcpu;

	if (!arg_user) return -EINVAL;

	if (copy_from_user(&ctx, arg_user, sizeof(userspace_ctx_t))) {
		printk("copy from user failed\n");
		return -EACCES;
	}

	if (main_vm == NULL) {
		printk("KVM_TRACK_PAGE: main_vm is not initialized, aborting!\n");
		return -EFAULT;
	}

	sevstep_uspt_clear();
	sevstep_uspt_initialize(ctx.pid, ctx.get_rip);

	printk("Resetting page tracking\n");
	vcpu = xa_load(&main_vm->vcpu_array, 0);
	sevstep_stop_tracking(vcpu, KVM_PAGE_TRACK_EXEC);
	sevstep_stop_tracking(vcpu, KVM_PAGE_TRACK_ACCESS);
	sevstep_stop_tracking(vcpu, KVM_PAGE_TRACK_WRITE);

	return 0;
}

int
cachepc_kvm_uscpt_ack_event_ioctl(void __user *arg_user)
{
	ack_event_t ack_event;

	if (!arg_user) return -EINVAL;

	if (!sevstep_uspt_is_initialiized()) {
		printk("userspace context not initilaized, call REGISTER_PID");
		return -EINVAL;
	}
	if (copy_from_user(&ack_event, arg_user, sizeof(ack_event_t))) {
		printk("ACK_EVENT failed to copy args");
		return -EINVAL;
	}

	return sevstep_uspt_handle_ack_event_ioctl(ack_event);
}

long
cachepc_kvm_ioctl(struct file *file, unsigned int ioctl, unsigned long arg)
{
	void __user *arg_user;
	uint32_t u32;
	uint64_t u64;
	int ret;

	arg_user = (void __user *)arg;
	switch (ioctl) {
	case KVM_CPC_TEST_ACCESS:
		if (!arg_user) return -EINVAL;
		if (copy_from_user(&u32, arg_user, sizeof(uint32_t)))
			return -EFAULT;
		ret = smp_call_function_single(2,
			cachepc_kvm_single_access_test, &u32, true);
		WARN_ON(ret != 0);
		if (copy_to_user(arg_user, &u32, sizeof(uint32_t)))
			return -EFAULT;
		break;
	case KVM_CPC_TEST_EVICTION:
		if (!arg_user) return -EINVAL;
		if (copy_from_user(&u32, arg_user, sizeof(uint32_t)))
			return -EFAULT;
		ret = smp_call_function_single(2,
			cachepc_kvm_single_eviction_test, &u32, true);
		WARN_ON(ret != 0);
		if (copy_to_user(arg_user, &u32, sizeof(uint32_t)))
			return -EFAULT;
		break;
	case KVM_CPC_INIT_PMC:
		if (!arg_user) return -EINVAL;
		if (copy_from_user(&u32, arg_user, sizeof(uint32_t)))
			return -EFAULT;
		ret = smp_call_function_single(2,
			cachepc_kvm_init_pmc_ioctl, &u32, true);
		WARN_ON(ret != 0);
		break;
	case KVM_CPC_READ_PMC:
		if (!arg_user) return -EINVAL;
		if (copy_from_user(&u32, arg_user, sizeof(uint32_t)))
			return -EFAULT;
		u64 = cachepc_read_pmc(u32);
		if (copy_to_user(arg_user, &u64, sizeof(uint64_t)))
			return -EFAULT;
		break;
	case KVM_CPC_READ_COUNTS:
		if (!arg_user) return -EINVAL;
		if (copy_to_user(arg_user, cachepc_msrmts,
				cachepc_msrmts_count * sizeof(uint16_t)))
			return -EFAULT;
		break;
	case KVM_TRACK_PAGE:
		return cachepc_kvm_track_page_ioctl(arg_user);
	case KVM_USPT_BATCH_TRACK_START:
		return cachepc_kvm_batch_track_start_ioctl(arg_user);
	case KVM_USPT_BATCH_TRACK_EVENT_COUNT:
		return cachepc_kvm_batch_track_count_ioctl(arg_user);
	case KVM_USPT_BATCH_TRACK_STOP:
		return cachepc_kvm_batch_track_stop_ioctl(arg_user);
	case KVM_USPT_TRACK_ALL:
		return cachepc_kvm_track_all_ioctl(arg_user);
	case KVM_USPT_UNTRACK_ALL:
		return cachepc_kvm_untrack_all_ioctl(arg_user);
	case KVM_READ_GUEST_MEMORY:
		return cachepc_kvm_read_guest_memory_ioctl(arg_user);
	case KVM_USPT_RESET:
		return cachepc_kvm_uspt_reset(arg_user);
	case KVM_USPT_REGISTER_PID:
		return cachepc_kvm_register_pid(arg_user);
	case KVM_USPT_POLL_EVENT:
		if (!sevstep_uspt_is_initialiized()) {
			printk("userspace context not initilaized, call REGISTER_PID");
			return -EINVAL;
		}
		return sevstep_uspt_handle_poll_event(arg_user);
	case KVM_USPT_ACK_EVENT:
		return cachepc_kvm_uscpt_ack_event_ioctl(arg_user);
	default:
		return kvm_arch_dev_ioctl(file, ioctl, arg);
	}

	return 0;
}

void
cachepc_kvm_setup_test(void *p)
{
	int cpu;

	cpu = get_cpu();

	printk(KERN_WARNING "CachePC: Running on core %i\n", cpu);

	cachepc_ctx = cachepc_get_ctx(L1_CACHE);
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
}

void
cachepc_kvm_exit(void)
{
	kfree(cachepc_msrmts);

	cachepc_release_ds(cachepc_ctx, cachepc_ds);
	cachepc_release_ctx(cachepc_ctx);
}
