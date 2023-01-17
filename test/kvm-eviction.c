#include "test/kvm-eviction.h"
#include "test/kvm.h"
#include "test/util.h"
#include "cachepc/uapi.h"

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <err.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#define SAMPLE_COUNT 64

#define TARGET_CORE 2
#define SECONDARY_CORE 3

extern uint8_t guest_with_start[];
extern uint8_t guest_with_stop[];
extern uint8_t guest_without_start[];
extern uint8_t guest_without_stop[];

static const char *vmtype;

uint64_t
vm_get_rip(struct kvm *kvm)
{
	struct kvm_regs regs;
	uint64_t rip;
	int ret;

	if (!strcmp(vmtype, "sev-snp")) {
		rip = snp_dbg_decrypt_rip(kvm->vmfd);
	} else if (!strcmp(vmtype, "sev-es")) {
		rip = sev_dbg_decrypt_rip(kvm->vmfd);
	} else {
		ret = ioctl(kvm->vcpufd, KVM_GET_REGS, &regs);
		if (ret == -1) err(1, "KVM_GET_REGS");
		rip = regs.rip;
	}

	return rip;
}

void
vm_init(struct kvm *kvm, void *code_start, void *code_end)
{
	size_t ramsize;

	ramsize = L1_SIZE * 2;
	if (!strcmp(vmtype, "kvm")) {
		kvm_init(kvm, ramsize, code_start, code_end);
	} else if (!strcmp(vmtype, "sev")) {
		sev_kvm_init(kvm, ramsize, code_start, code_end);
	} else if (!strcmp(vmtype, "sev-es")) {
		sev_es_kvm_init(kvm, ramsize, code_start, code_end);
	} else if (!strcmp(vmtype, "sev-snp")) {
		sev_snp_kvm_init(kvm, ramsize, code_start, code_end);
	} else {
		errx(1, "invalid version");
	}
}

void
vm_deinit(struct kvm *kvm)
{
	kvm_deinit(kvm);
}

void
collect(struct kvm *kvm, uint8_t *counts)
{
	int ret;

	ret = ioctl(kvm->vcpufd, KVM_RUN, NULL);
	if (ret == -1) err(1, "KVM_RUN");
	// warnx("rip:%lu code:%i", vm_get_rip(kvm), kvm->run->exit_reason);

	if (kvm->run->exit_reason != KVM_EXIT_HLT) {
		errx(1, "KVM died! rip:%lu code:%i",
			vm_get_rip(kvm), kvm->run->exit_reason);
	}

	ret = ioctl(kvm_dev, KVM_CPC_READ_COUNTS, counts);
	if (ret == -1) err(1, "ioctl KVM_CPC_READ_COUNTS");
}

int
main(int argc, const char **argv)
{
	struct kvm vms[2];
	uint8_t counts[2][SAMPLE_COUNT][L1_SETS];
	uint8_t baseline[L1_SETS];
	int i, k, ret;

	vmtype = "kvm";
	if (argc > 1) vmtype = argv[1];
	if (strcmp(vmtype, "kvm") && strcmp(vmtype, "sev")
			&& strcmp(vmtype, "sev-es")
			&& strcmp(vmtype, "sev-snp"))
		errx(1, "invalid vm mode: %s", vmtype);

	setvbuf(stdout, NULL, _IONBF, 0);

	pin_process(0, TARGET_CORE, true);

	kvm_setup_init();

	vm_init(&vms[WITH], guest_with_start, guest_with_stop);
	vm_init(&vms[WITHOUT], guest_without_start, guest_without_stop);

	/* reset kernel module state */
	ret = ioctl(kvm_dev, KVM_CPC_RESET);
	if (ret == -1) err(1, "ioctl KVM_CPC_RESET");

	/* resolve page faults in advance (code only covers 1 page)..
	 * we want the read counts to apply between KVM_RUN and KVM_EXIT_HLT,
	 * any exits through PFs inbetween will influence our measurement */
	collect(&vms[WITH], counts[WITH][0]);
	collect(&vms[WITHOUT], counts[WITHOUT][0]);

	/* collect samples */
	for (i = 0; i < SAMPLE_COUNT; i++) {
		collect(&vms[WITH], counts[WITH][i]);
		collect(&vms[WITHOUT], counts[WITHOUT][i]);
	}

	/* calculate measurement baseline */
	memset(baseline, 0xff, L1_SETS);
	for (i = 0; i < SAMPLE_COUNT; i++) {
		for (k = 0; k < L1_SETS; k++) {
			if (counts[WITH][i][k] < baseline[k])
				baseline[k] = counts[WITH][i][k];
			if (counts[WITHOUT][i][k] < baseline[k])
				baseline[k] = counts[WITHOUT][i][k];
		}
	}

	/* apply baseline and output samples */
	for (i = 0; i < SAMPLE_COUNT; i++) {
		for (k = 0; k < L1_SETS; k++) {
			counts[WITH][i][k] -= baseline[k];
			counts[WITHOUT][i][k] -= baseline[k];
		}

		printf("\n=== Sample %2i ===\n", i);

		printf("\nWith eviction:\n\n");
		print_counts(counts[WITH][i]);
		printf("\n");
		print_counts_raw(counts[WITH][i]);

		printf("\nWithout eviction:\n\n");
		print_counts(counts[WITHOUT][i]);
		printf("\n");
		print_counts_raw(counts[WITHOUT][i]);
	}

	/* check for measurment errors */
	for (i = 0; i < SAMPLE_COUNT; i++) {
		for (k = 0; k < L1_SETS; k++) {
			if (counts[WITH][i][k] + baseline[k] > L1_ASSOC)
				warnx("sample %i: With count OOB for set %i (=%i)",
					i, k, counts[WITH][i][k] + baseline[k]);

			if (counts[WITHOUT][i][k] + baseline[k] > L1_ASSOC)
				warnx("sample %i: Without count OOB for set %i (=%i)",
					i, k, counts[WITHOUT][i][k] + baseline[k]);
		}

		if (!counts[WITH][i][TARGET_SET])
			warnx("sample %i: Missing eviction in target set %i (=%i,%i)",
				i, TARGET_SET, counts[WITH][i][TARGET_SET],
				counts[WITH][i][TARGET_SET] + baseline[i]);
	}

	vm_deinit(&vms[WITH]);
	vm_deinit(&vms[WITHOUT]);

	kvm_setup_deinit();
}

