#pragma once

#include "util.h"

#include <stdint.h>
#include <stdlib.h>

#define MAIN_VMFD -0x42

enum { WITH, WITHOUT };

enum {
	GSTATE_UNINIT,
	GSTATE_LUPDATE,
	GSTATE_LSECRET,
	GSTATE_RUNNING,
	GSTATE_SUPDATE,
	GSTATE_RUPDATE,
	GSTATE_SENT
};

struct kvm {
	int fd, vmfd, vcpufd;
	void *mem;
	size_t memsize, runsize;
	struct kvm_run *run;
};

struct guest {
	void *code;
	size_t code_size;
	size_t mem_size;
};

const char *sev_fwerr_str(int code);
const char *sev_gstate_str(int code);

int sev_ioctl(int vmfd, int cmd, void *data, int *error);
void sev_get_measure(int vmfd);
uint8_t sev_guest_state(int vmfd, uint32_t handle);

void guest_init(struct guest *guest, const char *filename);
void guest_deinit(struct guest *guest);

void kvm_init(struct kvm *kvm, struct guest *guest);
void sev_kvm_init(struct kvm *kvm, struct guest *guest);
void sev_es_kvm_init(struct kvm *kvm, struct guest *guest);
void sev_snp_kvm_init(struct kvm *kvm, struct guest *guest);
void kvm_deinit(struct kvm *kvm);

uint64_t vm_get_rip(void);
void parse_vmtype(int argc, const char **argv);
void vm_init(struct kvm *kvm, struct guest *guest);
void vm_deinit(struct kvm *kvm);

void kvm_setup_init(void);
void kvm_setup_deinit(void);

extern int kvm_dev, sev_dev;
extern const char *vmtype;

