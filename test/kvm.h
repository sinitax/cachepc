#pragma once

#include <stdint.h>
#include <stdlib.h>

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

const char *sev_fwerr_str(int code);
const char *sev_gstate_str(int code);

int sev_ioctl(int vmfd, int cmd, void *data, int *error);
void sev_get_measure(int vmfd);
uint8_t sev_guest_state(int vmfd, uint32_t handle);
void sev_dbg_decrypt(int vmfd, void *src, void *dst, size_t size);
uint64_t sev_dbg_decrypt_rip(int vmfd);
void snp_dbg_decrypt(int vmfd, void *src, void *dst, size_t size);
uint64_t snp_dbg_decrypt_rip(int vmfd);

void kvm_init(struct kvm *kvm, size_t ramsize,
	void *code_start, void *code_stop);
void sev_kvm_init(struct kvm *kvm, size_t ramsize,
	void *code_start, void *code_stop);
void sev_es_kvm_init(struct kvm *kvm, size_t ramsize,
	void *code_start, void *code_stop);
void sev_snp_kvm_init(struct kvm *kvm, size_t ramsize,
	void *code_start, void *code_stop);
void kvm_deinit(struct kvm *kvm);

void parse_vmtype(int argc, const char **argv);
uint64_t vm_get_rip(struct kvm *kvm);
void vm_init(struct kvm *kvm, void *code_start, void *code_end);
void vm_deinit(struct kvm *kvm);

void kvm_setup_init(void);
void kvm_setup_deinit(void);

extern int kvm_dev, sev_dev;
extern const char *vmtype;

