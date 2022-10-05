LINUX ?= /usr/src/linux
PWD := $(shell pwd)

all: build test/eviction test/access test/kvm test/sev test/sev-es test/sevstep

clean:
	$(MAKE) -C $(LINUX) SUBDIRS=arch/x86/kvm clean

$(LINUX)/arch/x86/kvm/svm/cachepc:
	ln -sf $(PWD)/cachepc $@

$(LINUX)/arch/x86/kvm/sevstep:
	ln -sf $(PWD)/sevstep $@

build: $(LINUX)/arch/x86/kvm/svm/cachepc $(LINUX)/arch/x86/kvm/sevstep
	$(MAKE) -C $(LINUX) -j6 M=arch/x86/kvm

load:
	sudo rmmod kvm_amd || true
	sudo rmmod kvm || true
	sudo insmod $(LINUX)/arch/x86/kvm/kvm.ko
	sudo insmod $(LINUX)/arch/x86/kvm/kvm-amd.ko

test/%: test/%.c cachepc/uapi.h sevstep/uapi.h
	clang -o $@ $< -fsanitize=address -I . -Wunused-variable


update:
	git -C $(LINUX) diff 0aaa1e599bee256b3b15643bbb95e80ce7aa9be5 -G. > patch.diff

.PHONY: all clean build load update
