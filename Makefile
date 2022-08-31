KERNEL_SOURCE ?= /usr/src/linux
PWD := $(shell pwd)

.PHONY: all reset clean prepare build

all: reset clean prepare build test/eviction test/access test/kvm test/sev

clean:
	$(MAKE) -C $(KERNEL_SOURCE) SUBDIRS=arch/x86/kvm clean

reset:
	git -C $(KERNEL_SOURCE) reset --hard

$(KERNEL_SOURCE)/arch/x86/kvm/svm/cachepc:
	ln -sf $(PWD)/kmod $@

prepare: $(KERNEL_SOURCE)/arch/x86/kvm/svm/cachepc
	git -C $(KERNEL_SOURCE) apply $(PWD)/patch.diff 

build:
	#$(MAKE) -C $(KERNEL_SOURCE) arch/x86/kvm/kvm.ko arch/x86/kvm/kvm-amd.ko
	$(MAKE) -C $(KERNEL_SOURCE) -j6 M=arch/x86/kvm

load:
	sudo rmmod kvm_amd || true
	sudo rmmod kvm || true
	sudo insmod $(KERNEL_SOURCE)/arch/x86/kvm/kvm.ko
	sudo insmod $(KERNEL_SOURCE)/arch/x86/kvm/kvm-amd.ko

test/%: test/%.c kmod/cachepc_user.h
#	$(CC) -o $@ $< -I kmod
	clang -fsanitize=address -o $@ $< -I kmod -Wunused-variable

update: 
	git -C $(KERNEL_SOURCE) diff > patch.diff
