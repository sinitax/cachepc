KERNEL_SOURCE ?= /usr/src/linux
PWD := $(shell pwd)

.PHONY: all reset clean prepare build

all: reset prepare build

clean:
	$(MAKE) -C $(KERNEL_SOURCE) SUBDIRS=arch/x86/kvm clean

reset:
	git -C $(KERNEL_SOURCE) reset --hard
	#git -C $(KERNEL_SOURCE) clean -dfx
	#cp .config $(KERNEL_SOURCE)/.config

$(KERNEL_SOURCE)/arch/x86/kvm/svm/cachepc:
	ln -s $(PWD)/src $@

prepare: $(KERNEL_SOURCE)/arch/x86/kvm/svm/cachepc
	git -C $(KERNEL_SOURCE) apply $(PWD)/patch.diff 

build:
	# $(MAKE) -C $(KERNEL_SOURCE) arch/x86/kvm/kvm.ko arch/x86/kvm/kvm-amd.ko
	$(MAKE) -C $(KERNEL_SOURCE) -v modules -j6 SUBDIRS=arch/x86/kvm
	$(MAKE) -C $(KERNEL_SOURCE) -j6 M=arch/x86/kvm

load:
	sudo rmmod kvm_amd || true
	sudo rmmod kvm || true
	sudo insmod $(KERNEL_SOURCE)/arch/x86/kvm/kvm.ko
	sudo insmod $(KERNEL_SOURCE)/arch/x86/kvm/kvm-amd.ko
