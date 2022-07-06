KERNEL_SOURCE ?= /usr/src/linux
PWD := $(shell pwd)

.PHONY: all reset prepare build

all: clean reset prepare build

clean:
	$(MAKE) -C $(KERNEL_SOURCE) SUBDIRS=arch/x86/kvm clean

reset:
	git -C $(KERNEL_SOURCE) reset --hard

prepare:
	git -C $(KERNEL_SOURCE) apply $(PWD)/patch.diff 

$(KERNEL_SOURCE)/arch/x86/kvm/svm/cachepc:
	ln -s $(PWD)/src $@

build: $(KERNEL_SOURCE)/arch/x86/kvm/svm/cachepc
	$(MAKE) -C $(KERNEL_SOURCE) arch/x86/kvm/kvm.ko arch/x86/kvm/kvm-amd.ko

load:
	sudo rmmod kvm_amd || true
	sudo rmmod kvm || true
	sudo insmod $(KERNEL_SOURCE)/arch/x86/kvm/kvm.ko
	sudo insmod $(KERNEL_SOURCE)/arch/x86/kvm/kvm-amd.ko
