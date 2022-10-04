KERNEL_SOURCE ?= /usr/src/linux
PWD := $(shell pwd)

all: build test/eviction test/access test/kvm test/sev test/sev-es

clean:
	$(MAKE) -C $(KERNEL_SOURCE) SUBDIRS=arch/x86/kvm clean

$(KERNEL_SOURCE)/arch/x86/kvm/svm/cachepc:
	ln -sf $(PWD)/kmod $@

build:
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
	git -C $(KERNEL_SOURCE) diff 0aaa1e599bee256b3b15643bbb95e80ce7aa9be5 -G. > patch.diff

.PHONY: all clean build load update
