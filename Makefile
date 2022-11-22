LINUX ?= /usr/src/linux
PWD := $(shell pwd)

TARGETS = build test/eviction test/access test/kvm test/sev test/sev-es test/sevstep 
TARGETS += test/aes-detect_guest test/aes-detect_host
TARGETS += test/access-detect_guest test/access-detect_host

CFLAGS = -I . -I test -Wunused-variable -Wunknown-pragmas

all: $(TARGETS)

clean:
	$(MAKE) -C $(LINUX) SUBDIRS=arch/x86/kvm clean

$(LINUX)/arch/x86/kvm/cachepc:
	ln -sf $(PWD)/cachepc $@

build: $(LINUX)/arch/x86/kvm/cachepc
	$(MAKE) -C $(LINUX) -j6 M=arch/x86/kvm
	$(MAKE) -C $(LINUX) -j6 M=crypto

load:
	sudo rmmod kvm_amd || true
	sudo rmmod kvm || true
	sudo insmod $(LINUX)/arch/x86/kvm/kvm.ko
	sudo insmod $(LINUX)/arch/x86/kvm/kvm-amd.ko

freq:
	sudo cpupower frequency-set -f 1.5GHz
	sudo cpupower frequency-set -u 1.5GHz
	sudo cpupower frequency-set -d 1.5GHz

update:
	git -C $(LINUX) diff 0aaa1e599bee256b3b15643bbb95e80ce7aa9be5 -G. > patch.diff

test/aes-detect_%: test/aes-detect_%.c test/aes-detect.c
	clang -o $@ $< $(CFLAGS) -I test/libkcapi/lib -L test/libkcapi/.libs -lkcapi -static

test/%: test/%.c cachepc/uapi.h
	clang -o $@ $< $(CFLAGS)  -fsanitize=address

.PHONY: all clean build load freq update
