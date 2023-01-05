LINUX ?= linux
JOBS ?= 15
PWD := $(shell pwd)

BINS = test/eviction test/access test/kvm test/sev test/sev-es
BINS += test/fullstep test/execstep 
BINS += test/aes-detect_guest test/aes-detect_host
BINS += test/access-detect_guest test/access-detect_host
BINS += test/readsvme util/debug util/reset

CFLAGS = -I . -I test -Wunused-variable -Wunknown-pragmas

all: cachepc $(BINS)

clean:
	$(MAKE) -C $(LINUX) SUBDIRS=arch/x86/kvm clean
	$(MAKE) -C $(LINUX) SUBDIRS=crypto clean
	rm $(BINS)

$(LINUX)/arch/x86/kvm/cachepc:
	ln -sf $(PWD)/cachepc $@

host:
	# generate host kernel and Module.symvers for depmod
	cp extra/.config linux/.config
	git -C $(LINUX) add .
	git -C $(LINUX) stash
	git -C $(LINUX) checkout 0aaa1e5
	$(MAKE) -C $(LINUX) oldconfig
	$(MAKE) -C $(LINUX) prepare
	$(MAKE) -C $(LINUX) -j $(JOBS) bindeb-pkg
	git -C $(LINUX) checkout HEAD
	git -C $(LINUX) stash pop

cachepc: $(LINUX)/arch/x86/kvm/cachepc
	$(MAKE) -C $(LINUX) -j $(JOBS) M=arch/x86/kvm modules
	$(MAKE) -C $(LINUX) -j $(JOBS) M=crypto modules

load:
	sudo rmmod kvm_amd || true
	sudo rmmod kvm || true
	sudo insmod $(LINUX)/arch/x86/kvm/kvm.ko
	sudo insmod $(LINUX)/arch/x86/kvm/kvm-amd.ko

freq:
	sudo cpupower frequency-set -f 3.7GHz
	sudo cpupower frequency-set -u 3.7GHz
	sudo cpupower frequency-set -d 3.7GHz

update:
	git -C $(LINUX) diff 0aaa1e599bee256b3b15643bbb95e80ce7aa9be5 -G. > patch.diff

test/aes-detect_%: test/aes-detect_%.c test/aes-detect.c cachepc/uapi.h
	clang -o $@ $< $(CFLAGS) -I test/libkcapi/lib -L test/libkcapi/.libs -lkcapi -static

test/access-detect_%: test/access-detect_%.c cachepc/uapi.h
	clang -o $@ $< $(CFLAGS) -static

test/%: test/%.c cachepc/uapi.h
	clang -o $@ $< $(CFLAGS) -fsanitize=address

util/%: util/%.c cachepc/uapi.h
	clang -o $@ $< $(CFLAGS) -fsanitize=address

.PHONY: all clean host build load freq update
