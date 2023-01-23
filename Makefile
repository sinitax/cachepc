LINUX ?= linux
CORES ?= $(shell ls /dev/cpu | wc -l)
LOAD ?= $(CORES)
JOBS ?= $(CORES)

PWD := $(shell pwd)

BINS = test/eviction test/kvm-eviction
BINS += test/kvm-step #test/kvm-execstep
# BINS += test/qemu-eviction_guest test/qemu-eviction_host
# BINS += test/qemu-aes_guest test/qemu-aes_host
BINS += util/debug util/reset

CFLAGS = -I . -I linux/usr/include
CFLAGS += -g -Wunused-variable -Wunknown-pragmas -Wunused-function
CFLAGS += -fsanitize=address

CACHEPC_UAPI = cachepc/uapi.h cachepc/const.h

all: build $(BINS)

clean:
	$(MAKE) -C $(LINUX) clean M=arch/x86/kvm
	$(MAKE) -C $(LINUX) clean M=crypto
	rm -f cachepc/*.o
	rm -f $(BINS)

$(LINUX)/arch/x86/kvm/cachepc:
	ln -sf $(PWD)/cachepc $@

host:
	# build host kernel and Module.symvers for depmod
	cp extra/.config linux/.config
	git -C $(LINUX) add .
	git -C $(LINUX) stash
	git -C $(LINUX) checkout 0aaa1e5
	rm -f $(LINUX)/arch/x86/kvm/cachepc
	$(MAKE) -C $(LINUX) -j $(JOBS) -l $(LOAD) bindeb-pkg
	git -C $(LINUX) checkout master
	git -C $(LINUX) stash pop

build: $(LINUX)/arch/x86/kvm/cachepc
	$(MAKE) -C $(LINUX) -j $(JOBS) -l $(LOAD) M=arch/x86/kvm modules
	#$(MAKE) -C $(LINUX) -j $(JOBS) -l $(LOAD) M=crypto modules

load:
	sudo rmmod kvm_amd || true
	sudo rmmod kvm || true
	sudo insmod $(LINUX)/arch/x86/kvm/kvm.ko
	sudo insmod $(LINUX)/arch/x86/kvm/kvm-amd.ko

prep:
	sudo sh -c "echo 0 > /proc/sys/kernel/watchdog"
	sudo cpupower frequency-set -d 3.7GHz -u 3.7GHz

util/%: util/%.c $(CACHEPC_UAPI)

test/eviction: test/eviction.c test/util.c $(CACHEPC_UAPI)
	$(CC) -o $@ $(filter %.c,$^) $(filter %.S,$^) $(CFLAGS)

test/kvm-eviction: test/kvm-eviction.c test/kvm-eviction_guest.S test/util.c \
		test/util.h test/kvm.c test/kvm.h test/kvm-eviction.h $(CACHEPC_UAPI)
	$(CC) -o $@ $(filter %.c,$^) $(filter %.S,$^) $(CFLAGS)

test/kvm-step: test/kvm-step.c test/kvm-step_guest.S \
		test/util.c test/util.h test/kvm.c test/kvm.h $(CACHEPC_UAPI)
	$(CC) -o $@  $(filter %.c,$^) $(filter %.S,$^) $(CFLAGS)

.PHONY: all clean host build load prep
