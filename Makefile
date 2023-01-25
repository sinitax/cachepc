LINUX ?= linux
CORES ?= $(shell ls /dev/cpu | wc -l)
LOAD ?= $(CORES)
JOBS ?= $(CORES)

PWD := $(shell pwd)

BINS = test/eviction test/kvm-eviction
BINS += test/kvm-eviction-with_guest test/kvm-eviction-without_guest
BINS += test/kvm-step test/kvm-step_guest
BINS += test/kvm-pagestep test/kvm-pagestep_guest
# BINS += test/qemu-eviction_guest test/qemu-eviction
# BINS += test/qemu-aes_guest test/qemu-aes
BINS += util/debug util/reset

CFLAGS = -I . -I linux/usr/include
CFLAGS += -g -Wunused-variable -Wunknown-pragmas -Wunused-function
CFLAGS += -fsanitize=address

LDLIBS = -lpthread

TEST_SRCS = test/util.c test/util.h test/kvm.c test/kvm.h
TEST_SRCS += cachepc/uapi.h cachepc/const.h

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
	sudo sh -c "echo 1 > /proc/irq/127/smp_affinity"

util/%: util/%.c $(CACHEPC_UAPI)

test/%.o: test/%.c
	$(CC) -c -o $@ $^ $(CFLAGS)

test/%.o: test/%.S
	$(CC) -c -o $@ $^ $(CFLAGS)

test/%_guest: test/%_guest.o test/guest.lds
	$(LD) -Ttest/guest.lds -o $@ $<

test/eviction: test/eviction.c test/util.c $(TEST_SRCS)
	$(CC) -o $@ $(filter %.c,$^) $(filter %.S,$^) $(CFLAGS) $(LDLIBS)

test/kvm-eviction: test/kvm-eviction.c test/kvm-eviction.h $(TEST_SRCS)
	$(CC) -o $@ $(filter %.c,$^) $(filter %.S,$^) $(CFLAGS) $(LDLIBS)

test/kvm-step: test/kvm-step.c $(TEST_SRCS)
	$(CC) -o $@  $(filter %.c,$^) $(filter %.S,$^) $(CFLAGS) $(LDLIBS)

test/kvm-pagestep: test/kvm-pagestep.c $(TEST_SRCS)
	$(CC) -o $@  $(filter %.c,$^) $(filter %.S,$^) $(CFLAGS) $(LDLIBS)

.PHONY: all clean host build load prep
