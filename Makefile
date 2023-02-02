LINUX ?= linux
CORES ?= $(shell getconf _NPROCESSORS_ONLN)
LOAD ?= $(CORES)
JOBS ?= $(CORES)

PWD := $(shell pwd)

BINS = test/eviction test/kvm-eviction
BINS += test/kvm-eviction-with_guest test/kvm-eviction-without_guest
BINS += test/kvm-step test/kvm-step_guest
BINS += test/kvm-pagestep test/kvm-pagestep_guest
BINS += test/qemu-pagestep
BINS += test/qemu-eviction test/qemu-eviction_guest
# BINS += test/qemu-aes_guest test/qemu-aes
BINS += util/debug util/reset util/mainpfn

CFLAGS = -I . -I linux/usr/include
CFLAGS += -g -Wunused-variable -Wunknown-pragmas -Wunused-function

HOST_CFLAGS = $(CFLAGS) -fsanitize=address
GUEST_CFLAGS = $(CFLAGS) -static

LDLIBS = -lpthread

UTIL_HDRS = cachepc/uapi.h cachepc/const.h
UTIL_SRCS =

TEST_HDRS = cachepc/uapi.h cachepc/const.h test/util.h test/kvm.h
TEST_SRCS = test/util.c test/kvm.c

all: build $(BINS)

clean:
	$(MAKE) -C $(LINUX) clean M=arch/x86/kvm
	$(MAKE) -C $(LINUX) clean M=crypto
	rm -f cachepc/*.o
	rm -f $(BINS)

$(LINUX)/arch/x86/kvm/cachepc:
	ln -sf $(PWD)/cachepc $@

linux: # build host kernel for depmod
	git -C $(LINUX) add .
	git -C $(LINUX) stash
	git -C $(LINUX) checkout d9bd54fea4d2
	rm -f $(LINUX)/arch/x86/kvm/cachepc
	$(MAKE) -C $(LINUX) -j $(JOBS) -l $(LOAD) vmlinux headers
	git -C $(LINUX) checkout master
	git -C $(LINUX) stash pop || true

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
	sudo sh -c "echo 1500000 > /sys/devices/system/cpu/cpu2/cpufreq/scaling_min_freq"
	sudo sh -c "echo 1500000 > /sys/devices/system/cpu/cpu2/cpufreq/scaling_max_freq"
	sudo sh -c "echo 1500000 > /sys/devices/system/cpu/cpu2/cpufreq/scaling_min_freq"
	sudo bash -c "for f in /proc/irq/*/smp_affinity; do echo 1 > \$$f 2>/dev/null; done"

util/%: util/%.c $(UTIL_SRCS)
	$(CC) -o $@ $< $(HOST_CFLAGS)

util/mainpfn: util/mainpfn.c $(UTIL_SRCS)
	$(CC) -o $@ $< $(GUEST_CFLAGS)

test/%.o: test/%.c $(TEST_HDRS)
	$(CC) -c -o $@ $< $(HOST_CFLAGS)

test/%.o: test/%.S $(TEST_HDRS)
	$(CC) -c -o $@ $< $(HOST_CFLAGS)

test/%: test/%.c $(TEST_SRCS)
	$(CC) -o $@ $(filter %.c,$^) $(HOST_CFLAGS) $(LDLIBS)

test/kvm-%_guest: test/kvm-%_guest.o test/kvm-guest.lds
	$(LD) -Ttest/kvm-guest.lds -o $@ $<

test/kvm-%: test/kvm-%.c $(TEST_SRCS)
	$(CC) -o $@ $(filter %.c,$^) $(filter %.S,$^) $(HOST_CFLAGS) $(LDLIBS)

test/kvm-eviction: test/kvm-eviction.c test/kvm-eviction.h $(TEST_SRCS)
	$(CC) -o $@ $(filter %.c,$^) $(filter %.S,$^) $(HOST_CFLAGS) $(LDLIBS)

test/qemu-%: test/qemu-%.c $(TEST_SRCS)
	$(CC) -o $@ $(filter %.c,$^) $(filter %.S,$^) $(HOST_CFLAGS) $(LDLIBS)

test/qemu-%_guest: test/qemu-%_guest.c
	$(CC) -o $@ $(filter %.c,$^) $(filter %.S,$^) $(GUEST_CFLAGS) $(LDLIBS)

.PHONY: all clean linux build load prep
