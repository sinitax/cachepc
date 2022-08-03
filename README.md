# Installation & Testing
To test the kernel module, first clone and install the SEV kernel here:
```
https://github.com/AMDESE/AMDSEV.git
cd AMDSEV
./build.sh kernel
```
This should create a new kernel in AMDSEV/build/linux 
Then, change into the kernel_module directory to apply the kernel patch
and install it:
```
cd kernel_module
KERNEL_SOURCE=[...]/AMDSEV/build/linux make 
KERNEL_SOURCE=[...]/AMDSEV/build/linux make install
```
Now, to test the kernel module, switch to the `test_kernel_module` directory and run:
```
cd test_kernel_module
./build.sh
sudo ./test_vm
```
Which should print the accessed cache set after running one instruction in the VM.
# Directory & Code Structure
## Kernel Module To "Instrument" SVM with Performance Counters
The `kernel_module` directory contains a `patch.diff` file that 
patches a given linux kernel to insert some prime+probe code in the
`kvm/svm` module.The most important code change is in the function `svm_vcpu_run`
in `arch/x86/kvm/svm.c`, line 68 of the `patch.diff` file:
```
+	head = cachepc_prime(ds);
+
 	svm_vcpu_enter_exit(vcpu, svm);
 
+	cachepc_probe(head);
[...]
+	cachepc_save_msrmts(head);
```
Basically, we `prime` the code just before calling `svm_vcpu_enter_exit` and `probe` the code immediately after. 
The relevant functions are implemented in `kernel_module/src/cachepc.c` and `kernel_mdoule/src/cachepc.h`:
`cachepc_init_counters` in `cachepc.c`: Starts to perfomance counters by writing to the correct `MSR` registers.
`cachepc_prime` in `cachepc.h`: Primes the cache
`cachepc_probe` in `cachepc.h`: Probes the cache and stores in the cached datastructures itself. We use `rdmsr` to read the appropriate performance counters. 

The results are then exposed to userspace via a proc device, see function `kvm_cachepc_read` in the `patch.diff` file.
## KVM Test Code
The `test_kernel_module/test_vm.c` function interfaces with the SVM kernel module by starting VMs and then reading out the cache-misses via the exposed proc device. In particular, the code starts two VMs:
1. One VM that does not perform any memory access but immediately "VMEXISTS": 
```
__attribute__((section("guest_without"))) void
vm_guest_without(void)
{
	while (1) {
		asm volatile("out %%al, (%%dx)" : : );
	}
}
```
2. One VM that performs a memory access in a target cache set and then "VMEXISTS":
```
__attribute__((section("guest_with"))) void
vm_guest_with(void)
{
	while (1) {
		asm volatile("mov %%bl, (%[v])"
			: : [v] "r" (TARGET_CACHE_LINESIZE * TARGET_SET));
		asm volatile("out %%al, (%%dx)" : : );
	}
}5
```

After one VMEXIT for both VMs, the `test_vm.c` reads out the performance counter results and prints which sets have been accessed. It also storews some logs in 
`msmrt_without_access.out` and `msmrt_with_access.out`, respectively.

The results can be plotted like so:
`python3 plot/plot-log.py <out-file>`
which will create a png file in `plots/<out-file>.png`
Note that the errorbars are NOT the std-deviation, but rather the mimimum and maximum encountered measurements.
