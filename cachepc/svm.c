

int
cachepc_kvm_get_rip_ioctl(void __user *arg_user)
{
	struct kvm_regs *regs;
	struct kvm_vcpu *vcpu;

	if (!arg_user) return -EINVAL;

	if (!main_vm || xa_empty(&main_vm->vcpu_array))
		return -EFAULT;

	vcpu = xa_load(&main_vm->vcpu_array, 0);

	if (sev_es_guest(vcpu)) {

	}
	kvm_rip_read(vcpu);

	return 0;
}
