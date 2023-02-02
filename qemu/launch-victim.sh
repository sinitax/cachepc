#!/bin/sh

set -ex

gitroot=$(git rev-parse --show-toplevel)
cd "$gitroot/qemu"

if [ ! -e cmdline ]; then
	echo "Missing qemu/cmdline.."
	exit 1
fi

if [ ! -e guest_encrypted.qcow2 ]; then
	echo "Copying disk.."
	rsync -a --info=progress2 guest.qcow2 guest_encrypted.qcow2
fi

sudo LIBVIRT_DEBUG=1 virsh net-start default 2>&1 | grep -i warning || true

sudo PREFIX=$gitroot/AMDSEV $gitroot/AMDSEV/launch-qemu.sh \
	-hda guest_encrypted.qcow2 \
	-console serial \
	-vnc 1 \
	-mem 2024 \
	-smp 1,cores=1,threads=1 \
	-allow-debug \
	-initrd initrd.img-5.19.0-rc6-snp-guest-d9bd54fea4d2 \
	-kernel vmlinuz-5.19.0-rc6-snp-guest-d9bd54fea4d2 \
	-append "$(cat cmdline)" \
	-sev-snp

