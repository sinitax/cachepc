#!/bin/sh

set -ex

gitroot=$(git rev-parse --show-toplevel)
cd "$gitroot/qemu"

sudo LIBVIRT_DEBUG=1 virsh net-start default 2>&1 | grep -i warning || true

sudo PREFIX=$gitroot/AMDSEV $gitroot/AMDSEV/launch-qemu.sh \
	-hda guest.qcow2 \
	-console serial \
	-vnc 1 \
	-mem 2024 \
	-smp 1,cores=4,threads=2 \
	-allow-debug

