#!/bin/sh

set -ex

gitroot=$(git rev-parse --show-toplevel)
cd "$gitroot/qemu"

DISK="debian11.qcow2"
DEBIANISO="debian-11.4.0-amd64-DVD-1.iso"

if [ ! -e "$DISK" ]; then
	echo "Creating guest disk.."
	qemu-img create -f qcow2 "$DISK" 20G
fi

if [ ! -e "$DEBIANISO" ]; then
	echo "Downloading debian DVD image.."
	wget "https://cdimage.debian.org/mirror/cdimage/archive/11.4.0/amd64/iso-dvd/debian-11.4.0-amd64-DVD-1.iso" -O "$DEBIANISO"
fi

sudo LIBVIRT_DEBUG=1 virsh net-start default 2>&1 | grep -i warning || true

sudo PREFIX="$gitroot/AMDSEV" "$gitroot/AMDSEV/launch-qemu.sh" \
	-hda "$DISK" \
	-console serial \
	-vnc 1 \
	-mem 2024 \
	-smp 1,cores=4,threads=2 \
	-allow-debug \
	-cdrom "$DEBIANISO"

