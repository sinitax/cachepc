#!/bin/sh

for i in $(seq 0 100); do
	echo -n "\rRun $i"
	bash build.sh load 1>/dev/null
done
echo ""
dmesg -k | grep "CachePC:" | grep "access test" | tail -n100
