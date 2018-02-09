#!/bin/sh

#
# First argument: Name of kernel bzImage to execute
#
echo "Running QEMU with your kernel at $1"
/usr/bin/qemu-system-x86_64 -m 64M -L ./install/qemu/share/qemu/ -nographic -kernel bzImage -hda ./openwrt-15.05-x86-generic-combined-ext4.img -append "root=PARTUUID=076b2e55-02 rootfstype=ext4 rootwait console=tty0 console=ttyS0,38400n8 noinitrd" -hdb fat:rw:`pwd`/floppy
