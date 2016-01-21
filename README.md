# runas
Files for the runas program assignment

This repository contains the helper scripts for MP1 for CSC 292/572.

Students will need the QEMU emulator and the OpenWRT hard disk image. The getfiles.sh script will download and unpack these files from the course web page. In case students want to get the files by hand, the information is below:

o You can find the QEMU binaries for our Linux machines at http://www.cs.rochester.edu/courses/256/fall2015/QDGL/qemu-install.tar.gz

o The OpenWRT image that we use for our virtual machine is at http://www.cs.rochester.edu/courses/256/fall2015/QDGL/openwrt-15.05-x86-generic-combined-ext4.img

The runqemu.sh script will launch QEMU with the needed command-line options. With no arguments, it will boot the OpenWRT disk image with the default kernel residing on the image. Alternatively, students can provide the pathname to a Linux kernel, and runqemu.sh will boot that kernel instead.

You should boot QEMU with the bzImage kernel provided in the repository.  This kernel has MS-DOS file system and floppy disk device support enabled.  To boot this kernel, use:

o sh runqemu.sh ./bzImage

Files in the floppy directory will appear on the floppy disk within the virtual machine. To mount the floppy disk, use the command:

o mount -t msdos /dev/fd0 /mnt

The contents of floppy should appear in /mnt.

Please note that the size of the files in floppy must remain less than the size of an actual floppy disk.  If memory serves correctly, that is 1.44 MB.
