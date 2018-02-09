#!/bin/ash
if [! -d /var/tmp]
then
	mkdir /var/tmp
	chmod 1
fi
touch /var/tmp/runaslog
chown root /var/tmp
chmod 1777 /var/tmp
chown root /var/tmp/runaslog
chmod 644 /var/tmp/runaslog