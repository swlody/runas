#!/bin/ash
if [ ! -d /var/tmp ]
then
	mkdir /var/tmp
fi
touch /var/tmp/runaslog
chown root /var/tmp
chmod 1777 /var/tmp
chown root:root /var/tmp/runaslog
chmod 664 /var/tmp/runaslog