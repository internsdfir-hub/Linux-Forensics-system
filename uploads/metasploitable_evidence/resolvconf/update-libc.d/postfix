#!/bin/sh -e

# make sure we're still here...
[ -x /usr/sbin/postconf ] || exit 0

cp /etc/resolv.conf $(/usr/sbin/postconf -h queue_directory)/etc/resolv.conf
/etc/init.d/postfix reload >/dev/null 2>&1 || exit 0

exit 0
