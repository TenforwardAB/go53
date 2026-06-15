#!/bin/sh
set -eu

named -g -c /etc/bind/named.conf &
named_pid="$!"

while kill -0 "$named_pid" 2>/dev/null; do
	if [ -f /control/reload-member ]; then
		rm -f /control/reload-member
		kill -HUP "$named_pid"
	fi
	sleep 1
done

wait "$named_pid"
