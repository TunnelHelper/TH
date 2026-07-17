#!/bin/sh
set -eu

unit="tunnel-helperd.service"
group="tunnel-helper"

if command -v systemd-sysusers >/dev/null 2>&1; then
	systemd-sysusers /usr/lib/sysusers.d/tunnel-helper.conf
elif command -v getent >/dev/null 2>&1 && getent group "$group" >/dev/null 2>&1; then
	:
elif command -v groupadd >/dev/null 2>&1; then
	groupadd --system "$group"
elif command -v addgroup >/dev/null 2>&1; then
	addgroup --system "$group"
else
	echo "Unable to create the $group system group." >&2
	exit 1
fi

if command -v systemd-tmpfiles >/dev/null 2>&1; then
	systemd-tmpfiles --create /usr/lib/tmpfiles.d/tunnel-helper.conf
else
	install -d -m 0750 -o root -g "$group" /run/tunnel-helper
	install -d -m 0700 -o root -g root /var/lib/tunnel-helper
	install -d -m 0700 -o root -g root /var/lib/tunnel-helper/tunnels
	install -d -m 0700 -o root -g root /var/lib/tunnel-helper/cache
	install -d -m 0700 -o root -g root /var/lib/tunnel-helper/cache/srv6
fi

upgrade=0
case "${1:-}" in
	2|[3-9]|[1-9][0-9]*) upgrade=1 ;;
	configure)
		[ -n "${2:-}" ] && upgrade=1
		;;
esac

if command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload >/dev/null 2>&1 || true
	if [ "$upgrade" -eq 0 ]; then
		if [ -d /run/systemd/system ]; then
			if ! systemctl enable --now "$unit"; then
				echo "Could not enable and start $unit." >&2
				echo "Inspect it with: systemctl status $unit" >&2
				exit 1
			fi
		elif ! systemctl enable "$unit" >/dev/null 2>&1; then
			echo "Could not enable $unit in the installed system." >&2
			exit 1
		fi
	elif [ -d /run/systemd/system ] && systemctl is-active --quiet "$unit"; then
		if ! systemctl restart "$unit"; then
			echo "Upgraded $unit, but it did not restart successfully." >&2
			echo "Inspect it with: systemctl status $unit" >&2
		fi
	fi
fi

exit 0
