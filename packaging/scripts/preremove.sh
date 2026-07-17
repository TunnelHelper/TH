#!/bin/sh
set -eu

case "${1:-}" in
	0|remove|purge)
		if command -v systemctl >/dev/null 2>&1; then
			systemctl stop tunnel-helperd.service >/dev/null 2>&1 || true
			systemctl disable tunnel-helperd.service >/dev/null 2>&1 || true
		fi
		;;
esac

exit 0
