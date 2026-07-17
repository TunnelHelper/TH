#!/bin/sh
set -eu

case "${1:-}" in
	0|remove|purge)
		if command -v systemctl >/dev/null 2>&1; then
			systemctl daemon-reload >/dev/null 2>&1 || true
			systemctl reset-failed tunnel-helperd.service >/dev/null 2>&1 || true
		fi
		;;
esac

# Configuration, state, and the operator group are deliberately preserved.
exit 0
