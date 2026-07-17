#!/usr/bin/env bash
set -euo pipefail

REPOSITORY="sudogeeker/tunnel-helper"
INSTALL=0
args=()
for arg in "$@"; do
  if [[ "$arg" == "--install" ]]; then
    INSTALL=1
  else
    args+=("$arg")
  fi
done

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "tunnel-helper V2 supports Linux only." >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64|amd64) asset_arch="amd64" ;;
  aarch64|arm64) asset_arch="arm64" ;;
  armv7l|armv7) asset_arch="armv7" ;;
  *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

for dependency in curl tar sha256sum; do
  command -v "$dependency" >/dev/null 2>&1 || {
    echo "$dependency is required." >&2
    exit 1
  }
done

headers=()
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
  headers=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
fi
metadata="$(curl -fsSL --max-time 30 "${headers[@]}" "https://api.github.com/repos/${REPOSITORY}/releases/latest")"
asset_url="$(printf '%s\n' "$metadata" | awk -F '"' -v suffix="linux_${asset_arch}.tar.gz" '/browser_download_url/ && index($4, suffix) {print $4; exit}')"
checksum_url="$(printf '%s\n' "$metadata" | awk -F '"' '/browser_download_url/ && $4 ~ /\/checksums.txt$/ {print $4; exit}')"
if [[ -z "$asset_url" || -z "$checksum_url" ]]; then
  echo "No V2 release archive found for linux_${asset_arch}." >&2
  exit 1
fi

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT
curl -fsSL --max-time 120 "${headers[@]}" "$asset_url" -o "$workdir/release.tar.gz"
curl -fsSL --max-time 30 "${headers[@]}" "$checksum_url" -o "$workdir/checksums.txt"
asset_name="${asset_url##*/}"
expected_checksum="$(awk -v name="$asset_name" '$2 == name {print $1; exit}' "$workdir/checksums.txt")"
if [[ -z "$expected_checksum" ]]; then
  echo "Release checksum does not contain $asset_name." >&2
  exit 1
fi
printf '%s  %s\n' "$expected_checksum" "$workdir/release.tar.gz" | sha256sum --check --status
tar -xzf "$workdir/release.tar.gz" -C "$workdir"

client="$workdir/tunnel-helper"
daemon="$workdir/tunnel-helperd"
if [[ ! -x "$client" || ! -x "$daemon" ]]; then
  echo "Release archive does not contain both V2 binaries." >&2
  exit 1
fi

if [[ "$INSTALL" -eq 0 ]]; then
  "$client" "${args[@]}"
  exit $?
fi

as_root=()
if [[ "$(id -u)" -ne 0 ]]; then
  command -v sudo >/dev/null 2>&1 || {
    echo "Installation requires root or sudo." >&2
    exit 1
  }
  as_root=(sudo)
fi

"${as_root[@]}" install -Dm0755 "$client" /usr/bin/tunnel-helper
"${as_root[@]}" install -Dm0755 "$daemon" /usr/sbin/tunnel-helperd
"${as_root[@]}" install -Dm0644 "$workdir/packaging/systemd/tunnel-helperd.service" /usr/lib/systemd/system/tunnel-helperd.service
"${as_root[@]}" install -Dm0644 "$workdir/packaging/sysusers.d/tunnel-helper.conf" /usr/lib/sysusers.d/tunnel-helper.conf
"${as_root[@]}" install -Dm0644 "$workdir/packaging/tmpfiles.d/tunnel-helper.conf" /usr/lib/tmpfiles.d/tunnel-helper.conf
"${as_root[@]}" install -d -m0755 /etc/tunnel-helper
if ! "${as_root[@]}" test -e /etc/tunnel-helper/tunnel-helperd.json; then
  "${as_root[@]}" install -m0644 "$workdir/packaging/tunnel-helperd.json" /etc/tunnel-helper/tunnel-helperd.json
fi

if command -v systemd-sysusers >/dev/null 2>&1; then
  "${as_root[@]}" systemd-sysusers /usr/lib/sysusers.d/tunnel-helper.conf
fi
if command -v systemd-tmpfiles >/dev/null 2>&1; then
  "${as_root[@]}" systemd-tmpfiles --create /usr/lib/tmpfiles.d/tunnel-helper.conf
fi

echo "Installed tunnel-helper V2."
echo "Add operators to the tunnel-helper group, then enable tunnel-helperd with your service manager."
