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
  x86_64|amd64)
    asset_arch="amd64"
    deb_arch="amd64"
    rpm_arch="x86_64"
    ;;
  aarch64|arm64)
    asset_arch="arm64"
    deb_arch="arm64"
    rpm_arch="aarch64"
    ;;
  armv7l|armv7)
    asset_arch="armv7"
    deb_arch="armhf"
    rpm_arch="armv7hl"
    ;;
  *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

dependencies=(curl sha256sum)
if [[ "$INSTALL" -eq 0 ]]; then
  dependencies+=(tar)
fi
for dependency in "${dependencies[@]}"; do
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

package_format=""
if [[ "$INSTALL" -eq 1 ]]; then
  if command -v apt-get >/dev/null 2>&1 && command -v dpkg >/dev/null 2>&1; then
    package_format="deb"
    asset_suffix="_${deb_arch}.deb"
  elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1 || command -v zypper >/dev/null 2>&1 || command -v rpm >/dev/null 2>&1; then
    package_format="rpm"
    asset_suffix=".${rpm_arch}.rpm"
  else
    echo "A Debian or RPM package manager is required for installation." >&2
    exit 1
  fi
else
  asset_suffix="linux_${asset_arch}.tar.gz"
fi

asset_url="$(printf '%s\n' "$metadata" | awk -F '"' -v suffix="$asset_suffix" '
  /browser_download_url/ && length($4) >= length(suffix) && substr($4, length($4) - length(suffix) + 1) == suffix {print $4; exit}
')"
checksum_url="$(printf '%s\n' "$metadata" | awk -F '"' '/browser_download_url/ && $4 ~ /\/checksums.txt$/ {print $4; exit}')"
if [[ -z "$asset_url" || -z "$checksum_url" ]]; then
  echo "No release asset found for ${asset_suffix}." >&2
  exit 1
fi

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT
asset_name="${asset_url##*/}"
asset_path="$workdir/$asset_name"
curl -fsSL --max-time 120 "${headers[@]}" "$asset_url" -o "$asset_path"
curl -fsSL --max-time 30 "${headers[@]}" "$checksum_url" -o "$workdir/checksums.txt"
expected_checksum="$(awk -v name="$asset_name" '$2 == name {print $1; exit}' "$workdir/checksums.txt")"
if [[ -z "$expected_checksum" ]]; then
  echo "Release checksum does not contain $asset_name." >&2
  exit 1
fi
printf '%s  %s\n' "$expected_checksum" "$asset_path" | sha256sum --check --status

if [[ "$INSTALL" -eq 0 ]]; then
  tar -xzf "$asset_path" -C "$workdir"
  client="$workdir/tunnel-helper"
  daemon="$workdir/tunnel-helperd"
  if [[ ! -x "$client" || ! -x "$daemon" ]]; then
    echo "Release archive does not contain both V2 binaries." >&2
    exit 1
  fi
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

case "$package_format" in
  deb)
    "${as_root[@]}" apt-get install -y "$asset_path"
    ;;
  rpm)
    if command -v dnf >/dev/null 2>&1; then
      "${as_root[@]}" dnf install -y "$asset_path"
    elif command -v yum >/dev/null 2>&1; then
      "${as_root[@]}" yum install -y "$asset_path"
    elif command -v zypper >/dev/null 2>&1; then
      "${as_root[@]}" zypper --non-interactive --no-gpg-checks install "$asset_path"
    else
      "${as_root[@]}" rpm -Uvh --replacepkgs "$asset_path"
    fi
    ;;
esac

operator="${SUDO_USER:-$(id -un)}"
group_added=0
if [[ -n "$operator" && "$operator" != "root" ]] && id "$operator" >/dev/null 2>&1; then
  is_member=0
  for operator_group in $(id -nG "$operator"); do
    if [[ "$operator_group" == "tunnel-helper" ]]; then
      is_member=1
      break
    fi
  done
  if [[ "$is_member" -eq 0 ]]; then
    if "${as_root[@]}" sh -c 'command -v usermod >/dev/null 2>&1'; then
      "${as_root[@]}" usermod -aG tunnel-helper "$operator"
      group_added=1
    elif "${as_root[@]}" sh -c 'command -v gpasswd >/dev/null 2>&1'; then
      "${as_root[@]}" gpasswd -a "$operator" tunnel-helper
      group_added=1
    else
      echo "Could not add $operator to the tunnel-helper group automatically." >&2
    fi
  fi
fi

echo "Installed $asset_name and registered tunnel-helperd.service."
if [[ "$group_added" -eq 1 ]]; then
  echo "Added $operator to the tunnel-helper group; start a new login session before running tunnel-helper."
elif [[ "$operator" == "root" ]]; then
  echo "Add non-root operators to the tunnel-helper group before they run tunnel-helper."
fi
