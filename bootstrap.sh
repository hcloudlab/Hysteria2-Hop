#!/usr/bin/env bash
# HCloudLab Hysteria2-Hop bootstrap: Debian 11/12/13, Ubuntu 20.04/22.04/24.04/26.04
set -Eeuo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH}"
export DEBIAN_FRONTEND=noninteractive PYTHONIOENCODING=utf-8
if (( EUID != 0 )); then
  echo '请使用 root 权限运行' >&2
  exit 1
fi
need=()
command -v curl >/dev/null || need+=(curl ca-certificates)
python3 -c 'import sqlite3, sys; sys.exit(sys.version_info < (3, 8))' 2>/dev/null || need+=(python3)
if (( ${#need[@]} )); then
  echo "安装依赖: ${need[*]}"
  apt-get -y -o DPkg::Lock::Timeout=300 --no-install-recommends install "${need[@]}" >/dev/null 2>&1 || {
    apt-get -o DPkg::Lock::Timeout=300 update
    apt-get -y -o DPkg::Lock::Timeout=300 --no-install-recommends install "${need[@]}"
  }
fi
python3 -c 'import sqlite3, sys; sys.exit(sys.version_info < (3, 8))' || { echo '需要 Python 3.8+（含 sqlite3 模块）' >&2; exit 1; }
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
curl -fL --retry 3 --connect-timeout 10 -o "$TMP/hy2hop.py" 'https://raw.githubusercontent.com/hcloudlab/Hysteria2-Hop/main/hy2hop.py'
python3 -m py_compile "$TMP/hy2hop.py"
# Not exec: the EXIT trap must still remove $TMP afterwards.
python3 "$TMP/hy2hop.py" "$@"
