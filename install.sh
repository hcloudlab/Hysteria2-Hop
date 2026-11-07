#!/usr/bin/env bash
set -Eeuo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH}"
export DEBIAN_FRONTEND=noninteractive PYTHONIOENCODING=utf-8
if (( EUID != 0 )); then
  echo '请使用 root 权限运行：sudo bash install.sh' >&2
  exit 1
fi
if ! python3 -c 'import sqlite3, sys; sys.exit(sys.version_info < (3, 8))' 2>/dev/null; then
  echo '安装依赖: python3'
  apt-get -y -o DPkg::Lock::Timeout=300 --no-install-recommends install python3 >/dev/null 2>&1 || {
    apt-get -o DPkg::Lock::Timeout=300 update
    apt-get -y -o DPkg::Lock::Timeout=300 --no-install-recommends install python3
  }
fi
SOURCE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/hy2hop.py"
[[ -f "$SOURCE" ]] || { echo '缺少 hy2hop.py，请下载完整项目' >&2; exit 1; }
python3 -m py_compile "$SOURCE"
exec python3 "$SOURCE" "$@"
