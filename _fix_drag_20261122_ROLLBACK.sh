#!/bin/sh
# 回滚拖动卡顿修复：把 boot_doctor.py 还原成 2026-11-22 16:14 的版本
# 用法（Git Bash / sh）： sh _fix_drag_20261122_ROLLBACK.sh
set -e
cd "$(dirname "$0")"

if [ ! -f "boot_doctor.py.bak_拖动卡顿20261122" ]; then
  echo "找不到备份文件，回滚中止" >&2
  exit 1
fi

cp "boot_doctor.py.bak_拖动卡顿20261122" boot_doctor.py
echo "已回滚。当前 boot_doctor.py 大小：$(wc -c < boot_doctor.py) 字节"
echo "验证：python _drag_probe.py move_now   # 回滚后 p50 应回到 30ms 以上"
