# -*- coding: utf-8 -*-
"""特征库更新（命令行版）

正常用界面里的「操作 → 更新流氓软件特征库…」即可，这个脚本给三种场景用：
  1. 没开图形界面时批量更新（比如做成计划任务每周跑一次）
  2. 先看看上游加了什么，再决定要不要写进本地库（--dry-run）
  3. 内网 / 代理环境，手动把 folder.txt、sign.txt、whitepath.txt 下下来，
     用 --offline 从一个本地目录更新

用法：
    python _db_update.py                 # 在线更新
    python _db_update.py --dry-run       # 只看差异，不写文件
    python _db_update.py --offline D:\\db # 从本地目录更新
    python _db_update.py --source https://example.com/db/   # 指定源

更新前会自动把旧库备份到 _backups\\adware_db-<时间>.json，
差异明细追加写入 _logs\\adware_db.log。
"""
import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import boot_core as bc  # noqa: E402


def show_cur():
    st = bc.adware_db_stats()
    print("当前特征库：v%s  更新于 %s" % (st["version"], st["updated"]))
    print("  %d 个目录 + %d 个签名主体 + %d 个厂商家族（白名单 %d 条）"
          % (st["dirs"], st["pubs"], st["families"], st["white"]))
    if st["sources"]:
        print("  来源：%s" % st["sources"][0])


def show_rep(rep):
    if not rep.get("ok"):
        print("\n[失败] %s" % rep.get("error"))
        return 1
    if rep.get("up_to_date"):
        print("\n[已是最新] v%s（%s）  源：%s" % (rep["version"], rep["updated"],
                                              rep.get("source")))
        print("  上游没有新条目，本地库未改动。")
        return 0
    tag = "预演（未写入）" if rep.get("dry_run") else "已写入"
    print("\n[成功] %s  源：%s" % (tag, rep.get("source")))
    print("  新版本 v%s  更新日期 %s" % (rep["version"], rep["updated"]))
    print("  目录 %d（新增 %d / 移除 %d / 改为带路径 %d）"
          % (rep["dirs"], rep["added_dirs"], rep["removed_dirs"], rep["moved_dirs"]))
    print("  签名 %d（新增 %d / 移除 %d）"
          % (rep["pubs"], rep["added_pubs"], rep["removed_pubs"]))
    if rep.get("samples_added"):
        print("  新增样例：%s" % "、".join(rep["samples_added"][:12]))
    if rep.get("samples_removed"):
        print("  移除样例：%s" % "、".join(rep["samples_removed"][:8]))
    if rep.get("backup"):
        print("  旧库备份：%s" % rep["backup"])
    return 0


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    ap = argparse.ArgumentParser(description="更新流氓软件特征库")
    ap.add_argument("--dry-run", action="store_true", help="只算差异，不写文件")
    ap.add_argument("--offline", metavar="DIR", help="从本地目录读取 folder.txt / sign.txt")
    ap.add_argument("--source", action="append", metavar="URL",
                    help="自定义源（可重复，按顺序尝试）")
    ap.add_argument("--db", metavar="FILE", help="指定要写入的特征库路径（默认 adware_db.json）")
    a = ap.parse_args()

    show_cur()
    sources = None
    if a.offline:
        sources = [os.path.abspath(a.offline)]
    if a.source:
        sources = (sources or []) + a.source

    rep = bc.update_adware_db(dry_run=a.dry_run, sources=sources,
                              path=a.db, progress=lambda t: print("  · %s" % t))
    return show_rep(rep)


if __name__ == "__main__":
    sys.exit(main())
