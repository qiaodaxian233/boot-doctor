# -*- coding: utf-8 -*-
"""
boot_doctor 配套：取消 / 恢复「登录后延时启动」

那个把自启项改成延时启动的工具是本目录下的 boot_doctor（开机体检大师）。
它对一个自启项做「延迟启动」时会干两件事：
    1. 建计划任务  BootDoctor-Delay-<名字>   （登录后延迟 delay_seconds 秒）
    2. 在 StartupApproved\\Run（或 StartupFolder）里给原自启项写 03 00*11 的禁用标记

所以「不想延时了」= 删掉延迟任务 + 把 StartupApproved 里那条标记恢复原值。
本脚本就干这件事，原值从 _backups/*/snapshot.json 里读（工具自己存的快照）。

用法：
    python undelay.py            交互模式（列清单 -> 输编号）
    python undelay.py --list     只列清单
    python undelay.py --cancel 2,5,9     取消这几条的延时（立即随登录启动）
    python undelay.py --redo 2,5,9       反向：重新变回延时启动
"""
import os
import sys
import glob
import json
import base64
import winreg

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import boot_core as bc  # noqa: E402

try:
    sys.stdout.reconfigure(errors="replace")
except Exception:
    pass


# ---------------------------------------------------------------- 快照
def load_snapshot_map():
    """从历次备份里读出 任务名 -> 原始自启项信息（含 old = 原 StartupApproved 值）。"""
    m = {}
    pat = os.path.join(HERE, "_backups", "*", "snapshot.json")
    for p in sorted(glob.glob(pat), reverse=True):
        try:
            with open(p, encoding="utf-8") as fp:
                d = json.load(fp)
        except Exception:
            continue
        for it in d.get("items") or []:
            if it.get("kind") != "startup_delay":
                continue
            task = it.get("task")
            if task and task not in m:
                m[task] = it
    return m


def parse_old(v):
    """old 可能是 None / hex 字符串 / {'__b64__':...}。"""
    if not v:
        return None
    if isinstance(v, dict):
        b = v.get("__b64__")
        return base64.b64decode(b) if b else None
    if isinstance(v, str):
        try:
            return bytes.fromhex(v)
        except ValueError:
            return None
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    return None


# ---------------------------------------------------------------- 注册表标记
def approved_path(kindx):
    return bc._APPROVED_BASE + ("\\StartupFolder" if kindx == "folder" else "\\Run")


def read_approved(hive, kindx, name):
    try:
        with winreg.OpenKey(bc._root_of(hive), approved_path(kindx), 0, winreg.KEY_READ) as k:
            v, _ = winreg.QueryValueEx(k, name)
        return v if isinstance(v, (bytes, bytearray)) else None
    except OSError:
        return None


def write_approved(hive, kindx, name, blob):
    with winreg.CreateKeyEx(bc._root_of(hive), approved_path(kindx), 0, winreg.KEY_SET_VALUE) as k:
        if blob:
            winreg.SetValueEx(k, name, 0, winreg.REG_BINARY, blob)
        else:
            try:
                winreg.DeleteValue(k, name)
            except OSError:
                pass


def startup_value_exists(hive, kindx, name):
    """原自启项本身还在不在（Run 值 / 启动文件夹快捷方式）。"""
    if kindx == "folder":
        import pathlib
        base = os.path.join(os.environ.get("APPDATA", ""),
                            r"Microsoft\Windows\Start Menu\Programs\Startup")
        return os.path.exists(os.path.join(base, name))
    sub = r"Software\Microsoft\Windows\CurrentVersion\Run"
    try:
        with winreg.OpenKey(bc._root_of(hive), sub, 0, winreg.KEY_READ) as k:
            winreg.QueryValueEx(k, name)
        return True
    except OSError:
        return False


def is_disabled(blob):
    return bool(blob) and len(blob) > 0 and blob[0] % 2 == 1


# ---------------------------------------------------------------- 采集
def collect():
    """当前所有延迟任务 + 快照信息 + 现状，组成清单。"""
    snap = load_snapshot_map()
    rows = []
    for t in bc.existing_delay_tasks():
        it = snap.get(t["task"]) or {}
        hive = it.get("hive", "HKCU")
        kindx = it.get("kindx", "run")
        name = it.get("name") or t["name"]
        blob = read_approved(hive, kindx, name)
        rows.append({
            "task": t["task"],
            "name": name,
            "exe": os.path.basename(t["exe"] or "") or t["exe"],
            "delay": t["delay"],
            "enabled": t["enabled"],
            "hive": hive,
            "kindx": kindx,
            "old": it.get("old"),
            "now_disabled": is_disabled(blob),
            "value_alive": startup_value_exists(hive, kindx, name),
        })
    return rows


def describe(r):
    place = "%s\\%s" % (r["hive"], "启动文件夹" if r["kindx"] == "folder" else "Run")
    if not r["enabled"]:
        state = "任务已禁用"
    elif r["now_disabled"]:
        state = "延时中(%ds)" % r["delay"]
    else:
        state = "任务在但原自启未禁用"
    env = "" if r["value_alive"] else " [原自启项已不存在]"
    return state + env + "  " + place


def print_rows(rows):
    if not rows:
        print("没有找到 BootDoctor-Delay-* 任务。")
        return
    print("")
    print("  #  程序                          当前状态 / 位置")
    print("  " + "-" * 88)
    for i, r in enumerate(rows, 1):
        print("  %-3s %-28s %s" % (i, r["name"][:28], describe(r)))
    print("")


# ---------------------------------------------------------------- 动作
def cancel_one(r):
    ok, msg = bc._remove_delay_task(r["task"])
    print("    %s" % msg)
    if not ok:
        return False
    if r["value_alive"] is False:
        # 原自启项自己都没了，写回标记只会留一个「已禁用」幽灵条目，直接清掉
        try:
            write_approved(r["hive"], r["kindx"], r["name"], None)
        except OSError as e:
            print("    清除残留标记失败：%s" % e)
            return False
        print("    原自启项已不存在：已删除残留标记，不再恢复自启")
        return True
    blob = parse_old(r["old"])
    try:
        write_approved(r["hive"], r["kindx"], r["name"], blob)
    except OSError as e:
        print("    恢复自启标记失败：%s" % e)
        return False
    print("    已恢复自启：%s（%s\\%s）-> 下次登录立即启动"
          % (r["name"], r["hive"], "StartupFolder" if r["kindx"] == "folder" else "Run"))
    return True


def redo_one(r, delay=None):
    ok, msg = bc._create_delay_task(r["exe"], "", r["task"], delay_sec=delay)
    print("    %s" % msg)
    if not ok:
        return False
    ok2, msg2 = bc._disable_startup_item(
        {"hive": r["hive"], "kind": r["kindx"], "name": r["name"]})
    print("    %s" % msg2)
    return ok2


# ---------------------------------------------------------------- 入口
def pick(rows, raw):
    idx = []
    raw = (raw or "").strip().lower()
    if raw in ("all", "*", "a"):
        return list(range(len(rows)))
    for part in raw.replace("，", ",").split(","):
        part = part.strip()
        if not part:
            continue
        if part.isdigit():
            n = int(part)
            if 1 <= n <= len(rows):
                idx.append(n - 1)
        else:
            for i, r in enumerate(rows):
                if part in r["name"].lower() or part in r["task"].lower():
                    idx.append(i)
    return sorted(set(idx))


def main(argv):
    rows = collect()
    action = "list"
    target = ""

    if len(argv) >= 1:
        a = argv[0].lower()
        if a in ("--list", "-l"):
            action = "list"
        elif a in ("--cancel", "--redo"):
            action = "cancel" if a == "--cancel" else "redo"
            target = argv[1] if len(argv) > 1 else ""
        else:
            print(__doc__)
            return 2
    else:
        print_rows(rows)
        if not rows:
            return 0
        print("输入要【不再延时】的编号（逗号分隔，all=全部，直接回车退出）：")
        target = input("> ").strip()
        if not target:
            return 0
        action = "cancel"

    if action == "list" or not target:
        print_rows(rows)
        return 0

    sel = pick(rows, target)
    if not sel:
        print("没有匹配到条目。")
        return 1

    print("")
    print("将%s以下 %d 项：" % ("取消延时" if action == "cancel" else "恢复延时", len(sel)))
    for i in sel:
        print("  %s  (%s)" % (rows[i]["name"], describe(rows[i])))
    print("")

    if sys.stdin.isatty() and action == "cancel":
        c = input("确认？(y/N) ").strip().lower()
        if c not in ("y", "yes"):
            print("已取消操作。")
            return 0

    okc = 0
    for i in sel:
        r = rows[i]
        print("  [%s]" % r["name"])
        if action == "cancel":
            if r["value_alive"] is False:
                print("    跳过：原自启项已不存在，只删任务不恢复标记")
            if cancel_one(r):
                okc += 1
        else:
            if redo_one(r):
                okc += 1
    print("")
    print("完成：成功 %d / %d" % (okc, len(sel)))
    if okc:
        print("改动在【下次登录】生效；当前已运行的程序不受影响。")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
