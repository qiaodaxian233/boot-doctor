# -*- coding: utf-8 -*-
"""体检耗时细分：比 _prof_scan.py 多拆一层，看 PowerShell 里到底哪条命令慢。

用法：python _prof_detail.py      （CI 里也跑，日志里能直接看到各段耗时）
"""
import os
import subprocess
import sys
import time

t_imp = time.perf_counter()
import boot_core as bc  # noqa: E402
T_IMPORT_CORE = time.perf_counter() - t_imp


def ps_statements(script):
    """把 PS 脚本按「花括号配平」切成独立语句（foreach / ForEach-Object 块会跨行）。"""
    out, buf, depth = [], [], 0
    for line in script.strip().splitlines():
        if not line.strip():
            continue
        buf.append(line)
        depth += line.count("{") - line.count("}")
        if depth <= 0:
            out.append("\n".join(buf))
            buf, depth = [], 0
    if buf:
        out.append("\n".join(buf))
    return out


def time_ps_script(name, script):
    """在同一个 PowerShell 进程里逐条计时（排除进程启动开销）。"""
    stmts = ps_statements(script)
    parts = ["$__sw=[Diagnostics.Stopwatch]::new()"]
    for i, s in enumerate(stmts):
        if "ConvertTo-Json" in s:
            continue
        parts.append("$__sw.Restart()")
        parts.append(s)
        parts.append("'@@%d|' + $__sw.ElapsedMilliseconds" % i)
    out = bc.run_ps("\n".join(parts), timeout=300)
    print("\n[%s] 进程内逐条耗时：" % name)
    rows = []
    for line in out.splitlines():
        if line.startswith("@@"):
            i, ms = line[2:].split("|")
            first = stmts[int(i)].strip().splitlines()[0]
            rows.append((int(ms), first[:90]))
    for ms, s in sorted(rows, reverse=True):
        print("  %6d ms  %s" % (ms, s))
    return sum(ms for ms, _ in rows)


def timed(label, fn):
    t = time.perf_counter()
    try:
        r = fn()
    except Exception as e:
        r = e
    dt = time.perf_counter() - t
    print("  %-38s %7.0f ms" % (label, dt * 1000), flush=True)
    return r, dt


print("Python %s  管理员=%s" % (sys.version.split()[0], bc.is_admin()))
print("\n[导入]")
print("  %-38s %7.0f ms" % ("import boot_core", T_IMPORT_CORE * 1000))
t = time.perf_counter()
import PyQt5.QtWidgets  # noqa: E402,F401
print("  %-38s %7.0f ms" % ("import PyQt5.QtWidgets", (time.perf_counter() - t) * 1000))

print("\n[外部进程启动开销]")
nw = getattr(subprocess, "CREATE_NO_WINDOW", 0)
timed("powershell 空跑（-Command 1）", lambda: subprocess.run(
    ["powershell", "-NoProfile", "-NonInteractive", "-Command", "1"],
    capture_output=True, creationflags=nw))
timed("wevtutil 启动（列出日志）", lambda: subprocess.run(
    ["wevtutil", "el"], capture_output=True, creationflags=nw))

print("\n[整段：旧 vs 新，各跑两轮（第一轮含冷启动）]")
for rnd in (1, 2):
    timed("第%d轮 旧 run_ps(PS_SYS)" % rnd, lambda: bc.run_ps(bc.PS_SYS, timeout=120))
    if hasattr(bc, "sys_info_native"):
        timed("第%d轮 新 sys_info_native()" % rnd, bc.sys_info_native)
    if hasattr(bc, "PS_EVENTS_LEGACY"):
        timed("第%d轮 旧 run_ps(PS_EVENTS_LEGACY)" % rnd,
              lambda: bc.run_ps(bc.PS_EVENTS_LEGACY, timeout=180))
    timed("第%d轮 新 run_ps(PS_EVENTS)" % rnd, lambda: bc.run_ps(bc.PS_EVENTS, timeout=180))

if hasattr(bc, "sys_info_native"):
    print("\n[原生采集分项]")
    timed("服务状态 _svc_auto_stats", bc._svc_auto_stats)
    timed("开机/登录任务 boot_logon_tasks_from_xml", bc.boot_logon_tasks_from_xml)
    timed("磁盘健康 run_ps(PS_DISKS)", lambda: bc.run_ps(bc.PS_DISKS, timeout=60))
    timed("卷 _volumes", bc._volumes)
    timed("系统名/开机时间/内存", lambda: (bc._os_caption(), bc._boot_time_str(), bc._ram_gb()))

time_ps_script("PS_SYS", bc.PS_SYS)
time_ps_script("PS_EVENTS", bc.PS_EVENTS)

print("\n[体检全流程，与界面里的 ScanWorker 一致]")
os.environ.setdefault("BOOTDOC_NOSCAN", "1")
raw, dt_collect = timed("collect()（含并行 PowerShell）", lambda: bc.collect())
if isinstance(raw, dict):
    res, _ = timed("analyze()", lambda: bc.analyze(raw))
    if isinstance(res, dict):
        apps = {}
        for f in res.get("findings", []):
            app = f.get("app") or {}
            if app.get("path") and app.get("exists"):
                apps[app["path"].lower()] = app
        timed("签名校验 %d 个（串行）" % len(apps),
              lambda: [bc.app_signature(a) for a in apps.values()])
        print("  发现项 %d 个" % len(res.get("findings") or []))

print("\n[签名校验成本：系统目录前 40 个 exe，冷缓存]")
sysdir = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
exes = sorted(n for n in os.listdir(sysdir) if n.lower().endswith(".exe"))[:40]
infos = [bc.describe_app(os.path.join(sysdir, n)) for n in exes]
infos = [i for i in infos if i.get("exists")]
t = time.perf_counter()
for i in infos:
    bc.app_signature(i)
print("  串行 %d 个：%.0f ms（平均 %.1f ms/个）" % (
    len(infos), (time.perf_counter() - t) * 1000, (time.perf_counter() - t) * 1000 / max(1, len(infos))))
bc._SIG_CACHE.clear()
t = time.perf_counter()
bc.warm_signatures(infos)
print("  6 线程并行 %d 个：%.0f ms" % (len(infos), (time.perf_counter() - t) * 1000))
st = {}
for i in infos:
    r = bc.app_signature(i)
    st[(r["state"], bool(bc.real_microsoft(r)))] = st.get((r["state"], bool(bc.real_microsoft(r))), 0) + 1
print("  结果分布（状态, 是否认成微软）：%s" % sorted(st.items()))

print("\n[程序启动：打开到第一屏有内容]")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
t = time.perf_counter()
import boot_doctor as bd  # noqa: E402
print("  import boot_doctor                         %7.0f ms" % ((time.perf_counter() - t) * 1000))
from PyQt5.QtWidgets import QApplication  # noqa: E402
_app = QApplication.instance() or QApplication([])
t = time.perf_counter()
_win = bd.MainWindow(autoscan=False)
print("  构建主窗口 MainWindow()                    %7.0f ms" % ((time.perf_counter() - t) * 1000))
if isinstance(raw, dict):
    bc.save_last_scan(raw)
    t = time.perf_counter()
    _win._load_cached()
    print("  读缓存 + 重新分析 + 摆出结果               %7.0f ms   <- 打开后多久能看到上次的结果" % (
        (time.perf_counter() - t) * 1000))
    t = time.perf_counter()
    _r = bc.collect()
    print("  对比：真实重新体检 collect()              %7.0f ms   <- 以前要等这么久才有内容" % (
        (time.perf_counter() - t) * 1000))
_win.close()

