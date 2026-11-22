# -*- coding: utf-8 -*-
"""[一次性] 重启前基线快照 —— 重启后用于效果对比。

用法: python _baseline.py
输出: 同目录 _reboot_baseline.json
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import boot_core as bc  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "_reboot_baseline.json")

# 我们改过 / 重点关注的项
WATCH = [
    "Intel(R) Platform License Manager Service",
    "360AntiHijack", "360Box64", "360CactusNet", "360Camera", "360FsFlt",
    "360Hvm", "360netmon", "360qpesv", "360Sensor_DM", "BAPIDRV",
    "AlibabaProtect", "AliPaladin", "luafv",
    "ESRV_SVC_QUEENCREEK", "SystemUsageReportSvc_QUEENCREEK",
    "MBAMainService", "HiConnectivityService", "WUCS", "WUCSProxy",
    "HwPCCoreService", "HwDistributedMainService",
    "HuaweiHiSuiteService64.exe", "CDPSvc",
]

print("[1/4] collect ...")
raw = bc.collect()
print("[2/4] analyze ...")
res = bc.analyze(raw)

snap = {
    "taken_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    "tool_version": bc.VERSION,
    "score": res.get("score"),
    "grade": res.get("grade"),
    "findings": [{"id": f.get("id"), "sev": f.get("sev"), "title": f.get("title")}
                 for f in res.get("findings", [])],
}

# 汇总统计（重启后复测对比）
sm = {}
try:
    sm["startup_items"] = len(raw.get("startup") or [])
    sm["services_total"] = len(raw.get("services") or [])
    ssys = raw.get("sys") or {}
    sm["svcAuto"] = ssys.get("svcAuto")
    sm["svcAutoRun"] = ssys.get("svcAutoRun")
    sm["svcAutoDown"] = len(ssys.get("svcAutoDown") or [])
    sm["boot_tasks"] = len(ssys.get("tasks") or [])
    sm["filters"] = raw.get("filters")
    sm["ramGB"] = ssys.get("ramGB")
    sm["admin"] = raw.get("admin")
except Exception as e:
    sm["err"] = str(e)
snap["summary"] = sm

# 事件计数 & 电源状态：整个子字典存下来（都是可 JSON 化的）
try:
    snap["events"] = raw.get("events", {})
except Exception as e:
    snap["events_error"] = str(e)
try:
    snap["power"] = raw.get("power", {})
except Exception as e:
    snap["power_error"] = str(e)

# 服务快照（注册表原值）
svcs = {}
svc_list = raw.get("services", []) or []
for s in svc_list:
    nm = s.get("name")
    if nm in WATCH:
        svcs[nm] = {"start": s.get("start"), "type": s.get("type")}
for nm in WATCH:
    if nm not in svcs:
        svcs[nm] = {}
    try:
        svcs[nm]["reg_start"] = bc._read_start(nm)
    except Exception:
        svcs[nm]["reg_start"] = "err"
    try:
        svcs[nm]["reg_delayed"] = bc._read_delayed(nm)
    except Exception:
        svcs[nm]["reg_delayed"] = "err"
snap["watch_services"] = svcs

print("[3/4] boot timeline + proc count ...")

# (a) 本次开机的锚点：开机时刻 + 开机后最早的几条系统日志（重启后对比核心）
ps = r"""
$bt = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$r = @{}
$r.bootTime = $bt.ToString('yyyy-MM-dd HH:mm:ss')
$ev = Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$bt.AddMinutes(-2); EndTime=$bt.AddMinutes(8)} -MaxEvents 300 -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -ge $bt } | Sort-Object TimeCreated
$r.firstLogs = @()
if($ev){ $ev | Select-Object -First 8 | ForEach-Object { $r.firstLogs += ('{0} [{1}] {2}' -f $_.TimeCreated.ToString('HH:mm:ss'), $_.Id, [string]((($_.Message -split "`r?`n")[0]) -replace '\s+',' ')) } }
$r | ConvertTo-Json -Depth 4 -Compress
"""
tl = bc._parse_json(bc.run_ps(ps, timeout=90))
if isinstance(tl, list):
    tl = tl[0] if tl else {}
snap["boot_timeline"] = tl

# (b) 事件100（启动耗时评估）最近一条 —— 数据源状态参考
ps2 = r"""
$e = Get-WinEvent -LogName 'Microsoft-Windows-Diagnostics-Performance/Operational' -MaxEvents 800 | Where-Object {$_.Id -eq 100} | Select-Object -First 1
if($e){ $x=[xml]$e.ToXml(); $d=@{}; foreach($dd in $x.Event.EventData.Data){ $d[$dd.Name]=$dd.'#text' }
[pscustomobject]@{ t=$e.TimeCreated.ToString('yyyy-MM-dd HH:mm'); boot=[int]([double]$d['BootTime']/1000) } | ConvertTo-Json -Compress }
"""
be = bc._parse_json(bc.run_ps(ps2, timeout=90))
if isinstance(be, list):
    be = be[0] if be else {}
snap["last_boot_event_100"] = be

snap["proc_count"] = bc.run_ps("(Get-Process | Measure-Object).Count", timeout=60).strip()

print("[4/4] saving ...")
with open(OUT, "w", encoding="utf-8") as fp:
    json.dump(snap, fp, ensure_ascii=False, indent=2)

print("=" * 60)
print("saved ->", OUT)
print("taken_at :", snap["taken_at"])
print("score    :", snap["score"], "/", snap["grade"])
print("findings :")
for f in snap["findings"]:
    print("   [%s] %s" % (f["sev"], f["title"]))
print("boot timeline (this session):")
tl = snap.get("boot_timeline", {})
print("   boot_time:", tl.get("bootTime"))
for line in tl.get("firstLogs", []):
    print("   ", line)
print("last event-100:", snap.get("last_boot_event_100"))
print("proc_count:", snap["proc_count"])
print("events   :", json.dumps(snap.get("events", {}), ensure_ascii=False)[:400])
