# -*- coding: utf-8 -*-
"""重启后验证：当前状态 vs 重启前基线（_reboot_baseline.json）。

用法: python _verify_after_reboot.py
输出: 屏幕 + _reboot_verify_report.txt
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import boot_core as bc  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
BASE_PATH = os.path.join(HERE, "_reboot_baseline.json")
RPT = os.path.join(HERE, "_reboot_verify_report.txt")

LINES = []


def L(s=""):
    LINES.append(str(s))
    print(s)


def main():
    if not os.path.exists(BASE_PATH):
        print("baseline not found:", BASE_PATH)
        return 1
    with open(BASE_PATH, encoding="utf-8") as f:
        base = json.load(f)

    L("=" * 62)
    L("reboot verify report")
    L("baseline : %s" % base.get("taken_at"))
    L("now      : %s" % time.strftime("%Y-%m-%d %H:%M:%S"))
    L("=" * 62)

    L("")
    L("[0] collecting (approx 10-20s) ...")
    raw = bc.collect()
    res = bc.analyze(raw)
    ev = raw.get("events") or {}
    sysd = raw.get("sys") or {}

    # 1) score
    L("")
    L("[1] health score : %s -> %s" % (base.get("score"), res.get("score")))

    # 2) 7005 since fix
    b_last = (base.get("events") or {}).get("last7005")
    n_last = ev.get("last7005")
    if n_last == b_last:
        verdict = "OK - no new 7005 since fix"
    else:
        verdict = "WARN - new 7005 appeared!"
    L("")
    L("[2] 7005 last:")
    L("    baseline: %s" % b_last)
    L("    now     : %s   => %s" % (n_last, verdict))

    # 3) filter drivers
    want_gone = ["360Box64", "360FsFlt", "360qpesv", "AliPaladin"]
    flt = raw.get("filters") or []
    still = [x for x in want_gone if x in flt]
    gone = [x for x in want_gone if x not in flt]
    L("")
    L("[3] loaded filter drivers:")
    L("    removed     : %s" % (", ".join(gone) if gone else "(none)"))
    L("    still loaded: %s" % (", ".join(still) if still else "none - all clean"))
    L("    full list   : %s" % ",".join(flt))

    # 4) key services
    b_svcs = base.get("watch_services") or {}
    n_svcs = {}
    for s in raw.get("services") or []:
        n_svcs[s.get("name")] = s
    L("")
    L("[4] key services (Start value):")
    for nm in sorted(b_svcs):
        bv = (b_svcs.get(nm) or {}).get("reg_start")
        nv = (n_svcs.get(nm) or {}).get("start")
        tag = ""
        if nm == "AlibabaProtect":
            tag = "  (target=4, cleanup after reboot)"
        L("    %-46s %s -> %s%s" % (nm, bv, nv, tag))

    # 5) counts
    bsm = base.get("summary") or {}
    L("")
    L("[5] counts:")
    L("    svcAuto       : %s -> %s" % (bsm.get("svcAuto"), sysd.get("svcAuto")))
    L("    svcAutoRun    : %s -> %s" % (bsm.get("svcAutoRun"), sysd.get("svcAutoRun")))
    L("    startup items : %s -> %s" % (bsm.get("startup_items"), len(raw.get("startup") or [])))
    L("    boot tasks    : %s -> %s" % (bsm.get("boot_tasks"), len(sysd.get("tasks") or [])))
    L("    processes     : %s -> %s" % (base.get("proc_count"),
                                        bc.run_ps("(Get-Process | Measure-Object).Count", timeout=60).strip()))

    # 6) this boot timeline
    ps = r"""
$bt = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$r = @{}
$r.bootTime = $bt.ToString('yyyy-MM-dd HH:mm:ss')
$r.bootType = ''
$e27 = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Kernel-Boot'; Id=27; StartTime=$bt.AddMinutes(-2)} -MaxEvents 3 -ErrorAction SilentlyContinue
if($e27){ $m = ($e27 | Select-Object -First 1).Message; if($m -match '0x[0-9a-fA-F]+'){ $r.bootType = $Matches[0] } }
$r.kernStart = ''
$e12 = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Kernel-General'; Id=12; StartTime=$bt.AddMinutes(-2)} -MaxEvents 1 -ErrorAction SilentlyContinue
if($e12){ $r.kernStart = $e12.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') }
$ev = Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$bt; EndTime=$bt.AddMinutes(8)} -MaxEvents 300 -ErrorAction SilentlyContinue | Sort-Object TimeCreated
$r.firstLogs = @()
if($ev){ $ev | Select-Object -First 6 | ForEach-Object { $r.firstLogs += ('{0} [{1}]' -f $_.TimeCreated.ToString('HH:mm:ss'), $_.Id) } }
$r | ConvertTo-Json -Depth 4 -Compress
"""
    tl = bc._parse_json(bc.run_ps(ps, timeout=90))
    if isinstance(tl, list):
        tl = tl[0] if tl else {}
    bt = (tl or {}).get("bootType", "")
    meaning = {"0x0": "full cold boot (expected for RESTART)",
               "0x1": "FAST STARTUP active (hiberboot)",
               "0x2": "resume from hibernate"}.get(bt, "?")
    L("")
    L("[6] this boot:")
    L("    baseline boot time: %s" % (base.get("boot_timeline") or {}).get("bootTime"))
    L("    current  boot time: %s" % tl.get("bootTime"))
    L("    kernel start (12) : %s" % tl.get("kernStart"))
    L("    boot type         : %s  (%s)" % (bt, meaning))
    for x in tl.get("firstLogs") or []:
        L("      %s" % x)

    L("")
    L("=" * 62)
    with open(RPT, "w", encoding="utf-8") as f:
        f.write("\n".join(LINES))
    print("saved ->", RPT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
