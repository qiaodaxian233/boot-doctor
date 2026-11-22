# -*- coding: utf-8 -*-
"""开机体检大师 · 核心库 (boot_core)

职责：
  collect()          只读采集：注册表 / 事件日志 / 系统信息 / 过滤器驱动
  analyze()          智能分析：规则引擎 -> 问题清单 + 健康分
  make_backup()      修复前自动快照（snapshot.json + restore-all.reg + 说明.txt）
  apply_fixes()      执行修复（全部可还原）
  restore_backup()   一键还原
  list_backups()     列出历史备份
  build_report()     生成体检报告（markdown）

依赖：仅标准库（winreg / ctypes / subprocess / json），
      系统组件 PowerShell 5.1（事件日志与部分系统信息查询）。
      不做任何写入操作，除非显式调用 apply_fixes / restore_backup。
"""
from __future__ import annotations

import base64
import ctypes
import datetime as _dt
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import winreg

APP_NAME = "开机体检大师"
VERSION = "1.9.2"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BACKUP_DIR = os.path.join(BASE_DIR, "_backups")
LOG_DIR = os.path.join(BASE_DIR, "_logs")
SETTINGS_PATH = os.path.join(BASE_DIR, "_settings.json")

SEV_CN = {"high": "高", "mid": "中", "low": "低", "info": "提示"}
SEV_ORDER = {"high": 0, "mid": 1, "low": 2, "info": 3}
SEV_WEIGHT = {"high": 15, "mid": 8, "low": 3, "info": 0}

CAT_ORDER = ["启动速度", "快速启动", "流氓软件", "开机自启", "延迟启动",
             "服务与残留", "开机报错", "磁盘与其他"]

HKLM = winreg.HKEY_LOCAL_MACHINE
HKCU = winreg.HKEY_CURRENT_USER

_POWR_PATH = r"SYSTEM\CurrentControlSet\Control\Session Manager\Power"
_HIBE_PATH = r"SYSTEM\CurrentControlSet\Control\Power"
_SVC_BASE = r"SYSTEM\CurrentControlSet\Services"
_APPROVED_BASE = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved"

# 修复类型说明（GUI / 报告共用）
FIX_DESC = {
    "fast_startup": "开启快速启动（powercfg /h on + 注册表开关）",
    "svc_start": "调整服务启动类型（自动 -> 手动/禁用）",
    "rm_svc": "删除失效的服务注册表残留",
    "startup_off": "禁止开机自启（任务管理器同款标记，条目保留、随时可恢复）",
    "startup_delete": "彻底删除自启项（删注册表值 / 启动文件夹快捷方式，原值或文件已备份）",
    "task_off": "禁用开机/登录触发的计划任务",
    "svc_delay": "服务改为『自动（延迟启动）』（仍会启动，只错开开机高峰）",
    "startup_delay": "改为延迟启动（创建登录后延迟的计划任务，并关闭原自启标记）",
    "delay_task_set": "修改已创建的延迟任务：按当前『延迟时长』重新登记（覆盖原任务）",
    "delay_task_block": "禁止该延迟任务（Disable-ScheduledTask，任务保留、随时可恢复）",
    "delay_task_del": "删除该延迟任务（Unregister-ScheduledTask，删后不再自启；任务 XML 已备份）",
    "delay_task_restore": "改回立即启动（删掉延迟任务，并把原自启项恢复成登录即刻启动）",
}

# 处理方式（同一对象的几种取舍）。顺序即界面显示顺序。
OP_LABELS = {"delay": "延迟启动", "now": "改回立即启动",
             "block": "禁止启动", "delete": "彻底删除"}
OP_ORDER = ("delay", "now", "block", "delete")


def apply_op(f, op=None):
    """把 finding 的处理方式切到 op（delay / block / delete），就地改写 fix / title / short / detail。

    每个可选项都带完整文案（不是拼接），所以切回来不会串味。
    没有 opts 的 finding（如快速启动、服务残留）原样返回。
    """
    opts = f.get("opts")
    if not opts:
        return f
    if op not in opts:
        op = f.get("op") if f.get("op") in opts else OP_ORDER[0]
    if op not in opts:
        op = next(iter(opts))
    o = opts[op]
    f["op"] = op
    f["fix"] = o["fix"]
    f["title"] = o.get("title", f.get("title", ""))
    f["short"] = o.get("short", "")
    if "impact" in o:
        f["impact"] = o["impact"]
    if o.get("detail"):
        f["detail"] = o["detail"]
    return f


# --------------------------------------------------------------------------
# 基础工具
# --------------------------------------------------------------------------

def ensure_dirs():
    for d in (BACKUP_DIR, LOG_DIR):
        try:
            os.makedirs(d, exist_ok=True)
        except OSError:
            pass


def log_line(msg):
    try:
        ensure_dirs()
        fn = os.path.join(LOG_DIR, _dt.datetime.now().strftime("%Y%m%d") + ".log")
        with open(fn, "a", encoding="utf-8") as f:
            f.write("[%s] %s\n" % (_dt.datetime.now().strftime("%H:%M:%S"), msg))
    except Exception:
        pass


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


_k32 = ctypes.windll.kernel32
try:
    _k32.GetFileAttributesW.restype = ctypes.c_uint32
except Exception:
    pass


def path_exists_raw(path):
    """文件存在性检查：优先 GetFileAttributes；
    对权限受限的受保护文件（如 hiberfil.sys，attr 会返回访问拒绝）回退目录枚举。"""
    if not path:
        return False
    path = str(path)
    try:
        if _k32.GetFileAttributesW(path) != 0xFFFFFFFF:
            return True
    except Exception:
        pass
    try:
        parent = os.path.dirname(path)
        name = os.path.basename(path)
        if not parent or not name:
            return False
        return name.lower() in (x.lower() for x in os.listdir(parent))
    except OSError:
        return False


def _no_window():
    return getattr(subprocess, "CREATE_NO_WINDOW", 0)


def run_ps(script, timeout=120, env=None):
    """执行 PowerShell（script 必须为纯 ASCII；动态值经 env 传递），返回 stdout 文本。"""
    prefix = ("[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"
              "$ProgressPreference='SilentlyContinue';"
              "$ErrorActionPreference='SilentlyContinue';")
    try:
        p = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-Command", prefix + script],
            capture_output=True, timeout=timeout, creationflags=_no_window(), env=env)
        out = p.stdout or b""
        try:
            return out.decode("utf-8")
        except UnicodeDecodeError:
            return out.decode("gbk", errors="replace")
    except Exception as e:
        log_line("run_ps error: %r" % (e,))
        return ""


def _run(args, timeout=60):
    try:
        p = subprocess.run(args, capture_output=True, timeout=timeout,
                           creationflags=_no_window())
        return p.returncode, p.stdout or b"", p.stderr or b""
    except Exception as e:
        return -1, b"", str(e).encode("utf-8", "replace")


def _parse_json(text):
    """解析 run_ps 输出。支持顶层对象 {...} 与顶层数组 [...]（后者返回 list）。"""
    if not text:
        return {}
    t = text.strip()
    if t.startswith("["):
        j = t.rfind("]")
        if j > 0:
            try:
                return json.loads(t[:j + 1])
            except Exception as e:
                log_line("json parse error (array): %r  head=%s" % (e, text[:200]))
                return {}
    i, j = t.find("{"), t.rfind("}")
    if i < 0 or j <= i:
        return {}
    try:
        return json.loads(t[i:j + 1])
    except Exception as e:
        log_line("json parse error: %r  head=%s" % (e, text[:200]))
        return {}


def _reg_dword(root, sub, name):
    try:
        with winreg.OpenKey(root, sub, 0, winreg.KEY_READ) as k:
            return int(winreg.QueryValueEx(k, name)[0])
    except OSError:
        return None


def _set_dword(root, sub, name, value):
    with winreg.OpenKey(root, sub, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, name, 0, winreg.REG_DWORD, int(value))


# --------------------------------------------------------------------------
# 采集 1：启动项（Run 键 + 启动文件夹 + StartupApproved 状态）
# --------------------------------------------------------------------------

_RUN_KEYS = [
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run", "用户 Run"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "用户 RunOnce"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run", "系统 Run"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "系统 RunOnce"),
    ("HKLM", r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run", "系统 Run (32位)"),
]


def _root_of(hive):
    return HKCU if hive == "HKCU" else HKLM


def read_approved(hive, group):
    """读取 StartupApproved\\<group> 的二进制标记。group: Run / StartupFolder"""
    sub = _APPROVED_BASE + "\\" + group
    out = {}
    try:
        with winreg.OpenKey(_root_of(hive), sub, 0, winreg.KEY_READ) as k:
            i = 0
            while True:
                try:
                    name, data, _typ = winreg.EnumValue(k, i)
                except OSError:
                    break
                if isinstance(data, bytes) and data:
                    out[name] = data
                i += 1
    except OSError:
        pass
    return out


def _approved_enabled(ap_map, name):
    b = ap_map.get(name)
    if not b:
        return True
    return (b[0] % 2) == 0  # 03=禁用(奇) / 02=启用(偶)


def enum_startup_items():
    items = []
    ap_run_u = read_approved("HKCU", "Run")
    ap_run_m = read_approved("HKLM", "Run")
    ap_sf_u = read_approved("HKCU", "StartupFolder")
    ap_sf_m = read_approved("HKLM", "StartupFolder")
    for hive, sub, label in _RUN_KEYS:
        try:
            with winreg.OpenKey(_root_of(hive), sub, 0, winreg.KEY_READ) as k:
                i = 0
                while True:
                    try:
                        name, val, _typ = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    ap = ap_run_u if hive == "HKCU" else ap_run_m
                    items.append({
                        "name": str(name), "cmd": str(val), "source": label,
                        "kind": "run", "hive": hive, "subkey": sub,
                        "enabled": _approved_enabled(ap, str(name)),
                    })
                    i += 1
        except OSError:
            pass
    folders = [
        (os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"),
         "用户启动文件夹", "HKCU", ap_sf_u),
        (os.path.join(os.environ.get("ProgramData", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"),
         "公共启动文件夹", "HKLM", ap_sf_m),
    ]
    for folder, label, hive, ap in folders:
        try:
            for fn in os.listdir(folder):
                if fn.lower().endswith("desktop.ini"):
                    continue
                items.append({
                    "name": fn, "cmd": os.path.join(folder, fn), "source": label,
                    "kind": "folder", "hive": hive, "subkey": None,
                    "enabled": _approved_enabled(ap, fn),
                })
        except OSError:
            pass
    return items


# --------------------------------------------------------------------------
# 采集 1b：隐蔽启动点（对标 Autoruns 的 Logon 之外的分类）
#
# 这些位置普通启动项管理器都不看，但恶意软件和历史残留最爱藏在这里：
#   IFEO        映像劫持：把 taskmgr.exe 之类重定向到别的程序
#   Winlogon    登录通知 DLL，比杀软加载还早
#   AppInit     注入到所有加载 user32.dll 的进程
#   BootExecute 开机最早期执行的命令
#   Winsock     LSP 网络栈钩子
#   LSA         认证包钩子
#   Print      打印机监视器 DLL
#   ShellExt   资源管理器扩展（右键菜单 / 图标覆盖）
#
# 只读枚举，不在这里做任何修改；处理方式由 analyze 层决定。
# --------------------------------------------------------------------------

_WINLOGON = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
_IFEO = r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
_APPINIT = (r"Software\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs")
_WOW_APPINIT = (r"Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows",
                "AppInit_DLLs")


def _reg_values(root, sub):
    """读一个键下所有值，返回 [(name, value, type)]；读不到就返回空。"""
    out = []
    try:
        with winreg.OpenKey(root, sub, 0, winreg.KEY_READ) as k:
            i = 0
            while True:
                try:
                    n, v, t = winreg.EnumValue(k, i)
                except OSError:
                    break
                out.append((str(n), v, t))
                i += 1
    except OSError:
        pass
    return out


def _reg_subkeys(root, sub):
    out = []
    try:
        with winreg.OpenKey(root, sub, 0, winreg.KEY_READ) as k:
            i = 0
            while True:
                try:
                    out.append(str(winreg.EnumKey(k, i)))
                except OSError:
                    break
                i += 1
    except OSError:
        pass
    return out


def _reg_str(root, sub, name):
    """读注册表值成字符串。REG_MULTI_SZ 返回 list，拼成换行分隔的文本。"""
    try:
        with winreg.OpenKey(root, sub, 0, winreg.KEY_READ) as k:
            v, _t = winreg.QueryValueEx(k, name)
    except OSError:
        return ""
    if isinstance(v, (list, tuple)):
        return "\n".join(str(x) for x in v if str(x).strip())
    return str(v)


def _reg_seq(root, sub, name):
    """读注册表值成字符串列表（REG_MULTI_SZ 用）。"""
    try:
        with winreg.OpenKey(root, sub, 0, winreg.KEY_READ) as k:
            v, _t = winreg.QueryValueEx(k, name)
    except OSError:
        return []
    if isinstance(v, (list, tuple)):
        return [str(x) for x in v]
    return [str(v)] if str(v).strip() else []


def enum_extra_autostarts():
    """枚举 Run 键之外的启动点，返回与 enum_startup_items 同构的列表。

    额外字段：
      loc     位置说明（给人看的，如「Winlogon 通知」）
      danger  该位置的危险等级：high 表示正常软件几乎不会用，出现即需关注
      fixable 是否支持「禁止启动」（多数隐蔽位置只支持删除，见 analyze）
    """
    items = []

    def push(**kw):
        kw.setdefault("kind", "extra")
        kw.setdefault("hive", "")
        kw.setdefault("subkey", None)
        kw.setdefault("source", kw.get("loc") or "隐蔽启动点")
        kw.setdefault("enabled", True)
        kw.setdefault("fixable", True)
        items.append(kw)

    # ---- 1) IFEO 映像劫持 ----
    # 正常情况只在装了调试器时出现 Debugger 值；其它子键带 Debugger 基本可判定为劫持
    for name in _reg_subkeys(HKLM, _IFEO):
        sub = _IFEO + "\\" + name
        dbg = _reg_str(HKLM, sub, "Debugger")
        if not dbg:
            continue
        push(name="IFEO\\" + name, cmd=dbg, loc="IFEO 映像劫持",
             danger="high", reg_path="HKLM\\" + sub + "\\Debugger")

    # ---- 2) Winlogon 通知 ----
    for val in ("Userinit", "Shell", "AppSetup", "GinaDLL", "VmApplet"):
        v = _reg_str(HKLM, _WINLOGON, val)
        if not v:
            continue
        # Userinit 默认是 userinit.exe,；Shell 默认 explorer.exe
        low = v.lower().replace("/", "\\")
        if val == "Userinit" and low.strip(" ,") in ("c:\\windows\\system32\\userinit.exe",
                                                     "userinit.exe"):
            continue
        if val == "Shell" and low.strip(" ,") == "explorer.exe":
            continue
        if val in ("AppSetup", "GinaDLL", "VmApplet"):
            continue        # 这三项默认空，有值才可疑，下面单独处理
        push(name="Winlogon\\" + val, cmd=v, loc="Winlogon 通知",
             danger="high", reg_path="HKLM\\" + _WINLOGON + "\\" + val)
    for val in ("AppSetup", "GinaDLL"):
        v = _reg_str(HKLM, _WINLOGON, val)
        if v:
            push(name="Winlogon\\" + val, cmd=v, loc="Winlogon 通知",
                 danger="high", reg_path="HKLM\\" + _WINLOGON + "\\" + val)

    # ---- 3) AppInit_DLLs ----
    for root, (sub, val), tag in ((HKLM, _APPINIT, "64 位"), (HKLM, _WOW_APPINIT, "32 位")):
        dlls = _reg_str(root, sub, val)
        if not dlls.strip():
            continue
        enabled = _reg_str(root, sub, "LoadAppInit_DLLs")
        push(name="AppInit_DLLs (%s)" % tag, cmd=dlls, loc="AppInit 注入",
             danger="high", enabled=(enabled not in ("0", "")),
             reg_path="HKLM\\" + sub + "\\" + val)

    # ---- 4) BootExecute ----
    for line in _reg_seq(HKLM, r"SYSTEM\CurrentControlSet\Control\Session Manager",
                         "BootExecute"):
        for part in str(line).split("\x00"):
            part = part.strip()
            if not part:
                continue
            if part.lower().startswith("autocheck autochk"):
                continue
            push(name="BootExecute: " + part[:40], cmd=part, loc="BootExecute",
                 danger="high", reg_path="HKLM\\SYSTEM\\CurrentControlSet\\Control"
                                        "\\Session Manager\\BootExecute")

    # ---- 5) Winsock LSP ----
    lsp_root = r"SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries"
    for sub in _reg_subkeys(HKLM, lsp_root):
        path = lsp_root + "\\" + sub
        dll = _reg_str(HKLM, path, "PackedCatalogItem")
        if not dll:
            continue
        # PackedCatalogItem 是二进制，前面是 WSAPROTOCOL_INFOW，DLL 路径在尾部
        if isinstance(dll, str):
            continue
        push(name="Winsock LSP %s" % sub, cmd="", loc="Winsock 提供者",
             danger="mid", reg_path="HKLM\\" + path)

    # ---- 6) LSA 安全包 ----
    lsa = r"SYSTEM\CurrentControlSet\Control\Lsa"
    lsa_known = {"msv1_0", "kerberos", "schannel", "wdigest", "tspkg", "pku2u",
                 "cloudap", "negoexts", "livessp", "rassfm", "scecli",
                 "rassfm.dll", "scecli.dll", "pku2u.dll", "kerberos.dll"}
    for val in ("Authentication Packages", "Notification Packages", "Security Packages"):
        for dll in _reg_seq(HKLM, lsa, val):
            d = str(dll).strip().strip('"')
            if not d or d.lower() in lsa_known:
                continue
            push(name="LSA %s: %s" % (val.replace(" Packages", ""), d),
                 cmd=d, loc="LSA 安全包", danger="high",
                 reg_path="HKLM\\" + lsa + "\\" + val)

    # ---- 7) 打印机监视器 ----
    pm = r"SYSTEM\CurrentControlSet\Control\Print\Monitors"
    for name in _reg_subkeys(HKLM, pm):
        drv = _reg_str(HKLM, pm + "\\" + name, "Driver")
        if not drv:
            continue
        low = drv.lower()
        if low in ("localspl.dll", "luafmon.dll", "usbmon.dll", "wsdmon.dll",
                   "microsoft shared fax monitor", "appmon.dll", "portprompt.dll",
                   "tcpmon.dll", "apmon.dll", "fxSmon.dll".lower(), "inpout32.dll",
                   "zportmon.dll", "porthos.dll"):
            continue
        # 只报"非系统目录"的驱动，系统自带的端口监视器一律放过
        if not drv.lower().startswith(("c:////windows////system32", "%systemroot%")):
            push(name="打印监视器 " + name, cmd=drv, loc="打印机监视器",
                 danger="mid", reg_path="HKLM\\" + pm + "\\" + name + "\\Driver")
            continue

    return items


# --------------------------------------------------------------------------
# 采集 1c：启动项快照（用于「装完软件多了什么」对比）
# --------------------------------------------------------------------------

SNAPSHOT_DIR = os.path.join(BASE_DIR, "_snapshots")


def snapshot_path(ts=None):
    ensure_dirs()
    try:
        os.makedirs(SNAPSHOT_DIR, exist_ok=True)
    except OSError:
        pass
    ts = ts or _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    return os.path.join(SNAPSHOT_DIR, "snap-%s.json" % ts)


def save_snapshot(raw):
    """把本次采集的启动面存成快照，返回文件路径（失败返回空串）。"""
    try:
        ensure_dirs()
        try:
            os.makedirs(SNAPSHOT_DIR, exist_ok=True)
        except OSError:
            pass
        startup = []
        for it in (raw.get("startup") or []) + (raw.get("extra") or []):
            startup.append({
                "name": it.get("name", ""),
                "cmd": it.get("cmd", ""),
                "source": it.get("source", ""),
                "enabled": bool(it.get("enabled", True)),
            })
        svcs = []
        for s in raw.get("services") or []:
            if s.get("start", "").lower() != "auto":
                continue
            svcs.append({"name": s.get("name", ""), "path": s.get("path", ""),
                         "state": s.get("state", "")})
        data = {
            "ts": raw.get("ts") or _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "startup": startup,
            "services": svcs,
        }
        p = snapshot_path()
        with open(p, "w", encoding="utf-8") as fp:
            json.dump(data, fp, ensure_ascii=False, indent=1)
        _prune_snapshots(keep=30)
        return p
    except Exception as e:
        log_line("snapshot save failed: %r" % (e,))
        return ""


def _prune_snapshots(keep=30):
    try:
        fs = sorted(f for f in os.listdir(SNAPSHOT_DIR) if f.endswith(".json"))
        for f in fs[:-keep]:
            try:
                os.remove(os.path.join(SNAPSHOT_DIR, f))
            except OSError:
                pass
    except OSError:
        pass


def list_snapshots():
    """返回 [(路径, 时间字符串)]，按时间从新到旧。"""
    out = []
    try:
        for f in os.listdir(SNAPSHOT_DIR):
            if not f.endswith(".json"):
                continue
            p = os.path.join(SNAPSHOT_DIR, f)
            try:
                with open(p, "r", encoding="utf-8") as fp:
                    d = json.load(fp)
                out.append((p, d.get("ts") or f[5:-5]))
            except Exception:
                continue
    except OSError:
        pass
    out.sort(key=lambda x: x[1], reverse=True)
    return out


def load_snapshot(path):
    try:
        with open(path, "r", encoding="utf-8") as fp:
            d = json.load(fp)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def diff_snapshot(old, new):
    """对比两份快照，返回新增 / 消失的启动项与服务。

    判断依据是 (name, cmd) 组合的规范化字符串，避免只改顺序就被当成变更。
    """
    def key(it):
        return (str(it.get("name", "")).strip().lower(),
                str(it.get("cmd", "")).strip().lower())

    def index(d, field):
        m = {}
        for it in d.get(field) or []:
            m[key(it)] = it
        return m

    a_start, b_start = index(old, "startup"), index(new, "startup")
    a_svc, b_svc = index(old, "services"), index(new, "services")

    added_start = [b_start[k] for k in b_start if k not in a_start]
    gone_start = [a_start[k] for k in a_start if k not in b_start]
    added_svc = [b_svc[k] for k in b_svc if k not in a_svc]
    gone_svc = [a_svc[k] for k in a_svc if k not in b_svc]

    return {
        "old_ts": old.get("ts", ""),
        "new_ts": new.get("ts", ""),
        "added_startup": sorted(added_start, key=lambda x: x.get("name", "")),
        "gone_startup": sorted(gone_start, key=lambda x: x.get("name", "")),
        "added_services": sorted(added_svc, key=lambda x: x.get("name", "")),
        "gone_services": sorted(gone_svc, key=lambda x: x.get("name", "")),
    }


# --------------------------------------------------------------------------
# 流氓软件 / 全家桶扫描
#
# 思路（对标 SoftCnKiller，但只读不删）：
#   1. 目录名命中   —— 安装路径里出现黑名单目录（\360bizhi\、\LuDaShi\ 等）
#   2. 签名主体命中 —— 文件公司名在黑名单里（中小厂商捆绑软件的主要特征）
#   3. 厂商家族规则 —— 360 / 2345 / 鲁大师这类有正规签名的，按产品名与路径正则匹配
#
# 只做「识别 + 报告 + 给处理建议」，不自动卸载任何东西。
# 卸载交给系统自身的 uninstall 注册表项，这里只把卸载命令找出来。
# --------------------------------------------------------------------------

ADWARE_DB_PATH = os.path.join(BASE_DIR, "adware_db.json")
_ADB = {}


def adware_db():
    """懒加载特征库。文件缺失时返回空库，不影响其它功能。"""
    if _ADB:
        return _ADB
    d = {"dirs": {}, "pubs": [], "families": [], "version": 0, "updated": ""}
    try:
        with open(ADWARE_DB_PATH, "r", encoding="utf-8") as fp:
            raw = json.load(fp)
        if isinstance(raw, dict):
            d.update(raw)
    except Exception as e:
        log_line("adware db load failed: %r" % (e,))
    # 预编译家族正则，避免每次扫描重复编译
    fams = []
    for f in d.get("families") or []:
        try:
            fams.append({
                "id": f.get("id") or "",
                "name": f.get("name") or "",
                "vendor": f.get("vendor") or "",
                "sev": f.get("sev") or "mid",
                "note": f.get("note") or "",
                "res": [re.compile(p, re.I) for p in (f.get("pats") or [])],
            })
        except re.error as e:
            log_line("bad adware pattern in %s: %r" % (f.get("id"), e))
    d["_fam"] = fams
    # 目录名黑名单要过滤掉两类必然误报的条目：
    #   1) 通用词（downloads / update / temp / data …）——任何软件都可能用
    #   2) 长度 <= 3 的（kz / lds / tx …）——太短，会命中无关路径
    # 这两类在黑名单里本来是用来配合"完整路径"判断的，我们只按目录名匹配，
    # 直接用会满屏误报，所以这里排除。真正的流氓目录名（LuDaShi、360bizhi）都是长且有辨识度的。
    _COMMON = {"downloads", "download", "update", "updates", "temp", "tmp",
               "data", "cache", "bin", "lib", "app", "apps", "soft", "software",
               "tools", "tool", "setup", "install", "installer", "program",
               "programs", "programdata", "appdata", "local", "roaming",
               "common", "shared", "public", "default", "user", "users",
               "windows", "system32", "syswow64", "service", "services",
               "client", "server", "main", "core", "config", "log", "logs",
               "backup", "driver", "drivers", "plugin", "plugins", "skin"}
    # 上游 folder.txt 部分条目是「多级相对路径」（Local\finder、Program Files (x86)\Calendar），
    # 只比目录名会漏，也不能把 local 这种前缀词当通用词砍掉——整个键一起看才有辨识度。
    # 但有几个多级键本身是 Windows 的公共容器目录（公共文档 / 图片 / 音乐…），
    # 任何绿色软件放在那里都会被它们命中，误报成本太高，直接排除。
    _DEEP_COMMON = {
        "users\\public\\documents", "users\\public\\pictures", "users\\public\\music",
        "users\\public\\videos", "users\\public\\accountpictures",
        "users\\public\\downloads",
        # 这几个虽然上游是按 AppData 下真实流氓目录收录的，但 data / config / update
        # 太通用了，正规软件也常用；没有签名上下文时判不准，宁可不报。
        "roaming\\data", "roaming\\config", "roaming\\update",
    }
    raw_dirs = {str(k).lower(): v for k, v in (d.get("dirs") or {}).items()}
    simple, deep = {}, {}
    for k, v in raw_dirs.items():
        if "\\" in k:
            if len(k) >= 6 and k not in _DEEP_COMMON:
                deep[k] = v
        elif k not in _COMMON and len(k) >= 4:
            simple[k] = v
    d["_dir_lower"] = simple
    d["_dir_deep"] = deep
    d["_pub_lower"] = [str(p).lower() for p in (d.get("pubs") or []) if str(p).strip()]
    # 上游 whitepath.txt：明确已知的误报（系统 / 常用软件），命中就放过
    d["_white"] = {str(w).strip("\\").strip().lower()
                   for w in (d.get("white") or []) if str(w).strip()}
    _ADB.update(d)
    return _ADB


def adware_db_stats():
    """特征库概况（给界面 / 报告显示，避免到处写死 1126、398 这种数字）。"""
    db = adware_db()
    st = db.get("stats") or {}
    return {
        "version": int(db.get("version") or 0),
        "updated": db.get("updated") or "未知",
        "dirs": len(db.get("dirs") or {}),
        "pubs": len(db.get("pubs") or []),
        "families": len(db.get("families") or []),
        "white": len(db.get("white") or []),
        "sources": db.get("sources") or [],
        "added": st.get("added_dirs", 0) + st.get("added_pubs", 0),
    }


# 上游地址：Gitee 是作者官方数据源，GitHub 两个镜像是同步副本，按顺序尝试。
# 只读公开文本，不依赖任何 API token；失败就换下一条，全都失败则不动本地库。
ADWARE_DB_SOURCES = (
    "https://gitee.com/softcnkiller/data/raw/master/",
    "https://raw.githubusercontent.com/mirrormode/mirror-softcnkiller/master/",
    "https://raw.githubusercontent.com/qundao/mirror-softcnkiller/master/",
)
_ADB_FILES = ("folder.txt", "sign.txt", "whitepath.txt")


def _db_http_get(url, timeout=15):
    """取一个上游文本文件。返回 bytes；失败抛异常，不吞。"""
    req = urllib.request.Request(url, headers={
        "User-Agent": "boot-doctor/%s (+https://localhost)" % VERSION,
        "Cache-Control": "no-cache",
    })
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def _db_text(raw):
    """上游文件编码不统一：folder.txt / sign.txt 是 UTF-16 LE 带 BOM，历史上也出现过 UTF-8、
    GBK。先看 BOM 再按 UTF-8 → GB18030 试，最后才盲猜 UTF-16。

    注意顺序不能反：UTF-8 的中文被当成 UTF-16 解不会抛异常，只会解出一串私用区乱码，
    然后整份黑名单就废了——所以「有没有 BOM」才是判据，不能靠 try/except。
    """
    if not raw:
        return ""
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            return raw.decode("utf-16")
        except Exception:
            pass
    for enc in ("utf-8-sig", "gb18030"):
        try:
            t = raw.decode(enc)
        except Exception:
            continue
        if "\x00" in t:          # 解错编码时到处是 NUL
            continue
        bad = t.count("\ufffd")
        if bad and bad > len(t) * 0.001:
            continue
        return t
    return raw.decode("utf-16", "ignore").replace("\x00", "")


def _cjk(s):
    return bool(re.search(r"[\u4e00-\u9fff]", s or ""))


def parse_adware_txt(folder_raw, sign_raw, white_raw=b""):
    """解析上游 trio，返回 {"dirs": {键: 显示名}, "pubs": [...], "white": [...]}。

    folder.txt 每行 `\\目录名\\` 或 `\\Local\\finder\\`（多级路径）。
    键统一小写、反斜杠分隔；显示名默认取最后一段（有中文名时由 merge 补上）。
    """
    dirs = {}
    for line in _db_text(folder_raw).splitlines():
        s = line.strip().strip("\\").strip()
        if not s:
            continue
        segs = [x.strip() for x in s.replace("/", "\\").split("\\") if x.strip()]
        if not segs:
            continue
        key = "\\".join(x.lower() for x in segs)
        if key and key not in dirs:
            dirs[key] = segs[-1]
    pubs, seen = [], set()
    for line in _db_text(sign_raw).splitlines():
        s = line.strip()
        if len(s) < 4:
            continue
        k = s.lower()
        if k in seen:
            continue
        seen.add(k)
        pubs.append(s)
    white, wseen = [], set()
    for line in _db_text(white_raw).splitlines():
        s = line.strip().strip("\\").strip()
        if not s:
            continue
        k = s.lower()
        if k in wseen:
            continue
        wseen.add(k)
        white.append(s)
    return {"dirs": dirs, "pubs": pubs, "white": white}


def _db_file_path(path=None):
    return path or ADWARE_DB_PATH


def _read_db_file(path):
    try:
        with open(path, "r", encoding="utf-8") as fp:
            d = json.load(fp)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def merge_adware_db(old, parsed):
    """把上游解析结果合并进旧库。

    规则：
      - 目录 / 签名以**上游为准**（上游会删掉被证实误报的条目，本地留着只会多误判）
      - 但保留本地手工补充的条目（old["manual"] 里登记的），以及所有中文显示名
      - 厂商家族规则（本项目自写）原样保留
      - 上游把 `finder` 改写成 `Local\\finder` 时，按最后一段继承旧中文名，不然名字全丢
    """
    old_dirs = {str(k).lower(): v for k, v in (old.get("dirs") or {}).items()}
    old_pubs = [str(p) for p in (old.get("pubs") or []) if str(p).strip()]
    new_dirs = {}
    for key, leaf in (parsed.get("dirs") or {}).items():
        name = old_dirs.get(key) or ""
        if not _cjk(name):
            # 多级键去找同名叶子目录的旧中文名
            fallback = old_dirs.get(key.split("\\")[-1]) or ""
            if _cjk(fallback):
                name = fallback
        new_dirs[key] = name or leaf

    manual = {str(k).lower(): v for k, v in (old.get("manual") or {}).items()}
    for k, v in manual.items():
        new_dirs.setdefault(k, v)

    pubs, seen = [], set()
    for p in (parsed.get("pubs") or []) + [p for p in old_pubs if str(p).lower() in
                                           {x.lower() for x in (old.get("manual_pubs") or [])}]:
        k = p.lower()
        if k in seen:
            continue
        seen.add(k)
        pubs.append(p)

    added_dirs = sorted(set(new_dirs) - set(old_dirs))
    removed_dirs = sorted(set(old_dirs) - set(new_dirs))
    old_set = {p.lower() for p in old_pubs}
    new_set = {p.lower() for p in pubs}
    added_pubs = sorted(new_set - old_set)
    removed_pubs = sorted(old_set - new_set)

    # 上游经常把 `finder` 改写成 `Local\finder`：条目没少，只是加了路径前缀。
    # 这类要单独算成「改为带路径」，否则更新报告里「新增 75 / 移除 63」会误导用户。
    added_leaves = {k.split("\\")[-1] for k in added_dirs}
    moved_old = [k for k in removed_dirs if k in added_leaves]      # 旧键（短名）
    moved_leaves = set(moved_old)
    really_removed = [k for k in removed_dirs if k not in moved_leaves]
    moved_new = [k for k in added_dirs if k.split("\\")[-1] in moved_leaves]  # 新键（带路径）
    new_added = [k for k in added_dirs if k.split("\\")[-1] not in moved_leaves]

    db = dict(old)
    db["dirs"] = new_dirs
    db["pubs"] = pubs
    db["white"] = parsed.get("white") or old.get("white") or []
    db["families"] = old.get("families") or []
    db["version"] = int(old.get("version") or 0) + 1
    db["updated"] = _dt.date.today().isoformat()
    db["note"] = old.get("note") or ""
    db["stats"] = {
        "dirs": len(new_dirs), "pubs": len(pubs),
        "added_dirs": len(new_added), "removed_dirs": len(really_removed),
        "moved_dirs": len(moved_new),
        "added_pubs": len(added_pubs), "removed_pubs": len(removed_pubs),
    }
    return db, {
        "added_dirs": new_added, "removed_dirs": really_removed,
        "moved_dirs": moved_new,
        "added_pubs": added_pubs, "removed_pubs": removed_pubs,
    }


def _atomic_write_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fp:
        json.dump(obj, fp, ensure_ascii=False, indent=1)
        fp.flush()
        try:
            os.fsync(fp.fileno())
        except Exception:
            pass
    os.replace(tmp, path)


def update_adware_db(dry_run=False, sources=None, path=None, timeout=15,
                     progress=None):
    """在线更新流氓软件特征库。

    只读公开黑名单文本，不下载可执行文件；写入前自动备份旧库。
    返回 dict：
      ok / dry_run / source / dirs / pubs / added_* / removed_* / backup / error
    """
    db_path = _db_file_path(path)
    srcs = tuple(sources or ADWARE_DB_SOURCES)
    rep = {"ok": False, "dry_run": bool(dry_run), "source": "", "error": "",
           "up_to_date": False,
           "dirs": 0, "pubs": 0, "white": 0, "version": 0, "updated": "",
           "added_dirs": 0, "removed_dirs": 0, "moved_dirs": 0, "added_pubs": 0,
           "removed_pubs": 0, "backup": "", "samples_added": [],
           "samples_removed": [], "tried": []}

    def say(t):
        if progress:
            try:
                progress(t)
            except Exception:
                pass

    parsed, used = None, ""
    errs = []
    for base in srcs:
        # 支持本地目录（离线更新 / 内网共享 / 测试）：传一个含 folder.txt 的目录即可
        local = os.path.isdir(base)
        if not local:
            base = base if base.endswith("/") else base + "/"
        rep["tried"].append(base)

        def grab(name):
            if local:
                with open(os.path.join(base, name), "rb") as fp:
                    return fp.read()
            return _db_http_get(base + name, timeout)

        try:
            say("读取特征库源 %s" % (base if local else base.split("/")[2]))
            folder_raw = grab("folder.txt")
            sign_raw = grab("sign.txt")
            try:
                white_raw = grab("whitepath.txt")
            except Exception:
                white_raw = b""          # 白名单是可选文件，缺了不影响
            cand = parse_adware_txt(folder_raw, sign_raw, white_raw)
            # 防空/防半截：目录不到 200 条基本可以断定拿到的是错误页
            if len(cand["dirs"]) < 200 or len(cand["pubs"]) < 50:
                raise ValueError("内容不完整（%d 目录 / %d 签名）"
                                 % (len(cand["dirs"]), len(cand["pubs"])))
            parsed, used = cand, base
            break
        except Exception as e:
            errs.append("%s -> %s" % (base, e))
            continue

    if not parsed:
        rep["error"] = "所有特征库源都不可用：\n" + "\n".join(errs or ["(无)"])
        log_line("adware db update failed: %s" % (errs,))
        return rep

    old = _read_db_file(db_path)
    db, diff = merge_adware_db(old, parsed)
    db["sources"] = [used]
    rep.update({
        "ok": True, "source": used, "dirs": len(db["dirs"]),
        "pubs": len(db["pubs"]), "white": len(db.get("white") or []),
        "version": db["version"], "updated": db["updated"],
        "added_dirs": len(diff["added_dirs"]),
        "removed_dirs": len(diff["removed_dirs"]),
        "moved_dirs": len(diff.get("moved_dirs") or []),
        "added_pubs": len(diff["added_pubs"]),
        "removed_pubs": len(diff["removed_pubs"]),
        "samples_added": diff["added_dirs"][:20],
        "samples_removed": diff["removed_dirs"][:10],
    })

    # 内容完全没变就别写文件：避免每次点更新都把版本号 +1、白留一堆备份
    changed = any(diff[k] for k in ("added_dirs", "removed_dirs",
                                    "moved_dirs", "added_pubs", "removed_pubs"))
    if not changed:
        old_white = {str(x).lower() for x in (old.get("white") or [])}
        new_white = {str(x).lower() for x in (db.get("white") or [])}
        changed = old_white != new_white
    if not changed and old:
        rep.update({
            "ok": True, "up_to_date": True, "source": used,
            "dirs": len(db["dirs"]), "pubs": len(db["pubs"]),
            "white": len(db.get("white") or []),
            "version": int(old.get("version") or 0),
            "updated": old.get("updated") or "",
        })
        log_line("adware db already up to date (src=%s)" % used)
        return rep

    if dry_run:
        return rep

    # 备份旧库（同目录一份 + 备份目录一份，后者跟其它备份一起被用户看到）
    try:
        if os.path.exists(db_path):
            ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
            os.makedirs(BACKUP_DIR, exist_ok=True)
            bak = os.path.join(BACKUP_DIR, "adware_db-%s.json" % ts)
            shutil.copy2(db_path, bak)
            rep["backup"] = bak
    except Exception as e:
        log_line("adware db backup failed: %r" % (e,))

    _atomic_write_json(db_path, db)
    # 清缓存，让当前进程立刻用上新库（否则 adware_db() 还是旧的）
    _ADB.clear()
    log_line("adware db updated: v%s %s dirs=%d(+%d/-%d) pubs=%d(+%d/-%d) src=%s"
             % (db["version"], db["updated"], rep["dirs"], rep["added_dirs"],
                rep["removed_dirs"], rep["pubs"], rep["added_pubs"],
                rep["removed_pubs"], used))
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        with open(os.path.join(LOG_DIR, "adware_db.log"), "a", encoding="utf-8") as fp:
            fp.write("[%s] v%s %s\n  源: %s\n  目录 %d（新增 %d / 移除 %d / 改为带路径 %d）\n"
                     "  签名 %d（新增 %d / 移除 %d）\n"
                     % (_dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        db["version"], db["updated"], used,
                        rep["dirs"], rep["added_dirs"], rep["removed_dirs"],
                        rep["moved_dirs"],
                        rep["pubs"], rep["added_pubs"], rep["removed_pubs"]))
            if diff["added_dirs"]:
                fp.write("  新增目录: %s\n" % ", ".join(diff["added_dirs"][:60]))
            if diff["removed_dirs"]:
                fp.write("  移除目录: %s\n" % ", ".join(diff["removed_dirs"][:60]))
    except Exception:
        pass
    return rep


def _path_dirs(path):
    """把路径拆成各级目录名（小写），用于和目录黑名单比对。"""
    p = (path or "").replace("/", "\\")
    parts = [x for x in p.split("\\") if x]
    # 去掉盘符和文件名
    out = []
    for i, seg in enumerate(parts):
        if i == 0 and len(seg) == 2 and seg[1] == ":":
            continue
        if i == len(parts) - 1 and "." in seg:
            continue        # 文件名不算目录
        out.append(seg.lower())
    return out


def _path_windows(path, depth=4):
    """把路径炸成所有「连续 1~4 段」组合（小写反斜杠），用于和黑名单键比对。

    上游 folder.txt 里既有 `finder` 这种单词键，也有 `Local\\finder`、
    `Program Files (x86)\\Calendar` 这种多级键，必须按连续段整体匹配，
    否则前者会把 `C:\\Tools\\finder`（正常软件）也误判。
    """
    segs = [x.lower().strip('"') for x in (path or "").replace("/", "\\").split("\\") if x]
    out = []
    n = len(segs)
    for i in range(n):
        if i == 0 and len(segs[i]) == 2 and segs[i][1] == ":":
            continue
        hi = min(n, i + depth)
        for j in range(i + 1, hi + 1):
            out.append("\\".join(segs[i:j]))
    return out


def _match_family(text_path, text_name, text_pub):
    """按厂商家族规则匹配，返回命中的家族 dict（不含正则对象）或 None。"""
    db = adware_db()
    for f in db.get("_fam") or []:
        for r in f["res"]:
            if (r.search(text_path) or r.search(text_name) or r.search(text_pub)):
                return f
    return None


def adware_check(path="", name="", company="", cmd=""):
    """判定单个对象是否属于流氓软件 / 全家桶。

    返回 dict：
      hit     是否命中
      kind    dir / pub / family
      family  家族 id（如 "360"），非家族命中为空
      label   人话标签，如「360 全家桶」
      sev     high / mid / low
      why     命中理由（给用户看的证据）
    """
    db = adware_db()
    p = (path or "").lower()
    n = (name or "").lower()
    c = (company or "").lower()
    cmdl = (cmd or "").lower()
    blob_path = p + " " + cmdl

    # 微软自家组件直接放过，避免把系统组件误判
    win = os.environ.get("SystemRoot", r"C:\Windows").lower()
    if "microsoft" in c or "windows" == c:
        return {"hit": False}
    if p.startswith(win + "\\") and not c:
        return {"hit": False}

    # 0) 上游白名单：明确登记过的误报（redis-server.exe / mysqld.exe …），先放过
    if db.get("_white"):
        cands = set()
        base = p.replace("/", "\\").rstrip("\\").rsplit("\\", 1)[-1].strip('"')
        if base:
            cands.add(base)
        for tok in re.split(r'[\s"]+', cmdl):
            tok = tok.strip()
            if tok and "." in tok:
                cands.add(tok.replace("/", "\\").rstrip("\\").rsplit("\\", 1)[-1])
        if cands & db["_white"]:
            return {"hit": False}

    # 1) 厂商家族（优先级最高，标签最有用）
    fam = _match_family(blob_path, n, c)
    if fam:
        return {
            "hit": True, "kind": "family", "family": fam["id"],
            "label": fam["name"], "sev": fam["sev"],
            "why": fam["note"] or ("路径 / 名称命中「%s」特征" % fam["name"]),
        }

    # 2) 目录黑名单：先比多级键（更精确），再比单词键
    wins = _path_windows(blob_path)
    deep = db.get("_dir_deep") or {}
    if deep:
        for w in wins:
            if "\\" in w and w in deep:
                label = deep[w] or w.split("\\")[-1]
                return {
                    "hit": True, "kind": "dir", "family": "",
                    "label": label, "sev": "mid",
                    "why": "安装路径「%s」在流氓软件黑名单里（对应软件：%s）" % (w, label),
                }
    for d in _path_dirs(blob_path):
        if d in db["_dir_lower"]:
            label = db["_dir_lower"][d] or d
            return {
                "hit": True, "kind": "dir", "family": "",
                "label": label, "sev": "mid",
                "why": "安装目录「%s」在流氓软件黑名单里（对应软件：%s）" % (d, label),
            }

    # 3) 签名主体黑名单
    #
    # 匹配规则要收紧，否则必出误报：
    #   - 双向子串匹配会让 "UL" 命中 "tuling times..."、"Intel" 命中一堆公司名
    #   - 所以短名（< 6 字符）只允许完全相等，长名才允许互相包含
    #   - 另外把知名大厂硬性排除：它们有正规签名，出现在黑名单里多是重名误伤
    if c and len(c) >= 4:
        for pub in db["_pub_lower"]:
            if not pub:
                continue
            if pub == c:
                ok = True
            elif len(pub) >= 6 and len(c) >= 6:
                ok = (pub in c) or (c in pub)
            else:
                ok = False
            if not ok:
                continue
            if _is_big_vendor(c):
                continue
            return {
                "hit": True, "kind": "pub", "family": "",
                "label": company or pub, "sev": "mid",
                "why": "发布者「%s」在流氓软件签名黑名单里" % (company or pub),
            }
    return {"hit": False}


# 知名大厂白名单：这些公司有正规签名，即使黑名单里出现同名也放过。
# 误判成本很高（把 Intel 驱动标成流氓软件，用户会直接不信这个工具）。
_BIG_VENDORS = (
    "microsoft", "intel", "amd", "nvidia", "qualcomm", "realtek", "broadcom",
    "google", "apple", "adobe", "oracle", "ibm", "dell", "hp ", "lenovo",
    "asus", "acer", "samsung", "sony", "toshiba", "logitech", "razer",
    "corsair", "steelseries", "ul ", "ul llc", "futuremark", "3dmark",
    "vmware", "virtualbox", "jetbrains", "github", "mozilla", "python",
    "canonical", "red hat", "suse", "cisco", "juniper", "fortinet",
    "kaspersky", "eset", "bitdefender", "avast", "avg", "malwarebytes",
    "symantec", "mcafee", "trend micro", "sophos", "f-secure",
)


def _is_big_vendor(company_lower):
    c = (company_lower or "").strip()
    if not c:
        return False
    for v in _BIG_VENDORS:
        if c == v.strip() or c.startswith(v) or v in c:
            return True
    return False


def adware_scan(raw):
    """扫一遍采集结果，返回命中的启动项 / 服务清单。

    只读，不改系统。返回：
      {"items": [...], "families": {family_id: [item...]}, "count": n}
    每个 item 含 name / source / path / label / sev / why / uninstall
    """
    db = adware_db()
    hits = []
    seen = set()

    # 先把启动项里的 .lnk 一次性解析掉：逐条解析每条 250ms，会拖慢整个体检
    try:
        resolve_shortcuts_bulk([(it.get("cmd") or it.get("name") or "")
                                for it in (raw.get("startup") or [])])
    except Exception as e:
        log_line("bulk lnk resolve failed: %r" % (e,))

    def consider(name, source, path, company, cmd, kind):
        key = (name.lower(), (path or cmd or "").lower())
        if key in seen:
            return
        r = adware_check(path=path, name=name, company=company, cmd=cmd)
        if not r.get("hit"):
            return
        seen.add(key)
        hits.append({
            "name": name, "source": source, "path": path or cmd or "",
            "company": company or "", "kind": kind,
            "label": r.get("label", ""), "family": r.get("family", ""),
            "sev": r.get("sev", "mid"), "why": r.get("why", ""),
            "uninstall": "",
        })

    # 启动项
    for it in raw.get("startup") or []:
        info = describe_app(it.get("cmd") or it.get("name") or "")
        consider(it.get("name") or "", it.get("source") or "启动项",
                 info.get("path") or it.get("cmd") or "",
                 info.get("company") or "", it.get("cmd") or "", "startup")

    # 隐蔽启动点
    for it in raw.get("extra") or []:
        consider(it.get("name") or "", it.get("loc") or "隐蔽启动点",
                 it.get("cmd") or "", "", it.get("cmd") or "", "extra")

    # 服务：start 是 Windows 的 StartType 数值
    #   0=boot 1=system 2=auto 3=demand 4=disabled
    # 只看会真正随开机起来的（boot / system / auto），demand 是手动触发，不算开机负担
    for s in raw.get("services") or []:
        try:
            st = int(s.get("start"))
        except (TypeError, ValueError):
            continue
        if st not in (0, 1, 2):
            continue
        img = s.get("image") or s.get("path") or ""
        consider(s.get("name") or s.get("disp") or "", "服务",
                 img, s.get("company") or "", img, "service")

    # 已安装程序：很多全家桶本体不自启，但会常驻托盘 + 互相拉起，
    # 只看启动项会漏掉。这里单独扫一遍卸载表。
    try:
        for disp, pub, uninst, loc in _enum_uninstall():
            probe = loc or uninst or disp
            r = adware_check(path=probe, name=disp, company=pub, cmd=uninst)
            if not r.get("hit"):
                continue
            key = ("installed:" + disp.lower(), (loc or uninst or "").lower())
            if key in seen:
                continue
            seen.add(key)
            hits.append({
                "name": disp, "source": "已安装", "path": loc or uninst or "",
                "company": pub or "", "kind": "installed",
                "label": r.get("label", ""), "family": r.get("family", ""),
                "sev": r.get("sev", "mid"), "why": r.get("why", ""),
                "uninstall": uninst or "",
                "uninstall_name": disp,
            })
    except Exception as e:
        log_line("adware installed scan failed: %r" % (e,))

    # 按家族归组，方便界面按「360 全家桶」聚合显示
    fams = {}
    for h in hits:
        k = h["family"] or ("__" + h["label"])
        fams.setdefault(k, []).append(h)

    # 给每个家族补一个卸载入口（从注册表 Uninstall 里找同名项）
    _attach_uninstall(hits)

    return {"items": hits, "families": fams, "count": len(hits),
            "db_version": db.get("updated", ""),
            "db_dirs": len(db.get("dirs") or {}),
            "db_pubs": len(db.get("pubs") or []),
            "db_fams": len(db.get("families") or [])}


_UNINSTALL_KEYS = [
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
    ("HKLM", r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
]
_UNINSTALL_CACHE = {}


def _enum_uninstall():
    """枚举已安装程序：返回 [(显示名, 发布者, 卸载命令, 安装位置)]。"""
    if _UNINSTALL_CACHE.get("done"):
        return _UNINSTALL_CACHE.get("rows") or []
    rows = []
    for hive, sub in _UNINSTALL_KEYS:
        root = HKCU if hive == "HKCU" else HKLM
        for name in _reg_subkeys(root, sub):
            path = sub + "\\" + name
            disp = _reg_str(root, path, "DisplayName")
            if not disp:
                continue
            rows.append((
                disp,
                _reg_str(root, path, "Publisher"),
                _reg_str(root, path, "UninstallString"),
                _reg_str(root, path, "InstallLocation"),
            ))
    _UNINSTALL_CACHE["done"] = True
    _UNINSTALL_CACHE["rows"] = rows
    return rows


def _attach_uninstall(hits):
    """给命中的项目找对应的卸载命令（按显示名 / 安装位置模糊匹配）。"""
    try:
        rows = _enum_uninstall()
    except Exception:
        return
    if not rows:
        return
    for h in hits:
        hname = (h.get("name") or "").lower()
        hpath = (h.get("path") or "").lower()
        for disp, pub, uninst, loc in rows:
            if not uninst:
                continue
            d = disp.lower()
            ok = False
            if hpath and loc and loc.lower() and loc.lower() in hpath:
                ok = True
            elif hname and (hname in d or d in hname) and len(d) >= 3:
                ok = True
            if ok:
                h["uninstall"] = uninst
                h["uninstall_name"] = disp
                break


def adware_summary(res):
    """把扫描结果压成一句话，给界面摘要用。"""
    if not res or not res.get("count"):
        return ""
    fams = res.get("families") or {}
    names = []
    for k, items in fams.items():
        lbl = items[0].get("label") or k
        if lbl and lbl not in names:
            names.append(lbl)
    names = names[:4]
    more = "" if len(fams) <= 4 else " 等 %d 类" % len(fams)
    return "发现 %d 项疑似流氓软件 / 全家桶（%s%s）" % (
        res["count"], "、".join(names), more)


# --------------------------------------------------------------------------
# 弹窗定位 / 拦截
#
# 定位：EnumWindows 把桌面所有顶层窗口摊开，标出它属于哪个进程、发布者是谁、
#       是否命中流氓软件特征库。用户"右下角老弹广告"，这里能直接指认是谁弹的。
# 拦截：本程序不常驻（体检工具常开不合理），另起 popup_guard.py 托盘守护，
#       只对「命中特征库 / 用户点名」的窗口发 WM_CLOSE，系统窗口和正常软件永不碰。
# --------------------------------------------------------------------------

_W = ctypes.windll.user32
_K = ctypes.windll.kernel32
POPUP_RULES_PATH = os.path.join(BASE_DIR, "_popup_rules.json")
GUARD_PID_PATH = os.path.join(LOG_DIR, "popup_guard.pid")
GUARD_STOP_PATH = os.path.join(LOG_DIR, "popup_guard.stop")
GUARD_SCRIPT = os.path.join(BASE_DIR, "popup_guard.py")

# 这些窗口类属于系统外壳 / 输入法，关掉会破坏使用体验，任何规则下都不动
_POPUP_SAFE_CLASSES = {
    "shell_traywnd", "shell_secondarytraywnd", "progman", "workerw",
    "tasklistthumbnailwnd", "dv2controlhost", "windows.ui.core.corewindow",
    "applicationframewindow", "msgrimewindowclass", "sysshadow",
    "ime", "default ime", "customexe", "tooltips_class32",
}
# 这些进程即使在自动模式下也不碰：系统外壳 / 会话管理
_POPUP_SAFE_PROCS = {
    "explorer.exe", "dwm.exe", "winlogon.exe", "csrss.exe", "services.exe",
    "lsass.exe", "smss.exe", "sihost.exe", "taskhostw.exe", "ctfmon.exe",
    "startmenuexperiencehost.exe", "searchapp.exe",
}

_VI_CACHE = {}

# 已知的纯广告进程 / 弹窗窗口类。前四个进程名来自 MIT 许可的 PopKiller 社区规则，
# 其余为本项目补充（都是"只为弹广告而生"的组件，关掉不影响软件本体功能）。
_POPUP_BAD_PROCS = {
    "flashcenter.exe", "minipage.exe", "flashhelperservice.exe", "kwallpaper.exe",
    "2345minipage.exe", "2345mini.exe", "360minipage.exe", "sogounews.exe",
    "sgtool.exe", "kxecl.exe", "popwndexe.exe", "adpopup.exe",
}
_POPUP_BAD_CLASS_HINTS = ("popup", "advert", "ad_", "tips", "news", "minipage",
                          "hotspot", "recommend", "promote")
# 标题关键词只用于「可疑度提示」，绝不单独作为自动关闭依据
_POPUP_AD_WORDS = ("迷你首页", "今日热点", "热点资讯", "弹窗", "优惠券", "领券",
                   "抽奖", "广告", "限时特惠", "红包", "推荐", "精选", "会员福利")


def _ver_company(path):
    """读文件版本资源里的公司名，带缓存（枚举窗口时会反复问同一个 exe）。"""
    if not path:
        return ""
    k = path.lower()
    if k in _VI_CACHE:
        return _VI_CACHE[k]
    try:
        info = _file_version_info(path) or {}
        v = (info.get("CompanyName") or "").strip()
    except Exception:
        v = ""
    _VI_CACHE[k] = v
    return v


def _proc_image_path(pid):
    """按 PID 取 exe 全路径（QueryFullProcessImageNameW，普通权限即可读）。"""
    h = None
    try:
        h = _K.OpenProcess(0x1000, False, int(pid))     # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            return ""
        size = ctypes.c_ulong(2048)
        buf = ctypes.create_unicode_buffer(2048)
        if _K.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
            return buf.value
    except Exception:
        pass
    finally:
        if h:
            try:
                _K.CloseHandle(h)
            except Exception:
                pass
    return ""


def _win_text(hwnd, fn, n=512):
    try:
        buf = ctypes.create_unicode_buffer(n)
        fn(hwnd, buf, n)
        return buf.value or ""
    except Exception:
        return ""


def popup_hint(win):
    """0~100 的「像不像广告弹窗」评分。

    只用于排序和界面提示，**不单独决定关不关**——标题关键词误伤太大
    （"推荐"、"精选" 在正经软件里也常见），自动关闭只认特征库和用户规则。
    """
    s = 0
    title = win.get("title") or ""
    cls = (win.get("cls") or "").lower()
    proc = (win.get("proc") or "").lower()
    if proc in _POPUP_BAD_PROCS:
        s += 45
    if win.get("topmost"):
        s += 12
    if any(k in cls for k in _POPUP_BAD_CLASS_HINTS):
        s += 18
    if any(w in title for w in _POPUP_AD_WORDS):
        s += 25
    if not win.get("company"):
        s += 12
    r = win.get("rect") or [0, 0, 0, 0]
    w, h = (r[2], r[3]) if len(r) >= 4 else (0, 0)
    if 150 <= w <= 520 and 80 <= h <= 420:
        s += 8                      # 弹窗的典型尺寸区间
    if win.get("visible") is False:
        s += 6                      # 藏在后台待机的更像弹窗
    return min(100, s)


def _win_item(hwnd, include_hidden=True):
    """把单个 HWND 变成结构化 dict；不该看的窗口返回 None。

    enum_popups 和「选取窗口」（鼠标指哪抓哪）共用这一段，避免两处判定走偏。
    """
    try:
        hwnd = int(hwnd)
        pid = ctypes.wintypes.DWORD(0)
        _W.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        pid = int(pid.value)
        if not pid or pid == os.getpid() or pid == 4:
            return None
        title = _win_text(hwnd, _W.GetWindowTextW)
        cls = _win_text(hwnd, _W.GetClassNameW, 256)
        if (cls or "").lower() in _POPUP_SAFE_CLASSES:
            return None
        visible = bool(_W.IsWindowVisible(hwnd))
        r = ctypes.wintypes.RECT()
        _W.GetWindowRect(hwnd, ctypes.byref(r))
        w, h = int(r.right - r.left), int(r.bottom - r.top)
        area = max(0, w) * max(0, h)
        if not title and (not visible or area < 400):
            return None                       # 无标题的小透明窗口没意义
        if not visible and not include_hidden:
            return None
        ex = 0
        try:
            ex = int(_W.GetWindowLongW(hwnd, -20)) or 0   # GWL_EXSTYLE
        except Exception:
            pass
        path = _proc_image_path(pid)
        proc = os.path.basename(path) if path else ""
        company = _ver_company(path)
        chk = adware_check(path=path, name=title or proc, company=company)
        it = {
            "hwnd": hwnd, "title": title, "cls": cls, "pid": pid,
            "proc": proc, "path": path, "company": company,
            "visible": visible, "tool": bool(ex & 0x00000080),
            "topmost": bool(ex & 0x00000008),
            "rect": [int(r.left), int(r.top), w, h], "area": area,
            "judge": "normal", "label": "", "why": "", "hint": 0,
        }
        it["hint"] = popup_hint(it)
        if chk.get("hit"):
            it.update(judge="adware", label=chk.get("label", ""),
                      why=chk.get("why", ""))
        elif (proc or "").lower() in _POPUP_BAD_PROCS:
            it.update(judge="adware", label="已知广告弹窗进程",
                      why="进程 %s 是纯广告组件（不影响软件本体）" % proc)
        elif it["hint"] >= 50:
            it.update(judge="suspicious", label="疑似弹窗",
                      why="可疑度 %d：%s" % (
                          it["hint"],
                          "、".join([x for x in (
                              "窗口置顶" if it["topmost"] else "",
                              "无厂商信息" if not company else "",
                              "标题含推广词" if any(w in title for w in _POPUP_AD_WORDS) else "",
                          ) if x]) or "窗口特征符合弹窗"))
        elif not company and path:
            it.update(judge="unsign", why="exe 没有厂商信息（无签名主体）")
        return it
    except Exception:
        return None


def enum_popups(include_hidden=True, limit=400):
    """枚举桌面顶层窗口，标注来源进程与可疑度。

    返回 list[dict]：hwnd / title / cls / pid / proc / path / company /
                    visible / tool / topmost / rect / area / judge / label / why / hint
    judge: adware（特征库 / 已知广告进程）/ suspicious（可疑）/ unsign / normal
    """
    out = []

    def cb(hwnd, _lparam):
        if len(out) >= limit:
            return False
        it = _win_item(hwnd, include_hidden)
        if it:
            out.append(it)
        return True

    try:
        _W.EnumWindows(ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p,
                                          ctypes.c_void_p)(cb), 0)
    except Exception as e:
        log_line("enum_popups failed: %r" % (e,))
    rank = {"adware": 0, "suspicious": 1, "unsign": 2, "normal": 3}
    out.sort(key=lambda x: (rank.get(x["judge"], 9), -x["hint"],
                            not x["visible"], -x["area"]))
    return out


def popup_pick_window():
    """抓鼠标指针下的顶层窗口（"截图选窗"的轻量版：不用覆盖层，指哪抓哪）。

    用 WindowFromPoint + GetAncestor(GA_ROOT)，返回结构同 enum_popups 的元素。
    """
    try:
        pt = ctypes.wintypes.POINT()
        if not _W.GetCursorPos(ctypes.byref(pt)):
            return None
        hwnd = _W.WindowFromPoint(pt)
        if not hwnd:
            return None
        root = _W.GetAncestor(hwnd, 2)          # GA_ROOT
        return _win_item(root or hwnd, include_hidden=True)
    except Exception as e:
        log_line("popup_pick_window failed: %r" % (e,))
        return None


POPUP_WATCH_LOG = os.path.join(LOG_DIR, "popup_watch.log")


def popup_watch_log(limit=80, path=None):
    """窗口记录（火绒同款）：守护进程见过的窗口，按时间倒序返回。"""
    out = []
    p = path or POPUP_WATCH_LOG
    try:
        with open(p, "r", encoding="utf-8", errors="replace") as fp:
            for line in fp:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except Exception:
                    continue
    except Exception:
        return []
    return out[-int(limit):][::-1]


def append_popup_watch(rows, path=None):
    """追加窗口记录，顺手控制文件大小（只留最近 800 行）。"""
    if not rows:
        return
    p = path or POPUP_WATCH_LOG
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "a", encoding="utf-8") as fp:
            for r in rows:
                fp.write(json.dumps(r, ensure_ascii=False) + "\n")
        if os.path.getsize(p) > 512 * 1024:
            with open(p, "r", encoding="utf-8", errors="replace") as fp:
                lines = fp.readlines()[-800:]
            with open(p, "w", encoding="utf-8") as fp:
                fp.writelines(lines)
    except Exception:
        pass


DEFAULT_POPUP_RULES = {
    "enabled": False,
    "auto_adware": True,      # 自动关闭命中流氓软件特征库的弹窗
    "poll_ms": 1200,
    "block": [],              # [{"kind": "proc|path|title|class", "pattern": "...", "note": ""}]
    "allow": [],
}


def load_popup_rules(path=None):
    p = path or POPUP_RULES_PATH
    d = dict(DEFAULT_POPUP_RULES)
    try:
        with open(p, "r", encoding="utf-8") as fp:
            raw = json.load(fp)
        if isinstance(raw, dict):
            for k in ("enabled", "auto_adware", "poll_ms"):
                if k in raw:
                    d[k] = raw[k]
            for k in ("block", "allow"):
                if isinstance(raw.get(k), list):
                    d[k] = [r for r in raw[k]
                            if isinstance(r, dict) and (r.get("pattern") or r.get("all"))]
    except Exception:
        pass
    return d


def save_popup_rules(d, path=None):
    p = path or POPUP_RULES_PATH
    try:
        _atomic_write_json(p, d)
        return True
    except Exception as e:
        log_line("popup rules save failed: %r" % (e,))
        return False


def _rule_one(kind, pat, win):
    kind = (kind or "").lower()
    pat = str(pat or "").strip().lower()
    if not pat:
        return False
    if kind == "proc":
        p = (win.get("proc") or "").lower()
        return p == pat or p.startswith(pat)
    if kind == "proc_contains":
        return pat in (win.get("proc") or "").lower()
    if kind == "path":
        return pat in (win.get("path") or "").lower()
    if kind == "title":
        return pat in (win.get("title") or "").lower()
    if kind == "class":
        return pat == (win.get("cls") or "").lower()
    if kind == "class_contains":
        return pat in (win.get("cls") or "").lower()
    if kind == "min_w":
        return (win.get("rect") or [0, 0, 0, 0])[2] >= int(pat)
    if kind == "max_w":
        return (win.get("rect") or [0, 0, 0, 0])[2] <= int(pat)
    return False


def _rule_hit(rule, win):
    """规则命中：单条件，或 all 数组里的条件全部满足。"""
    if not isinstance(rule, dict):
        return False
    if rule.get("all"):
        return all(_rule_hit(x, win) for x in rule["all"])
    return _rule_one(rule.get("kind"), rule.get("pattern"), win)


def should_close_popup(win, rules=None):
    """判定某个窗口该不该关。返回 (bool, 原因)。

    顺序：系统白名单 → 用户 allow → 用户 block → 自动模式（特征库 / 已知广告进程）。
    系统窗口（任务栏 / 桌面 / UWP 外壳）无条件放过，用户规则也压不住。
    """
    rules = rules if rules is not None else load_popup_rules()
    cls = (win.get("cls") or "").lower()
    proc = (win.get("proc") or "").lower()
    if cls in _POPUP_SAFE_CLASSES:
        return False, "系统窗口"
    # 系统进程也必须在用户规则之前判断：否则一条 title=「下载」的规则
    # 会把资源管理器里打开的「下载」文件夹窗口（explorer.exe / CabinetWClass）关掉
    if proc in _POPUP_SAFE_PROCS:
        return False, "系统进程"
    if not rules.get("enabled"):
        return False, "拦截未开启"
    for r in rules.get("allow") or []:
        if _rule_hit(r, win):
            return False, "白名单：%s" % (r.get("pattern") or r.get("all") or "")
    for r in rules.get("block") or []:
        if _rule_hit(r, win):
            return True, "规则命中（%s）" % (r.get("note") or
                                          r.get("pattern") or "组合条件")
    if rules.get("auto_adware") and win.get("judge") == "adware":
        return True, win.get("why") or "命中流氓软件特征库"
    return False, ""


def popup_stats(items):
    n = len(items)
    return {
        "total": n,
        "adware": sum(1 for x in items if x.get("judge") == "adware"),
        "suspicious": sum(1 for x in items if x.get("judge") == "suspicious"),
        "unsign": sum(1 for x in items if x.get("judge") == "unsign"),
        "visible": sum(1 for x in items if x.get("visible")),
    }


# ad-blocker 风格条件 -> 本项目规则
_IMPORT_COND = {
    "processnameequals": lambda v: {"kind": "proc", "pattern": v},
    "processnamecontains": lambda v: {"kind": "proc_contains", "pattern": v},
    "processpathcontains": lambda v: {"kind": "path", "pattern": v},
    "classnamecontains": lambda v: {"kind": "class_contains", "pattern": v},
    "classnameequals": lambda v: {"kind": "class", "pattern": v},
    "titlecontains": lambda v: {"kind": "title", "pattern": v},
    "titleequals": lambda v: {"kind": "title", "pattern": v},
}


def import_popup_rules(path, merge=True, rules_path=None):
    """导入规则文件。

    认两种格式：
      1. 本项目：{"block": [{"kind": "proc", "pattern": "xx.exe"}], "allow": [...]}
      2. 社区常见（ad-blocker 风格）：
         {"software": [{"name": "...", "rules": [{"conditions": [
             {"type": "ProcessNameEquals", "value": "a.exe"}], "action": "Close"}]}]}
    返回 (ok, 导入条数, 说明)。
    """
    try:
        with open(path, "r", encoding="utf-8-sig") as fp:
            raw = json.load(fp)
    except Exception as e:
        return False, 0, "读不了规则文件：%s" % e

    got = {"block": [], "allow": []}
    if isinstance(raw, dict) and ("block" in raw or "allow" in raw):
        for k in ("block", "allow"):
            for r in raw.get(k) or []:
                if isinstance(r, dict) and (r.get("pattern") or r.get("all")):
                    got[k].append(r)
    else:
        sw = raw.get("software") if isinstance(raw, dict) else raw
        if not isinstance(sw, list):
            return False, 0, "不认识的规则格式"
        for app in sw:
            if not isinstance(app, dict):
                continue
            app_name = app.get("name") or ""
            for r in app.get("rules") or []:
                conds = [c for c in (r.get("conditions") or []) if isinstance(c, dict)]
                maps = []
                for c in conds:
                    fn = _IMPORT_COND.get(str(c.get("type") or "").lower())
                    if fn and str(c.get("value") or "").strip():
                        maps.append(fn(str(c["value"]).strip()))
                if not maps:
                    continue
                action = str(r.get("action") or "Close").lower()
                tgt = "allow" if action in ("ignore", "allow", "whitelist") else "block"
                note = "%s / %s" % (app_name, r.get("name") or "")
                rule = dict(maps[0]) if len(maps) == 1 else {"all": maps}
                rule["note"] = note.strip(" /")
                got[tgt].append(rule)

    n = len(got["block"]) + len(got["allow"])
    if not n:
        return False, 0, "文件里没有可用的规则"
    if merge:
        cur = load_popup_rules(rules_path)
        have = {(r.get("kind"), r.get("pattern"), json.dumps(r.get("all"), sort_keys=True))
                for r in cur["block"] + cur["allow"]}
        for k in ("block", "allow"):
            for r in got[k]:
                sig = (r.get("kind"), r.get("pattern"), json.dumps(r.get("all"), sort_keys=True))
                if sig not in have:
                    cur[k].append(r)
                    have.add(sig)
        got = cur
    out = dict(DEFAULT_POPUP_RULES)
    out.update({"block": got["block"], "allow": got["allow"]})
    if "enabled" in got:
        out["enabled"] = bool(got["enabled"])
    if not save_popup_rules(out, rules_path):
        return False, 0, "写规则文件失败"
    return True, n, "导入 %d 条（拦截 %d / 放行 %d）" % (
        n, len(got["block"]), len(got["allow"]))


# ---------------- 守护进程控制（popup_guard.py） ----------------

def _pid_alive(pid):
    h = None
    try:
        h = _K.OpenProcess(0x1000, False, int(pid))
        if not h:
            return False
        code = ctypes.wintypes.DWORD(0)
        if not _K.GetExitCodeProcess(h, ctypes.byref(code)):
            return False
        return int(code.value) == 259        # STILL_ACTIVE
    except Exception:
        return False
    finally:
        if h:
            try:
                _K.CloseHandle(h)
            except Exception:
                pass


def _proc_create_time(pid):
    """进程创建时间（FILETIME 的 64 位整数），失败返回 0。

    PID 会被系统复用（重启后尤其常见），只有「PID + 创建时间」才能唯一认出一个进程。
    """
    h = None
    try:
        h = _K.OpenProcess(0x1000, False, int(pid))     # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            return 0
        ft = [ctypes.wintypes.FILETIME() for _ in range(4)]
        if not _K.GetProcessTimes(h, *[ctypes.byref(x) for x in ft]):
            return 0
        return (int(ft[0].dwHighDateTime) << 32) | int(ft[0].dwLowDateTime)
    except Exception:
        return 0
    finally:
        if h:
            try:
                _K.CloseHandle(h)
            except Exception:
                pass


def write_guard_pid(path=None):
    """守护进程启动时调用：写「PID 创建时间」两个数，供 guard_pid() 校验身份。"""
    p = path or GUARD_PID_PATH
    pid = os.getpid()
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as fp:
        fp.write("%d %d" % (pid, _proc_create_time(pid)))


def guard_pid(path=None):
    """返回正在运行的守护 PID，没有则 0。

    只看 PID 不够：守护被关机 / 注销直接结束时来不及删 pid 文件，下次开机这个 PID
    可能已经分给了别的程序。那样界面会误报「守护已在运行」，stop_popup_guard()
    更会对那个无关进程 TerminateProcess（本程序是管理员权限，几乎什么都杀得掉）。
    """
    try:
        with open(path or GUARD_PID_PATH, "r", encoding="utf-8") as fp:
            parts = (fp.read() or "").split()
        pid = int(parts[0]) if parts else 0
        ct = int(parts[1]) if len(parts) > 1 else 0
    except Exception:
        return 0
    if not pid or not _pid_alive(pid):
        return 0
    if ct:
        return pid if _proc_create_time(pid) == ct else 0
    # 旧版 pid 文件只有 PID：至少确认那是个 Python 进程，否则当作过期文件
    name = os.path.basename(_proc_image_path(pid)).lower()
    return pid if name in ("python.exe", "pythonw.exe") else 0


def guard_running():
    return guard_pid() > 0


def start_popup_guard(progress=None):
    """后台拉起 popup_guard.py（pythonw，无控制台）。返回 (ok, msg)。"""
    if guard_running():
        return True, "守护已在运行（PID %d）" % guard_pid()
    if not os.path.isfile(GUARD_SCRIPT):
        return False, "找不到 popup_guard.py"
    rules = load_popup_rules()
    rules["enabled"] = True
    save_popup_rules(rules)
    if guard_autostart()[0] == "stale":
        # 项目目录被挪过：自启项还指着旧路径，顺手改写，否则下次开机白等
        set_guard_autostart(True)
    try:
        if os.path.exists(GUARD_STOP_PATH):
            os.remove(GUARD_STOP_PATH)
    except Exception:
        pass
    exe = sys.executable
    pydir = os.path.dirname(exe)
    for cand in ("pythonw.exe", "python.exe"):
        p = os.path.join(pydir, cand)
        if os.path.isfile(p):
            exe = p
            break
    try:
        flags = 0x00000008 | 0x08000000      # DETACHED_PROCESS | CREATE_NO_WINDOW
        subprocess.Popen([exe, GUARD_SCRIPT], cwd=BASE_DIR, creationflags=flags,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         close_fds=True)
    except Exception as e:
        log_line("start popup guard failed: %r" % (e,))
        return False, "启动失败：%s" % e
    for _ in range(30):                      # 最多等 3 秒写 pid
        time.sleep(0.1)
        if guard_running():
            log_line("popup guard started pid=%d" % guard_pid())
            return True, "守护已启动（PID %d）" % guard_pid()
    return False, "守护进程没起来，看 _logs\\popup_guard.log"


def stop_popup_guard():
    """优雅停止：写 stop 标记，守护自己退出；3 秒没退再强杀。"""
    try:
        rules = load_popup_rules()
        rules["enabled"] = False
        save_popup_rules(rules)
    except Exception:
        pass
    pid = guard_pid()
    if not pid:
        try:
            os.remove(GUARD_PID_PATH)              # 过期的 pid 文件顺手清掉
        except Exception:
            pass
        return True, "守护没在运行"
    ct = _proc_create_time(pid)
    try:
        ensure_dirs()
        with open(GUARD_STOP_PATH, "w", encoding="utf-8") as fp:
            fp.write("stop")
    except Exception:
        pass
    for _ in range(30):
        time.sleep(0.1)
        if not _pid_alive(pid):
            log_line("popup guard stopped pid=%d" % pid)
            return True, "守护已停止"
    # 强杀前再核对一次身份：等待的这 3 秒里守护可能已退出、PID 被别人拿走
    if not ct:
        log_line("popup guard pid=%d not responding, identity unknown, skip terminate" % pid)
        return False, "守护没有响应停止请求，且无法确认进程身份，未强制结束（可在托盘里退出）"
    if _proc_create_time(pid) != ct:
        log_line("popup guard pid=%d identity changed, skip terminate" % pid)
        return True, "守护已停止"
    try:
        h = _K.OpenProcess(0x0001, False, pid)      # PROCESS_TERMINATE
        if h:
            _K.TerminateProcess(h, 0)
            _K.CloseHandle(h)
    except Exception:
        pass
    try:
        os.remove(GUARD_PID_PATH)
    except Exception:
        pass
    return True, "守护已强制停止"


# --------------------------------------------------------------------------
# 开机自启：写 HKCU\...\Run（不需要管理员，也不装服务）
# 只放一个 pythonw 拉起 popup_guard.py 的命令行，卸载时删这一个值即可。
# --------------------------------------------------------------------------
GUARD_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
GUARD_RUN_NAME = "BootDoctorPopupGuard"


def _pythonw_path():
    """优先 pythonw.exe（无控制台黑窗），找不到退回当前解释器。"""
    exe = sys.executable or ""
    d = os.path.dirname(exe)
    p = os.path.join(d, "pythonw.exe")
    return p if os.path.isfile(p) else exe


def guard_cmdline():
    return '"%s" "%s" --silent' % (_pythonw_path(), GUARD_SCRIPT)


def guard_autostart():
    """读开机自启状态，返回 (state, value)。state：off / on / stale（指向旧路径）。"""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, GUARD_RUN_KEY) as k:
            val, _t = winreg.QueryValueEx(k, GUARD_RUN_NAME)
    except Exception:
        return "off", ""
    val = str(val or "")
    if GUARD_SCRIPT.lower() not in val.lower():
        return "stale", val
    return "on", val


def set_guard_autostart(on):
    """开/关开机自启。返回 (ok, msg)。"""
    try:
        import winreg
        if on:
            with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, GUARD_RUN_KEY, 0,
                                    winreg.KEY_SET_VALUE) as k:
                winreg.SetValueEx(k, GUARD_RUN_NAME, 0, winreg.REG_SZ, guard_cmdline())
        else:
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, GUARD_RUN_KEY, 0,
                                    winreg.KEY_SET_VALUE) as k:
                    winreg.DeleteValue(k, GUARD_RUN_NAME)
            except FileNotFoundError:
                pass
    except Exception as e:
        log_line("set guard autostart failed: %r" % (e,))
        return False, "写注册表失败：%s" % e
    return True, ("已开启：下次登录后在托盘静默拦截，不弹任何窗口" if on
                  else "已关闭开机自启（当前守护不受影响）")


def popup_enabled():
    return bool(load_popup_rules().get("enabled"))


def set_popup_enabled(on):
    """总开关。守护开机静默启动时也看它：关着就直接退出，不驻留托盘。"""
    try:
        r = load_popup_rules()
        r["enabled"] = bool(on)
        return save_popup_rules(r)
    except Exception:
        return False


def popup_log_tail(n=40):
    """读拦截日志尾部（给界面显示"刚拦了啥"）。"""
    p = os.path.join(LOG_DIR, "popup_guard.log")
    try:
        with open(p, "r", encoding="utf-8", errors="replace") as fp:
            lines = fp.readlines()
        return [x.rstrip() for x in lines[-int(n):]]
    except Exception:
        return []


# --------------------------------------------------------------------------
# 采集 2：服务（注册表直读，含镜像文件存在性）
# --------------------------------------------------------------------------

def resolve_image_path(img):
    if not img:
        return ""
    p = os.path.expandvars(img.strip())
    if p.startswith('"'):
        end = p.find('"', 1)
        p = (p[1:end] if end > 0 else p.strip('"'))
    if p.startswith("\\??\\"):
        p = p[4:]
    sysroot = os.environ.get("SystemRoot", r"C:\Windows")
    if p.lower().startswith("\\systemroot\\"):
        p = os.path.join(sysroot, p[len("\\systemroot\\"):])
    elif not re.match(r"(?i)^[a-z]:\\", p):
        p = os.path.join(sysroot, p.lstrip("\\"))
    # 未加引号的命令可能带启动参数：截取到 .exe/.sys 为止
    m = re.match(r'(?i)^([a-z]:\\[^"].*?\.(?:sys|exe))(\s|$)', p)
    if m:
        p = m.group(1)
    elif " -" in p:
        # 无扩展名的可执行（如 %SystemRoot%\SysWOW64\svchost -k xxx）
        p = p.split(" -", 1)[0]
    return p


def image_file_exists(rp):
    """镜像文件存在性：对省略 .exe/.sys 的写法（svchost 等）自动补扩展名。"""
    if not rp:
        return True
    if path_exists_raw(rp):
        return True
    if not rp.lower().endswith((".exe", ".sys")):
        if path_exists_raw(rp + ".exe") or path_exists_raw(rp + ".sys"):
            return True
    return False


def enum_services():
    out = []
    try:
        with winreg.OpenKey(HKLM, _SVC_BASE, 0, winreg.KEY_READ) as k:
            i = 0
            while True:
                try:
                    name = winreg.EnumKey(k, i)
                except OSError:
                    break
                i += 1
                try:
                    with winreg.OpenKey(HKLM, _SVC_BASE + "\\" + name, 0, winreg.KEY_READ) as sk:
                        def gv(n, d=None):
                            try:
                                return winreg.QueryValueEx(sk, n)[0]
                            except OSError:
                                return d
                        start = gv("Start")
                        typ = gv("Type")
                        img = gv("ImagePath")
                        disp = gv("DisplayName")
                        dly = gv("DelayedAutoStart")
                except OSError:
                    continue
                if start is None:
                    continue
                out.append({
                    "name": name, "start": int(start), "type": int(typ or 1),
                    "image": str(img or ""), "disp": str(disp or ""),
                    "delayed": int(dly or 0),
                })
    except OSError:
        pass
    return out


# --------------------------------------------------------------------------
# 采集 3：电源状态 / PowerShell 批量查询
# --------------------------------------------------------------------------

def read_power_state():
    return {
        "hiberboot": _reg_dword(HKLM, _POWR_PATH, "HiberbootEnabled"),
        "hibernate": _reg_dword(HKLM, _HIBE_PATH, "HibernateEnabled"),
        "enable_lua": _reg_dword(HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA"),
        "hiberfil": path_exists_raw(r"C:\hiberfil.sys"),
    }


PS_SYS = r"""
$r = @{}
$os = Get-CimInstance Win32_OperatingSystem
$r.osName = [string]$os.Caption
try { $r.build = [string](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild } catch {}
$r.bootTime = $os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss')
$r.ramGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
$r.svcAuto = @(Get-Service | Where-Object {$_.StartType -eq 'Automatic'}).Count
$r.svcAutoRun = @(Get-Service | Where-Object {$_.StartType -eq 'Automatic' -and $_.Status -eq 'Running'}).Count
$r.svcAutoDown = @(Get-Service | Where-Object {$_.StartType -eq 'Automatic' -and $_.Status -ne 'Running'} | ForEach-Object { [string]$_.Name })
$r.disks = @()
Get-PhysicalDisk -ErrorAction SilentlyContinue | ForEach-Object { $r.disks += @{ name = [string]$_.FriendlyName; media = [string]$_.MediaType; size = [int]([math]::Round($_.Size / 1GB)); health = [string]$_.HealthStatus } }
$r.vols = @()
Get-Volume -ErrorAction SilentlyContinue | Where-Object {$_.DriveLetter} | ForEach-Object { $r.vols += @{ letter = [string]$_.DriveLetter; free = [int]([math]::Round($_.SizeRemaining / 1GB)); total = [int]([math]::Round($_.Size / 1GB)) } }
$r.tasks = @()
Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Ready' -and @($_.Triggers | Where-Object { $_.CimClass.CimClassName -match 'BootTrigger|LogonTrigger' }).Count -gt 0 } | Select-Object -First 200 | ForEach-Object { $r.tasks += ($_.TaskPath + $_.TaskName) }
$r | ConvertTo-Json -Depth 6 -Compress
"""

PS_EVENTS_LEGACY = r"""
$r = @{}
$r.boots = @()
$ev = Get-WinEvent -LogName 'Microsoft-Windows-Diagnostics-Performance/Operational' -MaxEvents 800 -ErrorAction SilentlyContinue | Where-Object {$_.Id -eq 100} | Select-Object -First 10
foreach($e in $ev){
  $x = [xml]$e.ToXml(); $d = @{}
  foreach($dd in $x.Event.EventData.Data){ $d[$dd.Name] = $dd.'#text' }
  $r.boots += @{ time = $e.TimeCreated.ToString('yyyy-MM-dd HH:mm'); boot = [int]([double]$d['BootTime'] / 1000); main = [int]([double]$d['MainPathBootTime'] / 1000); post = [int]([double]$d['BootPostBootTime'] / 1000); profile = [int]([double]$d['BootUserProfileProcessingTime'] / 1000); explorer = [int]([double]$d['BootExplorerInitTime'] / 1000); apps = [int]$d['BootNumStartupApps'] }
}
$r.slow = @()
Get-WinEvent -LogName 'Microsoft-Windows-Diagnostics-Performance/Operational' -MaxEvents 800 -ErrorAction SilentlyContinue | Where-Object {$_.Id -in 101,102,103} | Select-Object -First 40 | ForEach-Object {
  $x = [xml]$_.ToXml(); $d = @{}
  foreach($dd in $x.Event.EventData.Data){ $d[$dd.Name] = $dd.'#text' }
  $n = $d['Name']; if(-not $n){ $n = $d['FriendlyName'] }; if(-not $n){ $n = $d['DriverName'] }
  $t = 0; if($d['TotalTime']){ $t = [int]([double]$d['TotalTime'] / 10000) }
  $r.slow += @{ id = $_.Id; time = $_.TimeCreated.ToString('MM-dd HH:mm'); name = [string]$n; ms = $t }
}
$r.scm = @()
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7009,7026,7000,7031; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue | Select-Object -First 60 | ForEach-Object {
  $r.scm += @{ id = $_.Id; time = $_.TimeCreated.ToString('MM-dd HH:mm'); msg = [string](($_.Message -split "`r?`n")[0]) }
}
$r.c7005 = @(Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Service Control Manager'; Id=7005; StartTime=(Get-Date).AddDays(-1)} -MaxEvents 8000 -ErrorAction SilentlyContinue).Count
$r.c7005_7d = @(Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Service Control Manager'; Id=7005; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 8000 -ErrorAction SilentlyContinue).Count
$r.c7005_1h = @(Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Service Control Manager'; Id=7005; StartTime=(Get-Date).AddHours(-1)} -MaxEvents 3000 -ErrorAction SilentlyContinue).Count
$r.last7005 = ''
$le = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Service Control Manager'; Id=7005; StartTime=(Get-Date).AddDays(-2)} -MaxEvents 1 -ErrorAction SilentlyContinue
if($le){ $r.last7005 = $le.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') }
$r.c7023 = @(Get-WinEvent -FilterHashtable @{LogName='System'; Id=7023; StartTime=(Get-Date).AddDays(-1)} -MaxEvents 2000 -ErrorAction SilentlyContinue).Count
$r | ConvertTo-Json -Depth 6 -Compress
"""

PS_EVENTS = r"""
$r = @{}
$r.boots = @()
$dp = 'Microsoft-Windows-Diagnostics-Performance/Operational'
$ev = Get-WinEvent -FilterHashtable @{LogName=$dp; Id=100} -MaxEvents 10 -ErrorAction SilentlyContinue
foreach($e in $ev){
  $x = [xml]$e.ToXml(); $d = @{}
  foreach($dd in $x.Event.EventData.Data){ $d[$dd.Name] = $dd.'#text' }
  $r.boots += @{ time = $e.TimeCreated.ToString('yyyy-MM-dd HH:mm'); boot = [int]([double]$d['BootTime'] / 1000); main = [int]([double]$d['MainPathBootTime'] / 1000); post = [int]([double]$d['BootPostBootTime'] / 1000); profile = [int]([double]$d['BootUserProfileProcessingTime'] / 1000); explorer = [int]([double]$d['BootExplorerInitTime'] / 1000); apps = [int]$d['BootNumStartupApps'] }
}
$r.slow = @()
Get-WinEvent -FilterHashtable @{LogName=$dp; Id=101,102,103} -MaxEvents 40 -ErrorAction SilentlyContinue | ForEach-Object {
  $x = [xml]$_.ToXml(); $d = @{}
  foreach($dd in $x.Event.EventData.Data){ $d[$dd.Name] = $dd.'#text' }
  $n = $d['Name']; if(-not $n){ $n = $d['FriendlyName'] }; if(-not $n){ $n = $d['DriverName'] }
  $t = 0; if($d['TotalTime']){ $t = [int]([double]$d['TotalTime'] / 10000) }
  $r.slow += @{ id = $_.Id; time = $_.TimeCreated.ToString('MM-dd HH:mm'); name = [string]$n; ms = $t }
}
$r.scm = @()
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7009,7026,7000,7031; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 60 -ErrorAction SilentlyContinue | ForEach-Object {
  $r.scm += @{ id = $_.Id; time = $_.TimeCreated.ToString('MM-dd HH:mm'); msg = [string](($_.Message -split "`r?`n")[0]) }
}
$now = Get-Date
$e7 = @(Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Service Control Manager'; Id=7005; StartTime=$now.AddDays(-7)} -MaxEvents 8000 -ErrorAction SilentlyContinue)
$t1d = $now.AddDays(-1); $t1h = $now.AddHours(-1)
$r.c7005_7d = $e7.Count
$r.c7005 = @($e7 | Where-Object { $_.TimeCreated -ge $t1d }).Count
$r.c7005_1h = @($e7 | Where-Object { $_.TimeCreated -ge $t1h }).Count
$r.last7005 = ''
if($e7.Count -gt 0 -and $e7[0].TimeCreated -ge $now.AddDays(-2)){ $r.last7005 = $e7[0].TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') }
$r.c7023 = @(Get-WinEvent -FilterHashtable @{LogName='System'; Id=7023; StartTime=$now.AddDays(-1)} -MaxEvents 2000 -ErrorAction SilentlyContinue).Count
$r | ConvertTo-Json -Depth 6 -Compress
"""


# --------------------------------------------------------------------------
# 系统信息：原生读取（替代 PS_SYS 里的大部分命令）
#
# 实测（CI 机器）PS_SYS 冷启动 5.1 秒：Get-PhysicalDisk 要先加载 Storage 模块（1.1s），
# Get-ScheduledTask 要枚举全部任务的 CIM 对象（0.6s），再加上 PowerShell / CIM 本身的冷启动。
# 这些信息其实都能从注册表、Win32 API、任务 XML 直接拿到，只有磁盘健康度必须走 WMI，
# 改用 Get-CimInstance 直接查 MSFT_PhysicalDisk，绕开 Storage 模块。
# 任何一步失败都退回原来的 PowerShell 查询，结果结构不变。
# --------------------------------------------------------------------------

PS_DISKS = r"""
$m = @{0='Unspecified';3='HDD';4='SSD';5='SCM'}
$h = @{0='Healthy';1='Warning';2='Unhealthy';5='Unknown'}
$r = @()
Get-CimInstance -Namespace root/Microsoft/Windows/Storage -ClassName MSFT_PhysicalDisk -ErrorAction SilentlyContinue | ForEach-Object {
  $mt = $m[[int]$_.MediaType]; if(-not $mt){ $mt = [string]$_.MediaType }
  $hs = $h[[int]$_.HealthStatus]; if(-not $hs){ $hs = [string]$_.HealthStatus }
  $r += @{ name = [string]$_.FriendlyName; media = $mt; size = [int]([math]::Round($_.Size / 1GB)); health = $hs }
}
ConvertTo-Json -InputObject @($r) -Depth 4 -Compress
"""

PS_TASKS = r"""
$r = @()
Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Ready' -and @($_.Triggers | Where-Object { $_.CimClass.CimClassName -match 'BootTrigger|LogonTrigger' }).Count -gt 0 } | Select-Object -First 200 | ForEach-Object { $r += ($_.TaskPath + $_.TaskName) }
ConvertTo-Json -InputObject @($r) -Compress
"""

_EDITION_CN = {
    "Core": "家庭版", "CoreCountrySpecific": "家庭中文版", "CoreSingleLanguage": "家庭单语言版",
    "Professional": "专业版", "ProfessionalEducation": "专业教育版",
    "ProfessionalWorkstation": "专业工作站版", "Education": "教育版",
    "Enterprise": "企业版", "EnterpriseS": "企业版 LTSC", "IoTEnterprise": "IoT 企业版",
    "IoTEnterpriseS": "IoT 企业版 LTSC",
}
_CV = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"


def _os_caption():
    """系统名称。注意 Win11 的注册表 ProductName 仍写着「Windows 10」，要按版本号纠正。"""
    prod = _reg_str(HKLM, _CV, "ProductName") or "Windows"
    build = _reg_str(HKLM, _CV, "CurrentBuild") or _reg_str(HKLM, _CV, "CurrentBuildNumber")
    if "server" in prod.lower():
        return "Microsoft " + prod
    fam = "Windows 11" if build.isdigit() and int(build) >= 22000 else "Windows 10"
    ed = _reg_str(HKLM, _CV, "EditionID")
    cn = _EDITION_CN.get(ed)
    if cn:
        return "Microsoft %s %s" % (fam, cn)
    return "Microsoft " + prod.replace("Windows 10", fam)


def _boot_time_str():
    """上次开机时间。取内核记录的 BootTime（WMI 的 LastBootUpTime 也是它），失败再按运行时长推算。"""
    try:
        buf = (ctypes.c_ubyte * 48)()
        n = ctypes.c_ulong(0)
        nt = ctypes.WinDLL("ntdll")
        nt.NtQuerySystemInformation.restype = ctypes.c_long
        nt.NtQuerySystemInformation.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong,
                                                ctypes.POINTER(ctypes.c_ulong)]
        if nt.NtQuerySystemInformation(3, buf, 48, ctypes.byref(n)) == 0:   # SystemTimeOfDayInformation
            ft = ctypes.c_longlong.from_buffer(buf).value                   # UTC，100ns，自 1601 年起
            utc = _dt.datetime(1601, 1, 1, tzinfo=_dt.timezone.utc) + _dt.timedelta(microseconds=ft // 10)
            return utc.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        pass
    k32 = ctypes.WinDLL("kernel32")
    k32.GetTickCount64.restype = ctypes.c_ulonglong
    up = _dt.timedelta(milliseconds=int(k32.GetTickCount64()))
    return (_dt.datetime.now() - up).strftime("%Y-%m-%d %H:%M:%S")


class _MEMSTAT(ctypes.Structure):
    _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]


def _ram_gb():
    m = _MEMSTAT()
    m.dwLength = ctypes.sizeof(_MEMSTAT)
    k32 = ctypes.WinDLL("kernel32")
    k32.GlobalMemoryStatusEx.argtypes = [ctypes.POINTER(_MEMSTAT)]
    if not k32.GlobalMemoryStatusEx(ctypes.byref(m)):
        raise OSError("GlobalMemoryStatusEx failed")
    return round(m.ullTotalPhys / float(1 << 30), 1)


class _SVC_STATUS_PROCESS(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ulong) for n in (
        "dwServiceType", "dwCurrentState", "dwControlsAccepted", "dwWin32ExitCode",
        "dwServiceSpecificExitCode", "dwCheckPoint", "dwWaitHint", "dwProcessId",
        "dwServiceFlags")]


class _ENUM_SVC_STATUS_PROCESS(ctypes.Structure):
    _fields_ = [("lpServiceName", ctypes.c_wchar_p), ("lpDisplayName", ctypes.c_wchar_p),
                ("status", _SVC_STATUS_PROCESS)]


def _scm_service_states():
    """{服务名: 当前状态}（4 = 运行中）。一次 EnumServicesStatusExW 拿全，不用起 PowerShell。"""
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    adv.OpenSCManagerW.restype = ctypes.c_void_p
    adv.OpenSCManagerW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_ulong]
    adv.EnumServicesStatusExW.restype = ctypes.c_int
    adv.EnumServicesStatusExW.argtypes = [
        ctypes.c_void_p, ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p,
        ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong), ctypes.POINTER(ctypes.c_ulong),
        ctypes.POINTER(ctypes.c_ulong), ctypes.c_wchar_p]
    adv.CloseServiceHandle.argtypes = [ctypes.c_void_p]
    h = adv.OpenSCManagerW(None, None, 0x0004)          # SC_MANAGER_ENUMERATE_SERVICE
    if not h:
        raise OSError(ctypes.get_last_error(), "OpenSCManagerW failed")
    out = {}
    try:
        need, cnt, resume = ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0)
        size = 128 * 1024
        for _ in range(16):
            buf = ctypes.create_string_buffer(size)
            ok = adv.EnumServicesStatusExW(h, 0, 0x30, 3, buf, size, ctypes.byref(need),
                                           ctypes.byref(cnt), ctypes.byref(resume), None)
            err = ctypes.get_last_error()
            arr = ctypes.cast(buf, ctypes.POINTER(_ENUM_SVC_STATUS_PROCESS))
            for i in range(cnt.value):                  # 字符串指针指向 buf 内部，必须趁 buf 还在时读完
                out[arr[i].lpServiceName] = int(arr[i].status.dwCurrentState)
            if ok:
                break
            if err != 234:                              # ERROR_MORE_DATA：带着 resume 句柄继续
                raise OSError(err, "EnumServicesStatusExW failed")
            size = max(size, int(need.value) + 4096)
    finally:
        adv.CloseServiceHandle(h)
    return out


def _svc_auto_stats():
    states = _scm_service_states()
    auto = [n for n in states
            if _reg_dword(HKLM, _SVC_BASE + "\\" + n, "Start") == 2]   # 2 = 自动（含延迟自动）
    down = sorted(n for n in auto if states[n] != 4)
    return len(auto), len(auto) - len(down), down


def _volumes():
    k32 = ctypes.WinDLL("kernel32")
    k32.GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
    mask = int(k32.GetLogicalDrives())
    out = []
    for i in range(26):
        if not mask & (1 << i):
            continue
        root = "%s:\\" % chr(65 + i)
        if k32.GetDriveTypeW(root) not in (2, 3):        # 只要本地硬盘 / 可移动盘，跳过光驱和网络盘
            continue
        try:
            u = shutil.disk_usage(root)
        except OSError:
            continue
        out.append({"letter": chr(65 + i), "free": int(round(u.free / float(1 << 30))),
                    "total": int(round(u.total / float(1 << 30)))})
    return out


def _task_xml_text(path):
    with open(path, "rb") as fp:
        raw = fp.read(512 * 1024)
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", "ignore")
    return raw.decode("utf-8", "ignore")


def boot_logon_tasks_from_xml(root=None, limit=200):
    """开机 / 登录触发、且未被禁用的计划任务（直接读 System32\\Tasks 下的 XML，需管理员）。

    返回与 PS_SYS 里 $r.tasks 相同的「\\路径\\任务名」列表；目录读不了时抛 PermissionError。
    """
    root = root or TASKS_DIR
    os.listdir(root)                                    # 普通权限下这里就会抛，交给调用方退回 PowerShell
    out = []
    for dp, dirs, files in os.walk(root):
        dirs.sort()
        for fn in sorted(files):
            p = os.path.join(dp, fn)
            try:
                txt = _task_xml_text(p)
            except OSError:
                continue
            m_trg = re.search(r"<Triggers>(.*?)</Triggers>", txt, re.S)
            if not m_trg or not re.search(r"<(BootTrigger|LogonTrigger)\b", m_trg.group(1)):
                continue
            m_set = re.search(r"<Settings>(.*?)</Settings>", txt, re.S)
            if m_set and re.search(r"<Enabled>\s*false\s*</Enabled>", m_set.group(1), re.I):
                continue                                # Disable-ScheduledTask 写的就是这里
            rel = os.path.relpath(p, root).replace("/", "\\")
            out.append("\\" + rel)
    out.sort(key=lambda x: (x.count("\\") > 1, x.lower()))   # 根目录任务在前，和 Get-ScheduledTask 一致
    return out[:limit]


def sys_info_native(with_disks=True):
    """PS_SYS 的原生实现，返回结构与 PS_SYS 完全一致。"""
    auto, run, down = _svc_auto_stats()
    d = {
        "osName": _os_caption(),
        "build": _reg_str(HKLM, _CV, "CurrentBuild") or _reg_str(HKLM, _CV, "CurrentBuildNumber"),
        "bootTime": _boot_time_str(),
        "ramGB": _ram_gb(),
        "svcAuto": auto, "svcAutoRun": run, "svcAutoDown": down,
        "vols": _volumes(),
        "disks": [],
        "tasks": [],
    }
    if with_disks:
        disks = _parse_json(run_ps(PS_DISKS, timeout=60))
        d["disks"] = disks if isinstance(disks, list) else []
    try:
        d["tasks"] = boot_logon_tasks_from_xml()
    except OSError:
        t = _parse_json(run_ps(PS_TASKS, timeout=120))
        d["tasks"] = t if isinstance(t, list) else []
    return d


def collect_sys():
    """系统信息：先走原生，出任何异常都整体退回 PowerShell（结构相同）。"""
    try:
        return sys_info_native()
    except Exception as e:
        log_line("sys_info_native failed, fallback to PS_SYS: %r" % (e,))
        return _parse_json(run_ps(PS_SYS, timeout=120))


def get_filters():
    """fltmc 过滤器驱动名列表（需管理员，失败返回空表）。"""
    rc, out, _ = _run(["fltmc", "filters"], timeout=20)
    names = []
    if rc == 0:
        txt = out.decode("gbk", errors="replace")
        for line in txt.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[1].isdigit():
                names.append(parts[0])
    return names


# --------------------------------------------------------------------------
# collect：完整采集
# --------------------------------------------------------------------------

class ScanCancelled(Exception):
    """用户中途取消体检（目前只在内部分支使用，界面暂不暴露取消按钮）。"""


def _bg_call(fn, timeout=200):
    """后台跑一个阻塞调用，返回 (等待函数, 取值函数)。

    PowerShell 每条要 1.5~2.5 秒（进程启动 + WMI），串行跑就是纯等待。
    这里开守护线程并行，主线程去做几十毫秒的注册表活。
    """
    box = {"val": {}, "err": ""}
    done = threading.Event()

    def run():
        try:
            box["val"] = fn()
        except Exception as e:                     # 不能把异常丢进线程里静默掉
            box["err"] = repr(e)
            log_line("bg call failed: %r" % (e,))
        finally:
            done.set()

    threading.Thread(target=run, daemon=True).start()

    def wait():
        done.wait(timeout)
        return box["val"]

    return wait


def collect(progress=None, should_stop=None):
    def P(t):
        log_line("collect: " + t)
        if progress:
            progress(t)

    def stopped():
        return bool(should_stop and should_stop())

    ensure_dirs()
    raw = {"ts": _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "admin": is_admin()}

    # 系统信息（大部分原生，磁盘健康走一个轻量 PowerShell）和事件日志扔后台，
    # 主线程同时做便宜的注册表读取
    wait_sys = _bg_call(collect_sys)
    wait_evt = _bg_call(lambda: _parse_json(run_ps(PS_EVENTS, timeout=180)))

    P("读取注册表：开机自启项 …")
    raw["startup"] = enum_startup_items()
    P("读取注册表：服务列表 …")
    raw["services"] = enum_services()
    P("读取电源 / 快速启动状态 …")
    raw["power"] = read_power_state()
    P("检查文件系统过滤器驱动 …")
    raw["filters"] = get_filters()
    P("扫描隐蔽启动点（IFEO / Winlogon / AppInit / LSP）…")
    try:
        raw["extra"] = enum_extra_autostarts()
    except Exception as e:
        log_line("extra autostarts failed: %r" % (e,))
        raw["extra"] = []
    P("比对流氓软件 / 全家桶特征库 …")
    try:
        raw["adware"] = adware_scan(raw)
    except Exception as e:
        log_line("adware scan failed: %r" % (e,))
        raw["adware"] = {"items": [], "families": {}, "count": 0}

    P("等待系统信息 / 事件日志返回 …")
    raw["sys"] = wait_sys()
    raw["events"] = wait_evt()
    if stopped():
        raise ScanCancelled()
    P("采集完成，开始分析 …")
    return raw


# --------------------------------------------------------------------------
# analyze：规则引擎
# --------------------------------------------------------------------------

def _is_updater_like(item):
    s = (item.get("name", "") + " " + item.get("cmd", ""))
    return re.search(r"(?i)(updater|update|autolaunch|cleanup|clean-up|预加载|自动更新|自动升级|updatecheck)", s) is not None


def _is_360_residue(s):
    n = s["name"].lower()
    return n.startswith("360") or n in ("bapidrv",)


def _extract_timeout_names(scm):
    """从 7009 事件里提取'等待连接超时'的服务名 -> 次数。"""
    out = {}
    for e in scm or []:
        if e.get("id") != 7009:
            continue
        msg = e.get("msg", "")
        m = re.search(r"(?:等待\s*)(.+?)(?:服务| 服务)的?连接超时", msg)
        if not m:
            m = re.search(r"(?i)waiting for the (.+?) service", msg)
        if m:
            n = m.group(1).strip()
            out[n] = out.get(n, 0) + 1
    return out


# --------------------------------------------------------------------------
# 延迟启动：设置（延迟时长）/ 候选筛选 / 计划任务创建
# --------------------------------------------------------------------------

DEFAULT_DELAY_SEC = 60
DELAY_CHOICES = [(30, "30 秒"), (60, "1 分钟"), (120, "2 分钟"),
                 (180, "3 分钟"), (300, "5 分钟")]


def _load_settings():
    try:
        with open(SETTINGS_PATH, "r", encoding="utf-8") as fp:
            d = json.load(fp)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def _save_settings(d):
    try:
        with open(SETTINGS_PATH, "w", encoding="utf-8") as fp:
            json.dump(d, fp, ensure_ascii=False, indent=1)
        return True
    except Exception as e:
        log_line("settings save failed: %r" % (e,))
        return False


def get_delay_seconds():
    """当前「延迟启动」使用的延迟秒数（默认 60，范围 5~600）。"""
    try:
        v = int(_load_settings().get("delay_seconds", DEFAULT_DELAY_SEC))
    except Exception:
        v = DEFAULT_DELAY_SEC
    return max(5, min(600, v))


def set_delay_seconds(sec):
    d = _load_settings()
    d["delay_seconds"] = max(5, min(600, int(sec)))
    return _save_settings(d)


def get_setting(key, default=None):
    """读任意设置项（与延迟时长、AI 配置同一个 _settings.json）。"""
    d = _load_settings()
    v = d.get(key, default)
    return default if v is None else v


def set_setting(key, value):
    d = _load_settings()
    d[key] = value
    return _save_settings(d)


def delay_text(sec=None):
    sec = get_delay_seconds() if sec is None else int(sec)
    if sec <= 0:
        return "无延迟"
    if sec >= 60 and sec % 60 == 0:
        return "%d 分钟" % (sec // 60)
    return "%d 秒" % sec


def _iso_delay_to_sec(s):
    """解析任务计划 XML 里的 ISO8601 时长（PT1M / PT30S / PT1M30S / PT1H）。"""
    if not s:
        return 0
    m = re.match(r"(?i)^P(?:(\d+)D)?T?(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?$", str(s).strip())
    if not m:
        return 0
    d, h, mi, se = (int(x or 0) for x in m.groups())
    return d * 86400 + h * 3600 + mi * 60 + se


TASKS_DIR = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Tasks")
DELAY_TASK_PREFIX = "BootDoctor-Delay-"


def existing_delay_tasks():
    """列出本工具已创建的延迟任务（直接读 C:\\Windows\\System32\\Tasks 下的 XML 文件）。

    返回：[{task, name, exe, args, delay(秒), enabled}]
    """
    out = []
    try:
        names = [n for n in os.listdir(TASKS_DIR) if n.startswith(DELAY_TASK_PREFIX)]
    except OSError:
        return out
    for n in sorted(names):
        p = os.path.join(TASKS_DIR, n)
        try:
            with open(p, "rb") as fp:
                raw = fp.read()
        except OSError:
            continue
        try:
            txt = raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") \
                else raw.decode("utf-8", "ignore")
        except Exception:
            continue
        m_delay = re.search(r"<Delay>([^<]*)</Delay>", txt)
        m_cmd = re.search(r"<Command>([^<]*)</Command>", txt)
        m_arg = re.search(r"<Arguments>([^<]*)</Arguments>", txt)
        # 任务是否启用：Disable-ScheduledTask 写的是 <Settings><Enabled>false</Enabled>，
        # 同时把触发器的 <Enabled> 整个去掉；只看 Triggers 会永远读到「启用」。
        enabled = True
        m_set = re.search(r"<Settings>.*?</Settings>", txt, re.S | re.I)
        if m_set:
            m_e = re.search(r"<Enabled>(true|false)</Enabled>", m_set.group(0), re.I)
            if m_e:
                enabled = (m_e.group(1).lower() == "true")
        m_trg = re.search(r"<Triggers>.*?</Triggers>", txt, re.S | re.I)
        if m_trg:
            m_e2 = re.search(r"<Enabled>(true|false)</Enabled>", m_trg.group(0), re.I)
            if m_e2 and m_e2.group(1).lower() == "false":
                enabled = False
        out.append({
            "task": n,
            "name": n[len(DELAY_TASK_PREFIX):],
            "exe": (m_cmd.group(1) if m_cmd else ""),
            "args": (m_arg.group(1) if m_arg else ""),
            "delay": _iso_delay_to_sec(m_delay.group(1) if m_delay else ""),
            "enabled": enabled,
        })
    return out


DELAY_SVC_EXCLUDE = {
    "HipsDaemon", "Adguard Service", "Clash Core Service",
    "NvContainerLocalSystem", "NVDisplay.ContainerLocalSystem", "nvagent",
    "vmms", "vmcompute", "WSLService", "HvHost", "VBoxSDS",
    "CoworkVMService", "CodexSandboxService.OpenAI.Codex",
}
DELAY_SVC_EXCLUDE_RE = re.compile(
    r"(?i)(anti.?cheat|defender|firewall|mysql|mariadb|postgre|mongo|redis|\bsql\b|oracle|vmware|virtualbox|licen|sentinel|flexnet|gaming)")

_DELAY_ITEM_EXCLUDE_RE = re.compile(
    r"(?i)(输入法|input|weasel|rime|(^|[^a-z])ime([^a-z]|$)|licen|chaos|ccb|flexnet|sentinel|sysdiag|huorong)")


def _svc_delay_candidates(svcs):
    """可改为『延迟启动』的第三方自动服务（排除安全 / 网络 / 虚拟化 / 数据库类）。"""
    root = os.environ.get("SystemRoot", r"C:\Windows").lower() + "\\"
    out = []
    for s in svcs:
        if s.get("start") != 2 or int(s.get("delayed") or 0) == 1:
            continue
        if s["name"] in DELAY_SVC_EXCLUDE or DELAY_SVC_EXCLUDE_RE.search(s["name"]):
            continue
        rp = resolve_image_path(s["image"])
        if not rp or rp.lower().startswith(root):
            continue
        out.append(s)
    return out


def split_cmdline(cmd):
    """拆分启动项命令 -> (exe路径, 参数)。支持带引号 / 不带引号 / 含环境变量。"""
    cmd = (cmd or "").strip()
    if not cmd:
        return "", ""
    if cmd.startswith('"'):
        end = cmd.find('"', 1)
        if end > 0:
            return cmd[1:end], cmd[end + 1:].strip()
    exp = os.path.expandvars(cmd)
    positions = [m.start() for m in re.finditer(r"(?i)\.(?:exe|com|bat|cmd)", exp)]
    for pos in reversed(positions):
        cand = exp[:pos + 4]
        if os.path.exists(cand):
            return cand, exp[pos + 4:].strip()
    i = exp.find(" ")
    if i > 0:
        return exp[:i], exp[i + 1:].strip()
    return exp, ""


def cmd_argv(cmd):
    """把命令行拆成 argv（给 Popen 用，别走 shell=True）。

    卸载命令来自注册表 UninstallString，是第三方软件写的字符串。交给 cmd.exe 解析
    等于白送一个注入面；拆成参数列表直接 CreateProcess 更干净。
    """
    cmd = (cmd or "").strip()
    if not cmd:
        return []
    exe, rest = split_cmdline(cmd)
    if not exe:
        return []
    argv = [os.path.expandvars(exe.strip().strip('"'))]
    rest = (rest or "").strip()
    if rest:
        try:
            toks = shlex.split(rest, posix=False)
        except ValueError:
            toks = [rest]
        for tok in toks:
            tok = tok.strip()
            if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in "\"'":
                tok = tok[1:-1]
            if tok:
                argv.append(tok)
    return argv


def _task_name_for(name):
    return "BootDoctor-Delay-" + re.sub(r'[\\/:*?"<>|]', "_", str(name))[:120]


# --------------------------------------------------------------------------
# 应用识别：把「自启项 / 服务 / 延迟任务」还原成"这到底是哪个程序"
# --------------------------------------------------------------------------

try:
    from ctypes import wintypes as _wt

    _VER = ctypes.WinDLL("version", use_last_error=True)
    _VER.GetFileVersionInfoSizeW.argtypes = [_wt.LPCWSTR, ctypes.POINTER(_wt.DWORD)]
    _VER.GetFileVersionInfoSizeW.restype = _wt.DWORD
    _VER.GetFileVersionInfoW.argtypes = [_wt.LPCWSTR, _wt.DWORD, _wt.DWORD, ctypes.c_void_p]
    _VER.GetFileVersionInfoW.restype = _wt.BOOL
    _VER.VerQueryValueW.argtypes = [ctypes.c_void_p, _wt.LPCWSTR,
                                    ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(_wt.UINT)]
    _VER.VerQueryValueW.restype = _wt.BOOL
except Exception:                                    # pragma: no cover
    _VER = None


def _file_version_info(path):
    """读 exe 的版本资源 -> {FileDescription, CompanyName, ProductName, FileVersion, ...}。"""
    if _VER is None or not path:
        return {}
    try:
        dummy = _wt.DWORD(0)
        size = _VER.GetFileVersionInfoSizeW(str(path), ctypes.byref(dummy))
        if not size:
            return {}
        buf = ctypes.create_string_buffer(int(size))
        if not _VER.GetFileVersionInfoW(str(path), 0, int(size), buf):
            return {}
        ptr, ln = ctypes.c_void_p(), _wt.UINT(0)
        langs = [(0x0409, 0x04B0)]
        if _VER.VerQueryValueW(buf, "\\VarFileInfo\\Translation",
                               ctypes.byref(ptr), ctypes.byref(ln)) and ln.value >= 4:
            arr = ctypes.cast(ptr, ctypes.POINTER(_wt.WORD))
            n = min(ln.value // 4, 4)
            langs = [(arr[i * 2], arr[i * 2 + 1]) for i in range(n)]
        out = {}
        for key in ("FileDescription", "CompanyName", "ProductName",
                    "FileVersion", "OriginalFilename", "LegalCopyright"):
            for lang, cp in langs:
                q = "\\StringFileInfo\\%04x%04x\\%s" % (lang, cp, key)
                if _VER.VerQueryValueW(buf, q, ctypes.byref(ptr), ctypes.byref(ln)) and ln.value:
                    s = ctypes.wstring_at(ptr, int(ln.value)).split("\x00")[0].strip()
                    if s:
                        out[key] = s
                        break
        return out
    except Exception:
        return {}


_LNK_CACHE = {}


def resolve_shortcuts_bulk(lnks):
    """一次 PowerShell 批量解析快捷方式。

    逐条解析要 250ms/条（每次起一个 powershell 进程），6 个启动快捷方式就是 1.5 秒，
    体检里最大的冤枉开销之一。这里把待解析清单塞进环境变量，一次进程全解掉。
    """
    todo, seen = [], set()
    for p in lnks or []:
        p = (p or "").strip().strip('"')
        if not p or not p.lower().endswith(".lnk") or p in _LNK_CACHE:
            continue
        if not os.path.isfile(p) or p.lower() in seen:
            continue
        seen.add(p.lower())
        todo.append(p)
    if not todo:
        return 0
    env = dict(os.environ)
    env["BD_LNKS"] = "\n".join(todo)
    ps = ("$sh=New-Object -ComObject WScript.Shell;"
          "foreach($p in ($env:BD_LNKS -split \"`n\")){"
          " if(-not $p){continue};"
          " try{$s=$sh.CreateShortcut($p);"
          " Write-Output ($p+[char]9+$s.TargetPath+[char]9+$s.Arguments)}"
          " catch{Write-Output ($p+[char]9+[char]9)}}")
    out = run_ps(ps, timeout=max(30, 5 * len(todo)), env=env) or ""
    got = 0
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        src = parts[0].strip()
        tgt = parts[1].strip()
        arg = parts[2].strip() if len(parts) > 2 else ""
        if not src:
            continue
        _LNK_CACHE[src] = (tgt, arg)
        if not tgt:
            log_line("resolve_shortcut failed: %s" % src)
        got += 1
    return got


def resolve_shortcut(lnk):
    """解析 .lnk -> (目标 exe, 参数)。失败返回 ("", "")。结果缓存。"""
    lnk = (lnk or "").strip().strip('"')
    if not lnk.lower().endswith(".lnk") or not os.path.isfile(lnk):
        return "", ""
    if lnk not in _LNK_CACHE:
        resolve_shortcuts_bulk([lnk])
    return _LNK_CACHE.get(lnk, ("", ""))


_APP_CACHE = {}

# 这些"宿主"程序本身说明不了装的什么软件，真正有价值的是它加载的 dll / 脚本
_GENERIC_HOST = {"regsvr32.exe", "rundll32.exe", "cmd.exe", "powershell.exe",
                 "wscript.exe", "cscript.exe", "mshta.exe", "svchost.exe"}


def _app_paths_registry(name):
    """查 App Paths 注册表（Windows 解析裸文件名的官方位置之一）。"""
    sub = r"Software\Microsoft\Windows\CurrentVersion\App Paths\\" + name
    for hive, s in ((HKCU, sub),
                    (HKLM, sub),
                    (HKLM, r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\App Paths\\" + name)):
        try:
            with winreg.OpenKey(hive, s, 0, winreg.KEY_READ) as k:
                v = winreg.QueryValueEx(k, None)[0]
            if isinstance(v, str) and v.strip():
                p = os.path.expandvars(v.strip().strip('"'))
                if os.path.isfile(p):
                    return p
        except OSError:
            continue
    return ""


def resolve_bare_exe(name):
    """把只有文件名的命令（如 CTHELPER.EXE）解析成完整路径。

    顺序按 Windows 的规则来：App Paths -> System32/SysWOW64/Windows -> PATH。
    """
    nm = (name or "").strip().strip('"')
    if not nm or os.path.isabs(nm) or os.path.dirname(nm):
        return ""
    hit = _app_paths_registry(nm)
    if hit:
        return hit
    sysroot = os.environ.get("SystemRoot", r"C:\Windows")
    for d in (sysroot, os.path.join(sysroot, "System32"),
              os.path.join(sysroot, "SysWOW64"),
              os.path.join(sysroot, "Sysnative")):
        for cand in (nm, nm + ".exe"):
            p = os.path.join(d, cand)
            if os.path.isfile(p):
                return p
    for d in (os.environ.get("PATH") or "").split(os.pathsep):
        d = d.strip().strip('"')
        if not d or not os.path.isdir(d):
            continue
        for cand in (nm, nm + ".exe"):
            p = os.path.join(d, cand)
            if os.path.isfile(p):
                return p
    return ""


_EXE_SEARCH_CACHE = {}
_SEARCH_SKIP = {"$recycle.bin", "windows", "windows.old", "node_modules", "cache",
                "caches", "temp", "tmp", "logs", "installer", "backup"}


def search_exe_file(name, max_depth=3, budget=0.6):
    """在常见安装目录里限量搜一个 exe（App Paths / PATH 都查不到时的兜底）。

    只搜到固定深度、带时间上限，结果（含未找到）会缓存，避免反复拖慢体检。
    预算别调大：实测 1.6s 的预算基本都会被吃满，而命中率极低。
    """
    nm = os.path.basename((name or "").strip().strip('"').replace("/", "\\"))
    if not nm:
        return ""
    low = nm.lower()
    if low in _EXE_SEARCH_CACHE:
        return _EXE_SEARCH_CACHE[low]
    env = os.environ
    roots = [env.get("ProgramFiles"), env.get("ProgramFiles(x86)"),
             os.path.join(env.get("LOCALAPPDATA", ""), "Programs"),
             env.get("ProgramData"), env.get("APPDATA")]
    t0 = time.time()
    hit = ""
    for root in roots:
        if not root or not os.path.isdir(root):
            continue
        base_depth = root.rstrip("\\/").count(os.sep)
        for dirpath, dirnames, filenames in os.walk(root):
            if time.time() - t0 > budget:
                dirnames[:] = []
                break
            depth = dirpath.count(os.sep) - base_depth
            if depth >= max_depth:
                dirnames[:] = []
            dirnames[:] = [d for d in dirnames
                           if d.lower() not in _SEARCH_SKIP and not d.startswith(".")]
            for fn in filenames:
                if fn.lower() == low:
                    hit = os.path.join(dirpath, fn)
                    break
            if hit:
                break
        if hit:
            break
    _EXE_SEARCH_CACHE[low] = hit
    if hit:
        log_line("exe resolved by search: %s -> %s" % (nm, hit))
    return hit


def describe_app(exe, args=""):
    """把启动命令 / exe 路径解析成应用信息。

    返回 {} 或 {cmd, path, args, exists, size, mtime, desc, company, product, version, orig}
    支持：带引号 / 不带引号的完整命令行、.lnk 快捷方式、含 %VAR% 的路径。
    """
    raw = (exe or "").strip()
    if not raw:
        return {}
    if args:
        path, rest = raw, args
    else:
        cand = os.path.expandvars(raw.strip('"'))
        if os.path.isfile(cand):
            path, rest = cand, ""
        else:
            path, rest = split_cmdline(raw)
            if not path:
                path, rest = raw, ""
    path = os.path.expandvars(path.strip().strip('"'))
    if path and not os.path.dirname(path):
        hit = resolve_bare_exe(path)
        if hit:
            path = hit
    if (path and not os.path.isfile(path)
            and os.path.splitext(path)[1].lower() in (".exe", ".com")
            and not path.lower().endswith(".lnk")):
        # 原路径失效：按文件名在常见安装目录兜底找一个（只在明确是 exe 时做）
        alt = search_exe_file(path)
        if alt:
            path = alt
    if path.lower().endswith(".lnk"):
        tgt, targs = resolve_shortcut(path)
        if tgt:
            path = tgt
            rest = (" ".join(x for x in (targs, rest) if x)).strip()
    try:
        st = os.stat(path)
        exists, size, mtime = True, int(st.st_size), int(st.st_mtime)
    except OSError:
        exists, size, mtime = False, 0, 0
    key = path.lower()
    c = _APP_CACHE.get(key)
    if c and c.get("_mtime") == mtime and c.get("_exists") == exists:
        info = dict(c)
        info["args"] = rest
        return info
    vi = _file_version_info(path) if exists else {}
    info = {
        "cmd": raw, "path": path, "args": rest, "exists": exists,
        "size": size, "mtime": mtime,
        "desc": vi.get("FileDescription", ""),
        "company": vi.get("CompanyName", ""),
        "product": vi.get("ProductName", ""),
        "version": vi.get("FileVersion", ""),
        "orig": vi.get("OriginalFilename", ""),
        "_mtime": mtime, "_exists": exists,
    }
    if not exists:
        info["siblings"] = _sibling_exes(path)
    _APP_CACHE[key] = info
    return dict(info)


def _sibling_exes(path):
    """目标文件不见了：看看同目录下现存的 exe，帮用户判断是不是改名/卸载残留。"""
    folder = os.path.dirname(path or "")
    if not folder or not os.path.isdir(folder):
        return []
    try:
        names = [n for n in os.listdir(folder) if n.lower().endswith(".exe")]
    except OSError:
        return []
    return sorted(names)[:6]


# --------------------------------------------------------------------------
# 数字签名（AutoRuns 同款列：已签名 / 目录签名 / 未签名 / 签名无效）
#
# 两级判断：
#   1) 内嵌 Authenticode  -> WinVerifyTrust（离线，不联网吊销检查）
#   2) 无内嵌但被系统目录签 -> CryptCATAdmin 系列 API 查 catalog 命中
# 目的：让用户一眼看出「这个自启项的程序是谁签的、有没有被动过」。
# --------------------------------------------------------------------------

_SIG_CACHE = {}

_WTD_UI_NONE = 2
_WTD_REVOKE_NONE = 0
_WTD_CHOICE_FILE = 1
_WTD_STATEACTION_VERIFY = 1
_WTD_STATEACTION_CLOSE = 2
_WTD_SAFER_FLAG = 0x100
_WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000
_WINTRUST_ACTION_GENERIC_VERIFY_V2 = "{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}"

_TRUST_E_NOSIGNATURE = 0x800B0100
_TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0101
_TRUST_E_SUBJECT_NOT_TRUSTED = 0x800B0102
_TRUST_E_BAD_DIGEST = 0x80096010
_TRUST_E_EXPLICIT_DISTRUST = 0x800B0111
_CERT_E_UNTRUSTEDROOT = 0x800B0109
_CERT_E_CHAINING = 0x800B010A

_sig_ready = False


class _GUID(ctypes.Structure):
    _fields_ = [("Data1", ctypes.c_ulong), ("Data2", ctypes.c_ushort),
                ("Data3", ctypes.c_ushort), ("Data4", ctypes.c_ubyte * 8)]


class _WT_FILE_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", ctypes.c_ulong), ("pcwszFilePath", ctypes.c_wchar_p),
                ("hFile", ctypes.c_void_p), ("pgKnownSubject", ctypes.POINTER(_GUID))]


class _WT_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", ctypes.c_ulong), ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p), ("dwUIChoice", ctypes.c_ulong),
        ("fdwRevocationChecks", ctypes.c_ulong), ("dwUnionChoice", ctypes.c_ulong),
        ("pFile", ctypes.POINTER(_WT_FILE_INFO)), ("dwStateAction", ctypes.c_ulong),
        ("hWVTStateData", ctypes.c_void_p), ("pwszURLReference", ctypes.c_wchar_p),
        ("dwProvFlags", ctypes.c_ulong), ("dwUIContext", ctypes.c_ulong),
        ("pSignatureSettings", ctypes.c_void_p),
    ]


class _CATALOG_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", ctypes.c_ulong), ("wszCatalogFile", ctypes.c_wchar * 260)]


def _init_sig_api():
    """显式声明 argtypes/restype：64 位下不声明会截断指针（实测会 AV 崩）。"""
    global _sig_ready
    if _sig_ready:
        return True
    try:
        k32 = ctypes.windll.kernel32
        wv = ctypes.windll.wintrust
        k32.CreateFileW.restype = ctypes.c_void_p
        k32.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_ulong,
                                    ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong,
                                    ctypes.c_void_p]
        k32.CloseHandle.argtypes = [ctypes.c_void_p]
        wv.WinVerifyTrust.restype = ctypes.c_long
        wv.WinVerifyTrust.argtypes = [ctypes.c_void_p, ctypes.POINTER(_GUID),
                                      ctypes.c_void_p]
        wv.CryptCATAdminAcquireContext2.restype = ctypes.c_int
        wv.CryptCATAdminAcquireContext2.argtypes = [
            ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, ctypes.c_wchar_p,
            ctypes.c_wchar_p, ctypes.c_ulong]
        wv.CryptCATAdminCalcHashFromFileHandle2.restype = ctypes.c_int
        wv.CryptCATAdminCalcHashFromFileHandle2.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong),
            ctypes.c_void_p, ctypes.c_ulong]
        wv.CryptCATAdminEnumCatalogFromHash.restype = ctypes.c_void_p
        wv.CryptCATAdminEnumCatalogFromHash.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong,
            ctypes.c_void_p]
        wv.CryptCATCatalogInfoFromContext.restype = ctypes.c_int
        wv.CryptCATCatalogInfoFromContext.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(_CATALOG_INFO), ctypes.c_ulong]
        wv.CryptCATAdminReleaseCatalogContext.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong]
        wv.CryptCATAdminReleaseContext.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
        _sig_ready = True
    except Exception as e:
        log_line("sig api init failed: %r" % (e,))
        _sig_ready = False
    return _sig_ready


def _sig_embedded(path):
    """内嵌签名状态：valid / invalid / none。"""
    wv = ctypes.windll.wintrust
    fi = _WT_FILE_INFO()
    fi.cbStruct = ctypes.sizeof(_WT_FILE_INFO)
    fi.pcwszFilePath = path
    fi.hFile = None
    fi.pgKnownSubject = None
    d = _WT_DATA()
    d.cbStruct = ctypes.sizeof(_WT_DATA)
    d.dwUIChoice = _WTD_UI_NONE
    d.fdwRevocationChecks = _WTD_REVOKE_NONE
    d.dwUnionChoice = _WTD_CHOICE_FILE
    d.pFile = ctypes.pointer(fi)
    d.dwStateAction = _WTD_STATEACTION_VERIFY
    d.dwProvFlags = _WTD_SAFER_FLAG | _WTD_CACHE_ONLY_URL_RETRIEVAL
    g = _GUID()
    ctypes.windll.ole32.CLSIDFromString(
        ctypes.c_wchar_p(_WINTRUST_ACTION_GENERIC_VERIFY_V2), ctypes.byref(g))
    rc = wv.WinVerifyTrust(None, ctypes.byref(g), ctypes.byref(d)) & 0xFFFFFFFF
    d.dwStateAction = _WTD_STATEACTION_CLOSE
    wv.WinVerifyTrust(None, ctypes.byref(g), ctypes.byref(d))
    if rc == 0:
        return "valid", rc
    if rc in (_TRUST_E_NOSIGNATURE, _TRUST_E_SUBJECT_FORM_UNKNOWN):
        return "none", rc
    return "invalid", rc


def _sig_catalog_path(path):
    """查 Windows 目录签名（CatRoot 下的 .cat）：命中返回 .cat 路径，否则 ''。"""
    wv = ctypes.windll.wintrust
    k32 = ctypes.windll.kernel32
    h_admin = ctypes.c_void_p()
    if not wv.CryptCATAdminAcquireContext2(
            ctypes.byref(h_admin), None, ctypes.c_wchar_p("SHA256"), None, 0):
        return ""
    h_file = k32.CreateFileW(path, 0x80000000, 1, None, 3, 0x80, None)
    if not h_file or h_file == ctypes.c_void_p(-1).value:
        wv.CryptCATAdminReleaseContext(h_admin, 0)
        return ""
    try:
        n = ctypes.c_ulong(0)
        if not wv.CryptCATAdminCalcHashFromFileHandle2(
                h_admin, h_file, ctypes.byref(n), None, 0) or not n.value:
            return ""
        buf = (ctypes.c_ubyte * n.value)()
        if not wv.CryptCATAdminCalcHashFromFileHandle2(
                h_admin, h_file, ctypes.byref(n), buf, 0):
            return ""
    finally:
        k32.CloseHandle(h_file)
    info = wv.CryptCATAdminEnumCatalogFromHash(h_admin, buf, n.value, 0, None)
    out = ""
    if info:
        ci = _CATALOG_INFO()
        ci.cbStruct = ctypes.sizeof(_CATALOG_INFO)
        if wv.CryptCATCatalogInfoFromContext(info, ctypes.byref(ci), 0):
            out = ci.wszCatalogFile
        wv.CryptCATAdminReleaseCatalogContext(h_admin, info, 0)
    wv.CryptCATAdminReleaseContext(h_admin, 0)
    return out or ""


def app_signature(info):
    """给一条应用信息算签名状态，带缓存（按 路径+大小+修改时间 失效）。

    返回 {state, label, detail, cat}
      state: valid / catalog / unsigned / invalid / missing / unknown
    """
    info = info or {}
    path = info.get("path") or ""
    if not path:
        return {"state": "unknown", "label": "", "detail": "", "cat": ""}
    if not info.get("exists", os.path.isfile(path)):
        return {"state": "missing", "label": "文件不存在",
                "detail": "磁盘上找不到这个文件，多半是卸载/改名后的残留。", "cat": ""}
    if not path.lower().endswith((".exe", ".dll", ".sys", ".ocx", ".cpl", ".msi")):
        return {"state": "unknown", "label": "—", "detail": "该类型不做签名校验。", "cat": ""}
    key = "%s|%s|%s" % (path.lower(), info.get("size", 0), info.get("mtime", 0))
    hit = _SIG_CACHE.get(key)
    if hit:
        return hit
    if not _init_sig_api():
        return {"state": "unknown", "label": "—", "detail": "系统 API 不可用。", "cat": ""}
    try:
        st, rc = _sig_embedded(path)
        if st == "valid":
            res = {"state": "valid", "label": "已签名",
                   "detail": "文件带完整数字签名，且校验通过（文件未被改动）。", "cat": ""}
        elif st == "invalid":
            why = {
                _TRUST_E_BAD_DIGEST: "签名与文件内容对不上——文件被改过，或签名已损坏。",
                _TRUST_E_EXPLICIT_DISTRUST: "该证书已被系统明确吊销。",
                _CERT_E_UNTRUSTEDROOT: "签名证书的根证书不在系统信任列表里。",
                _CERT_E_CHAINING: "证书链不完整，无法建到受信任的根。",
                _TRUST_E_SUBJECT_NOT_TRUSTED: "签名主体不被信任。",
            }.get(rc, "签名校验未通过（错误码 0x%08X）。" % rc)
            res = {"state": "invalid", "label": "签名无效", "detail": why, "cat": ""}
        else:
            cat = _sig_catalog_path(path)
            if cat:
                res = {"state": "catalog", "label": "目录签名",
                       "detail": "由系统目录签名（CatRoot）覆盖：\n%s" % cat, "cat": cat}
            else:
                res = {"state": "unsigned", "label": "未签名",
                       "detail": "既没有内嵌签名，也不在任何系统目录签名里。"
                                 "自研/绿色软件常见，但来源不明的自启项要当心。", "cat": ""}
    except Exception as e:
        res = {"state": "unknown", "label": "—", "detail": "校验失败：%r" % (e,), "cat": ""}
    _SIG_CACHE[key] = res
    return res


def is_microsoft(info):
    """粗判这一项是否属于微软/Windows 自家组件（用于「只看第三方」过滤）。"""
    info = info or {}
    comp = (info.get("company") or "").lower()
    if "microsoft" in comp or "windows" == comp:
        return True
    path = (info.get("path") or "").lower()
    win = os.environ.get("SystemRoot", r"C:\Windows").lower()
    if path.startswith(win + os.sep):
        # 系统目录里也有第三方驱动，公司名有值时不按路径算
        return not comp
    return False


def _host_target(info):
    """regsvr32 / rundll32 这类宿主，从参数里挑出真正被加载的文件。"""
    args = (info or {}).get("args") or ""
    if not args:
        return ""
    for tok in re.findall(r'"[^"]+"|\S+', args):
        t = tok.strip('"')
        if not t or t.startswith(("/", "-")):
            continue
        if re.search(r"(?i)\.(dll|exe|ocx|ax|cpl|js|vbs|ps1|bat|cmd)$", t):
            return t
    return ""


def app_label(info):
    """一行式应用名（给列表列用）：优先「文件说明 · 文件名」。"""
    if not info:
        return ""
    path = info.get("path") or info.get("cmd") or ""
    base = os.path.basename(str(path).rstrip("\\/")) if path else ""
    if not info.get("exists"):
        return "⚠ 找不到文件：%s" % (base or path or "?")
    if base.lower() in _GENERIC_HOST:
        tgt = _host_target(info)
        if tgt:
            return "%s → %s" % (base, os.path.basename(tgt.replace("/", "\\")))
    desc = (info.get("desc") or "").strip()
    stem = os.path.splitext(base)[0]
    if desc and desc.lower() != stem.lower():
        return "%s · %s" % (desc, base)
    return base or path


def app_detail_text(info):
    """多行应用详情（报告 / 弹窗共用）。"""
    if not info:
        return "（无应用信息）"
    rows = [
        ("应用名称", app_label(info)),
        ("文件路径", info.get("path") or "?"),
        ("文件说明", info.get("desc") or ""),
        ("公司", info.get("company") or ""),
        ("产品", info.get("product") or ""),
        ("版本", info.get("version") or ""),
        ("启动参数", info.get("args") or ""),
        ("文件状态", "存在" if info.get("exists") else "不存在（可能是软件已卸载 / 改名后的残留）"),
    ]
    txt = "\n".join("%s：%s" % (k, v) for k, v in rows if v)
    sib = info.get("siblings") or []
    if sib and not info.get("exists"):
        txt += "\n同目录下现有程序：%s" % "、".join(sib[:5])
    return txt


def find_startup_entry(name, items=None):
    """按名字在当前自启项里找一条（Run 值 / 启动文件夹快捷方式，忽略大小写与 .lnk 后缀）。"""
    if not name:
        return None
    items = items if items is not None else enum_startup_items()
    low = str(name).lower()
    low_stem = os.path.splitext(low)[0]
    for it in items:
        n = str(it.get("name", "")).lower()
        if n == low:
            return it
    for it in items:
        if os.path.splitext(str(it.get("name", "")).lower())[0] == low_stem:
            return it
    return None


# --------------------------------------------------------------------------
# AI 助手：本地网关（OpenAI 兼容接口），帮忙判断"这程序是什么、能不能关"
# --------------------------------------------------------------------------

AI_BASE_DEFAULT = "http://127.0.0.1:3425"
AI_MODEL_DEFAULT = "workbuddy-ai/hy4flash-free"

AI_VERDICT_CN = {"keep": "建议保留", "delay": "建议延迟", "disable": "建议禁止"}
AI_VERDICT_COLOR = {"keep": "#2f9e63", "delay": "#df8a1a", "disable": "#d64545"}

AI_SYSTEM = (
    "你是 Windows 开机启动项顾问，服务对象是不懂技术的普通用户。"
    "用户会给你一份自启项清单（每项带唯一 id，以及名字 / 应用说明 / 公司 / 路径 / 文件是否存在 / 当前状态）。"
    "请逐项判断开机时是否必须启动，并按普通用户视角给建议：\n"
    "· keep = 建议保留开机启动（安全软件、输入法、声卡/触控板/显卡驱动、云同步、远程控制等）\n"
    "· delay = 可以延迟启动（不着急但要常驻：网盘、更新器、启动器、小组件）\n"
    "· disable = 建议禁止开机启动（只为托盘/加速/统计/推广存在，或文件已不存在=卸载残留）\n"
    "只输出一个 JSON 数组，不要 markdown 代码块，不要多余文字。每个元素格式：\n"
    '{"id":"原样返回的 id","name":"原样返回的 name","verdict":"keep|delay|disable",'
    '"reason":"不超过 25 字的中文理由","risk":"低|中|高"}\n'
    "id 必须原样照抄，不能改写、不能省略——同名条目很多，只能靠 id 区分。"
    "risk 表示关闭它的风险程度。拿不准时选 keep 并把 risk 标为中。"
)


def get_ai_cfg():
    d = _load_settings()
    base = str(d.get("ai_base") or AI_BASE_DEFAULT).rstrip("/")
    model = str(d.get("ai_model") or AI_MODEL_DEFAULT)
    return base, model


def set_ai_cfg(base=None, model=None):
    d = _load_settings()
    if base:
        d["ai_base"] = base
    if model:
        d["ai_model"] = model
    return _save_settings(d)


def ai_chat(messages, timeout=120, max_tokens=1600, temperature=0.3, model=None):
    """调用本地 OpenAI 兼容接口 -> (文本, 错误信息)。"""
    base, default_model = get_ai_cfg()
    url = base + "/v1/chat/completions"
    payload = {
        "model": model or default_model,
        "messages": messages,
        "max_tokens": int(max_tokens),
        "temperature": float(temperature),
        "reasoning": {"effort": "low"},   # 少想一点，快一点
    }
    req = urllib.request.Request(
        url, data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return "", "AI 接口返回 %s：%s" % (e.code, (e.read() or b"").decode("utf-8", "replace")[:200])
    except urllib.error.URLError as e:
        return "", ("连不上本地 AI 网关（%s）。请确认 %s 在运行，"
                    "或在 _settings.json 里改 ai_base。" % (e.reason, base))
    except Exception as e:
        return "", "AI 调用失败：%r" % (e,)
    try:
        msg = (data.get("choices") or [{}])[0].get("message") or {}
    except Exception:
        return "", "AI 返回格式无法识别"
    txt = (msg.get("content") or "").strip()
    if not txt:
        txt = (msg.get("reasoning_content") or "").strip()
    if not txt:
        return "", "AI 没有给出内容（可能被长度截断），请重试"
    log_line("ai_chat ok: %d chars, usage=%s" % (len(txt), data.get("usage")))
    return txt, ""


def is_local_ai(base):
    """AI 接口是不是本机回环地址。非本机时界面要提醒用户数据会离开这台电脑。"""
    try:
        import urllib.parse
        host = (urllib.parse.urlparse(str(base or "")).hostname or "").lower()
    except Exception:
        return True
    return host in ("127.0.0.1", "localhost", "::1", "0.0.0.0", "")


def _ai_mask_path(path):
    """发给 AI 的路径只保留「上一级目录 + 文件名」。

    完整路径会泄露用户名、项目目录、内网共享盘名；判断"这是什么软件"只需要
    最后两级就够。上一级还保留，是因为很多全家桶靠目录名认出来（\360bizhi\）。
    """
    p = str(path or "").strip().strip('"')
    if not p:
        return ""
    parts = [x for x in re.split(r"[\\/]+", p) if x]
    if len(parts) <= 2:
        return p
    return os.path.join(parts[-2], parts[-1])


def _ai_item_row(f):
    app = f.get("app") or {}
    return {
        "name": f.get("name") or f.get("id"),
        "app": app_label(app),
        "company": app.get("company") or "",
        "path": _ai_mask_path(app.get("path") or ""),
        "exists": bool(app.get("exists")),
        "state": f.get("short") or "",
    }


def _parse_ai_json(txt):
    """从模型输出里抠出 JSON 数组（容忍 ```json 包裹 / 前后废话）。"""
    if not txt:
        return []
    t = txt.strip()
    if "```" in t:
        parts = t.split("```")
        for p in parts:
            p = p.strip()
            if p.startswith("json"):
                p = p[4:].strip()
            if p.startswith("[") or p.startswith("{"):
                t = p
                break
    i, j = t.find("["), t.rfind("]")
    if i >= 0 and j > i:
        try:
            v = json.loads(t[i:j + 1])
            if isinstance(v, list):
                return v
            if isinstance(v, dict):
                return [v]
        except Exception:
            pass
    # 逐对象兜底
    out = []
    for m in re.finditer(r'\{[^{}]*\}', t):
        try:
            out.append(json.loads(m.group(0)))
        except Exception:
            continue
    return out


def ai_advise(findings, timeout=180, progress=None, chunk=8):
    """批量判断：返回 ({finding_id: {verdict, reason, risk}}, err)。

    分批请求（默认 8 项/次）：模型思考会吃掉 token，一次塞太多会只出思考不出结论。
    部分批次失败不算整体失败，只要有一批成功就返回可用结果。
    """
    items = []
    for f in findings:
        if not f.get("app") and not f.get("fix"):
            continue
        row = _ai_item_row(f)
        row["id"] = f.get("id")
        items.append(row)
    if not items:
        return {}, "没有可分析的自启项"

    by_id_all = {}
    by_name_all = {}
    errors = []
    total = len(items)
    for start in range(0, total, chunk):
        part = items[start:start + chunk]
        if progress:
            progress("AI 正在分析 %d - %d 项（共 %d 项）…"
                     % (start + 1, min(start + chunk, total), total))
        brief = json.dumps(part, ensure_ascii=False)
        msgs = [{"role": "system", "content": AI_SYSTEM},
                {"role": "user", "content": "清单如下：\n" + brief}]
        txt, err = ai_chat(msgs, timeout=timeout, max_tokens=3000, temperature=0.2)
        if err and ("empty reply" in err or "502" in err or "截断" in err):
            txt, err = ai_chat(msgs, timeout=timeout, max_tokens=6000, temperature=0.2)
        if err:
            log_line("ai_advise chunk failed: %s" % err)
            errors.append(err)
            continue
        rows = _parse_ai_json(txt)
        if not rows:
            errors.append("AI 返回里没有 JSON：%s" % txt[:120])
            continue
        for r in rows:
            if not isinstance(r, dict):
                continue
            # 优先按 id 对齐：同名自启项（HKCU/HKLM 各一个、同名服务）在按 name
            # 匹配时会互相覆盖，A 的结论会贴到 B 上
            fid = str(r.get("id") or "").strip()
            if fid:
                by_id_all[fid] = r
            nm = str(r.get("name") or "").strip().lower()
            if nm:
                by_name_all.setdefault(nm, r)   # 兜底：旧模型不回 id 时用，先到先得不再覆盖

    out = {}
    for it in items:
        r = by_id_all.get(str(it.get("id") or "").strip())
        if not r:
            r = by_name_all.get(str(it["name"]).strip().lower())
        if not r:
            continue
        v = str(r.get("verdict") or "").strip().lower()
        if v not in ("keep", "delay", "disable"):
            continue
        out[it["id"]] = {"verdict": v,
                         "reason": str(r.get("reason") or "").strip()[:80],
                         "risk": str(r.get("risk") or "").strip()[:8]}
    if out:
        return out, ""
    return {}, (errors[0] if errors else "AI 没给出可用结论，请重试")


def ai_explain(f, timeout=120):
    """单项：这是什么程序 + 能不能关 -> 自然语言。"""
    row = _ai_item_row(f)
    app = f.get("app") or {}
    extra = []
    if app.get("version"):
        extra.append("版本 %s" % app["version"])
    if app.get("siblings") and not app.get("exists"):
        extra.append("同目录现有程序：%s" % "、".join(app["siblings"][:5]))
    prompt = ("请用中文回答，面向不懂电脑的用户，分三段、每段一两句话：\n"
              "1) 这个程序是什么、属于哪个软件；\n"
              "2) 禁止它开机自启会有什么影响；\n"
              "3) 明确结论：建议保留 / 延迟启动 / 禁止启动（三选一，给出理由）。\n\n"
              "信息：\n" + json.dumps(dict(row, **{"extra": "；".join(extra)}),
                                     ensure_ascii=False, indent=1))
    return ai_chat([{"role": "system", "content": "你是 Windows 启动项顾问，回答要短、准、不绕弯子。"},
                    {"role": "user", "content": prompt}], timeout=timeout, max_tokens=900)


def ai_available(timeout=3):
    base, _model = get_ai_cfg()
    try:
        with urllib.request.urlopen(base + "/v1/models", timeout=timeout) as r:
            return r.status == 200
    except Exception:
        return False


def _create_delay_task(exe, args, task_name, dry_run=False, delay_sec=None):
    """创建『登录后延迟 N 秒』的计划任务（.lnk 自动解析目标）。动态值经 env 传递。

    delay_sec=None 用界面设置的时长；显式传 0 表示"不设延迟"（还原历史任务时用）。
    """
    sec = get_delay_seconds() if delay_sec is None else max(0, min(600, int(delay_sec)))
    if dry_run:
        return True, "[试运行] 创建延迟任务：%s  <-  %s（%s）" % (task_name, exe, delay_text(sec))
    if not exe:
        return False, "无法解析启动命令，跳过（建议手动处理）"
    ps = (
        "$ErrorActionPreference='Stop';"
        "$exe=$env:BD_EXE;$arguments=$env:BD_ARGS;"
        "if($exe -match '\\.lnk$'){"
        "$sh=New-Object -ComObject WScript.Shell;$sc=$sh.CreateShortcut($exe);"
        "$arguments=$sc.Arguments;$exe=$sc.TargetPath};"
        "$act=New-ScheduledTaskAction -Execute $exe;"
        "if($arguments){$act=New-ScheduledTaskAction -Execute $exe -Argument $arguments};"
        "$trg=New-ScheduledTaskTrigger -AtLogOn;"
        "if($env:BD_DELAY -ne 'PT0S'){try{$trg.Delay=$env:BD_DELAY}catch{}};"
        "$set=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero);"
        "Register-ScheduledTask -TaskName $env:BD_TASK -Action $act -Trigger $trg -Settings $set "
        "-Description 'BootDoctor delayed startup' -Force | Out-Null;"
        "$t=Get-ScheduledTask -TaskName $env:BD_TASK -ErrorAction Stop;"
        "$d='';try{$d=$t.Triggers[0].Delay}catch{};"
        "'OK delay=' + $d"
    )
    env = dict(os.environ)
    env["BD_EXE"] = exe or ""
    env["BD_ARGS"] = args or ""
    env["BD_TASK"] = task_name
    env["BD_DELAY"] = "PT%dS" % sec
    out = run_ps(ps, timeout=90, env=env)
    if "OK" in out:
        return True, "已创建延迟任务：%s（%s，%s）" % (task_name, delay_text(sec), out.strip())
    return False, "创建延迟任务失败：%s（%s）" % (task_name, out.strip()[:200])


def _remove_delay_task(task_name, dry_run=False):
    if dry_run:
        return True, "[试运行] 删除延迟任务：%s" % task_name
    env = dict(os.environ)
    env["BD_TASK"] = task_name
    out = run_ps("Unregister-ScheduledTask -TaskName $env:BD_TASK -Confirm:$false -ErrorAction Stop; 'OK'",
                 timeout=60, env=env)
    if "OK" in out:
        return True, "已删除延迟任务：%s" % task_name
    return False, "删除任务失败：%s（可能已不存在）" % task_name


def analyze(raw):
    F = []

    def add(**kw):
        kw.setdefault("fix", None)
        kw.setdefault("default", False)
        kw.setdefault("impact", None)
        kw.setdefault("short", "")
        # 有应用信息时，统一在说明末尾补一段「这是什么程序」，三种处理方式共用
        app = kw.get("app")
        if app:
            block = "\n\n" + app_detail_text(app)
            kw["detail"] = (kw.get("detail") or "") + block
            for o in (kw.get("opts") or {}).values():
                o["detail"] = (o.get("detail") or "") + block
        F.append(kw)

    svcs = raw.get("services") or []
    sysd = raw.get("sys") or {}
    ev = raw.get("events") or {}
    pw = raw.get("power") or {}
    boots = ev.get("boots") or []
    scm = ev.get("scm") or []

    # ---------------- 启动速度 ----------------
    if boots:
        b = boots[0]
        sev = "high" if b["boot"] >= 90 else ("mid" if b["boot"] >= 60 else None)
        if sev:
            add(id="boot_slow", cat="启动速度", sev=sev,
                title="上次开机耗时 %d 秒" % b["boot"], short="系统启动性能日志",
                impact="目标 < 60 秒",
                detail=("最近一次开机（%s）：总耗时 %d 秒。\n"
                        "· 登录阶段（用户配置 %d 秒 + 桌面加载 %d 秒）：%d 秒\n"
                        "· 桌面出现后的后台收尾：%d 秒\n\n"
                        "处理下方『快速启动 / 开机自启 / 服务与残留』里的问题后，再体检对比效果。") % (
                    b["time"], b["boot"], b["profile"], b["explorer"],
                    b["profile"] + b["explorer"], b["post"]))
        if (b["profile"] + b["explorer"]) >= 40:
            add(id="login_phase", cat="启动速度", sev="mid",
                title="登录阶段耗时 %d 秒（占大头）" % (b["profile"] + b["explorer"]),
                short="配置 %ds + 桌面 %ds" % (b["profile"], b["explorer"]),
                detail=("登录后系统要依次：加载用户配置 → 启动自启程序 → 初始化桌面（Explorer）。\n"
                        "这两项偏大通常是自启程序多、常驻软件（杀软/网盘/更新器）多、或残留驱动拖慢所致。\n"
                        "处理『开机自启』与『服务与残留』里标出的问题后可改善。"))
        if len(boots) >= 3:
            avg = sum(x["boot"] for x in boots[:5]) // max(1, len(boots[:5]))
            add(id="boot_trend", cat="启动速度", sev="info",
                title="近几次开机平均 %d 秒（共 %d 条记录）" % (avg, len(boots)),
                short="用于对比优化效果",
                detail="历史记录（最近在前）：\n" + "\n".join(
                    "· %s — %d 秒" % (x["time"], x["boot"]) for x in boots))
        slow = ev.get("slow") or []
        from collections import Counter
        c = Counter()
        for s in slow:
            if s.get("name"):
                c[s["name"]] += 1
        top = [n for n, k in c.most_common(8) if k >= 2]
        if top:
            add(id="slow_items", cat="启动速度", sev="info",
                title="反复出现在『启动缓慢』记录里的程序",
                short="%d 个" % len(top),
                detail="这些程序在近几次开机中多次被系统标记为启动较慢：\n" +
                       "\n".join("· %s" % n for n in top) +
                       "\n\n不一定都要关闭，如果你的工作流不需要它们常驻，可考虑处理。")
    else:
        add(id="no_boot_log", cat="启动速度", sev="info",
            title="没有读到启动性能记录",
            short="可能诊断服务被关闭",
            detail="系统日志中没有启动性能事件（可能被优化工具关闭了诊断），无法评估开机耗时。")

    # ---------------- 快速启动 ----------------
    if pw:
        fast_ok = (pw.get("hiberboot") == 1) and pw.get("hiberfil")
        if not fast_ok:
            add(id="fast_startup", cat="快速启动", sev="mid",
                title="快速启动未开启", short="预计可省 20~60 秒",
                impact="预计节省 20~60 秒",
                detail=("Windows 的『快速启动』会把内核会话保存到 hiberfil.sys，"
                        "下次【关机 → 开机】直接恢复，省掉驱动/服务的完整初始化。\n\n"
                        "当前状态：HiberbootEnabled=%s，休眠文件%s。\n"
                        "注意：只加速『关机再开机』；『重启』始终是完整冷启动（排障请用重启）。") % (
                    pw.get("hiberboot"), "存在" if pw.get("hiberfil") else "不存在"),
                fix={"type": "fast_startup", "risk": "safe"}, default=True)

    # ---------------- 流氓软件 / 全家桶 ----------------
    # 只做识别与建议，不自动卸载。处理方式：
    #   已安装 → 打开官方卸载程序（用户自己点确认）
    #   自启项 → 走常规「禁止启动 / 彻底删除」
    aw = raw.get("adware") or {}
    aw_items = aw.get("items") or []
    if aw_items:
        fams = aw.get("families") or {}
        # 按家族聚合成一条，避免 360 装了 8 个组件就刷 8 条
        for fk, group in sorted(fams.items(), key=lambda kv: -len(kv[1])):
            label = group[0].get("label") or fk
            sev = "high" if any(g.get("sev") == "high" for g in group) else "mid"
            names = [g.get("name") or "" for g in group]
            names = [n for n in names if n]
            inst = [g for g in group if g.get("kind") == "installed"]
            starts = [g for g in group if g.get("kind") != "installed"]
            why = group[0].get("why") or ""

            lines = ["命中特征库：%s" % why, ""]
            if inst:
                lines.append("已安装：")
                for g in inst[:10]:
                    lines.append("  · %s%s" % (
                        g.get("name") or "",
                        ("（%s）" % g["company"]) if g.get("company") else ""))
            if starts:
                lines.append("")
                lines.append("随开机启动：")
                for g in starts[:12]:
                    lines.append("  · [%s] %s" % (g.get("source") or "", g.get("name") or ""))
            lines.append("")
            lines.append("建议：这类软件通常是「装一个带一串」，卸载本体后残留的启动项与"
                         "服务仍会随开机加载。建议先在「设置 → 应用」里正常卸载，"
                         "再回来体检清理残留。")
            detail = "\n".join(lines)

            # 卸载入口：优先给已安装项里找到的卸载命令
            uninst = ""
            for g in inst:
                if g.get("uninstall"):
                    uninst = g["uninstall"]
                    break

            opts = {}
            if starts:
                # 启动项类可以按常规方式禁掉
                opts["startup_off"] = {
                    "label": "禁止这些启动项",
                    "detail": "把上面列出的启动项标记为禁用（可还原）。\n"
                              "注意：软件本体还在，某些组件可能被其它程序重新拉起。",
                }
            add(id="adware_" + (fk or "misc"), cat="流氓软件", sev=sev,
                title="%s：%d 项" % (label, len(group)),
                short="、".join(names[:3]) + ("…" if len(names) > 3 else ""),
                impact="建议卸载" if inst else "建议禁止启动",
                detail=detail,
                uninstall_cmd=uninst,
                adware_group=[g.get("name") for g in group if g.get("name")],
                opts=opts or None)

    # 隐蔽启动点：单独列，即使没命中流氓特征也值得看
    extra = raw.get("extra") or []
    if extra:
        risky = [e for e in extra if e.get("danger") == "high"]
        if risky:
            lines = ["这些位置普通启动项管理器不会显示，恶意软件常用来持久化：", ""]
            for e in risky[:12]:
                lines.append("· %s" % (e.get("name") or ""))
                if e.get("cmd"):
                    lines.append("    %s" % str(e["cmd"])[:100])
            lines.append("")
            lines.append("如果你的机器没有装调试器 / 安全软件，这些条目基本可判定为异常。"
                         "不确定的话，右键「问 AI」让它看看。")
            add(id="extra_autostart", cat="流氓软件", sev="high",
                title="隐蔽启动点 %d 处" % len(risky),
                short="IFEO / Winlogon / AppInit / LSP",
                impact="需要人工确认",
                detail="\n".join(lines))

    # ---------------- 开机自启 ----------------
    su = raw.get("startup") or []
    enabled = [x for x in su if x.get("enabled")]
    if len(enabled) >= 12:
        lst = "\n".join("· [%s] %s" % (x["source"], x["name"]) for x in enabled[:60])
        if len(enabled) > 60:
            lst += "\n…"
        add(id="startup_count", cat="开机自启",
            sev=("mid" if len(enabled) >= 20 else "low"),
            title="已启用开机自启 %d 项" % len(enabled),
            short="共盘点 %d 项" % len(su),
            detail=("登录阶段要逐个拉起这些程序，数量越多登录越慢。\n\n当前启用清单：\n%s\n\n"
                    "说明：本工具只对『更新器/预加载』类自动建议关闭；其他项目请在任务管理器里按需取舍。") % lst)
    upd = [x for x in enabled if _is_updater_like(x)]
    if upd:
        lst = "\n".join("· %s（%s）" % (x["name"], x["source"]) for x in upd)
        add(id="updater_startups", cat="开机自启", sev="low",
            title="检测到 %d 个『更新器 / 预加载』类自启（可关）" % len(upd),
            short="不影响软件正常使用",
            impact="每个约省 0.5~3 秒",
            detail=("以下项目只负责更新检查或预加载，关闭不影响软件运行（需要时软件会自己检查更新）：\n\n"
                    "%s\n\n关闭方式与任务管理器一致，随时可恢复。") % lst,
            fix={"type": "startup_off", "risk": "safe",
                 "items": [{"hive": x["hive"], "kind": x["kind"], "name": x["name"]} for x in upd]},
            default=True)

    # ---------------- 延迟启动（可选优化） ----------------
    # 每个对象都提供「延迟 / 禁止 / 删除」三种取舍（服务不提供删除：删服务键风险太高，
    # 失效残留走『服务与残留』分类）。勾选后按所选方式执行，互不影响。
    dtext = delay_text()
    for s in _svc_delay_candidates(svcs):
        _sapp = describe_app(s.get("image", ""))
        add(id="delay_svc@" + s["name"], cat="延迟启动", sev="low", name=s["name"],
            src="服务",
            title="服务：%s" % s["name"],
            short="自动服务 · 可改为延迟加载",
            impact="减少开机拥堵（服务仍会启动）",
            app=_sapp,
            detail=("『%s』现在是『自动』，会和系统服务同时抢开机资源。\n\n"
                    "● 延迟启动：改为『自动（延迟启动）』，Windows 等系统就绪后再拉起它，功能照常。\n"
                    "● 禁止启动：启动类型改为『禁用』，开机完全不加载（需要时可在服务管理器里改回）。\n\n"
                    "两种都直接写服务注册表项，不建计划任务；随时可用『还原』回到原状态。\n"
                    "服务路径：%s") % (s["name"], s.get("image", "")),
            fix={"type": "svc_delay", "risk": "safe", "items": [s["name"]]},
            opts={
                "delay": {"title": "服务：%s" % s["name"],
                          "short": "延迟加载（仍会启动）",
                          "impact": "减少开机拥堵（服务仍会启动）",
                          "detail": ("把『%s』改为『自动（延迟启动）』：系统启动完成后再拉起，功能照常。\n\n"
                                     "写法：服务的 DelayedAutoStart=1，不建计划任务；随时可还原。\n"
                                     "服务路径：%s") % (s["name"], s.get("image", "")),
                          "fix": {"type": "svc_delay", "risk": "safe", "items": [s["name"]]}},
                "block": {"title": "服务：%s" % s["name"],
                          "short": "启动类型改为禁用",
                          "impact": "完全不加载该服务",
                          "detail": ("把『%s』的启动类型改为『禁用（4）』：开机和手动都不会加载它。\n\n"
                                     "⚠ 若这个服务属于你还在用的软件，功能可能不可用；\n"
                                     "需要时在『服务』里改回『自动』，或用本工具的『还原』一键恢复。\n"
                                     "服务路径：%s") % (s["name"], s.get("image", "")),
                          "fix": {"type": "svc_start", "risk": "confirm",
                                  "items": {s["name"]: 4}}},
            },
            default=True)
    for x in [i for i in enabled if not _is_updater_like(i) and not _DELAY_ITEM_EXCLUDE_RE.search(i["name"])]:
        _base_item = {"hive": x["hive"], "kind": x["kind"], "name": x["name"],
                      "cmd": x["cmd"], "subkey": x.get("subkey")}
        _iapp = describe_app(x["cmd"])
        add(id="delay_item@" + x["name"], cat="延迟启动", sev="info", name=x["name"],
            src=x.get("source") or "自启项",
            title="自启项：%s" % x["name"],
            short="登录后约 %s 启动" % dtext,
            impact="错开登录高峰",
            app=_iapp,
            detail=("『%s』（%s）现在是开机自启。三种处理方式挑一个：\n\n"
                    "● 延迟启动：创建『登录后延迟 %s』的计划任务，并关掉原自启标记。\n"
                    "● 禁止启动：保留自启条目，只打上任务管理器同款「已禁用」标记（随时可启用）。\n"
                    "● 彻底删除：把自启条目本身删掉（注册表值 / 启动文件夹快捷方式），原值会备份。\n\n"
                    "命令：%s") % (x["name"], x["source"], dtext, x["cmd"]),
            fix={"type": "startup_delay", "risk": "confirm", "items": [dict(_base_item)]},
            opts={
                "delay": {"title": "自启项：%s" % x["name"],
                          "short": "登录后约 %s 启动" % dtext,
                          "impact": "错开登录高峰",
                          "detail": ("把『%s』（%s）改为延迟启动：登录约 %s 后再自动启动。\n\n"
                                     "实现：创建带延迟的登录计划任务，并关闭原来的自启标记（随时可还原）。\n\n"
                                     "命令：%s") % (x["name"], x["source"], dtext, x["cmd"]),
                          "fix": {"type": "startup_delay", "risk": "confirm",
                                  "items": [dict(_base_item)]}},
                "block": {"title": "自启项：%s" % x["name"],
                          "short": "标记为已禁用（条目保留）",
                          "impact": "登录时不再拉起",
                          "detail": ("给『%s』（%s）打上「已禁用」标记（和任务管理器里右键禁用完全一样）。\n\n"
                                     "条目还在，随时可以在任务管理器里重新启用，或用本工具『还原』。\n\n"
                                     "命令：%s") % (x["name"], x["source"], x["cmd"]),
                          "fix": {"type": "startup_off", "risk": "safe",
                                  "items": [dict(_base_item)]}},
                "delete": {"title": "自启项：%s" % x["name"],
                           "short": "从自启列表删除（已备份）",
                           "impact": "登录时不再拉起",
                           "detail": ("把『%s』（%s）的自启条目整个删掉：\n"
                                      "%s\n\n"
                                      "● 注册表项：删除对应的值；启动文件夹项：删除快捷方式文件。\n"
                                      "● 同时清掉「启动应用」里的历史记录，任务管理器不再显示。\n"
                                      "● 执行前会备份原值 / 快捷方式文件，可用『还原』恢复。\n\n"
                                      "命令：%s") % (x["name"], x["source"],
                                                    "· 位置：" + (x.get("subkey") or x["source"])
                                                    if x["kind"] == "run" else "· 文件：" + x["cmd"],
                                                    x["cmd"]),
                           "fix": {"type": "startup_delete", "risk": "confirm",
                                   "items": [dict(_base_item)]}},
            },
            default=False)
    for t in existing_delay_tasks():
        _cur = delay_text(t["delay"]) or "无延迟"
        _off = "" if t.get("enabled", True) else "，已禁止"
        _tapp = describe_app(t["exe"], t.get("args", ""))
        _orig = find_startup_entry(t["name"], su)
        if _orig:
            _now_short = "删任务 + 恢复登录后立刻启动"
            _now_detail = ("把这个程序的启动方式改回「普通开机自启」：\n\n"
                           "● 删除计划任务：%s\n"
                           "● 清掉原自启项『%s』（%s\\%s）的「已禁用」标记，\n"
                           "  登录后立刻启动，和没改延时之前一样。\n\n"
                           "⚠ 删任务后不再延迟；想再改回延时，选『延迟启动』即可。\n"
                           "命令：%s %s"
                           % (t["task"], t["name"], _orig.get("hive", ""),
                              "StartupFolder" if _orig.get("kind") == "folder" else "Run",
                              t["exe"], t["args"]))
        else:
            _now_short = "原自启项已不存在，只删延迟任务"
            _now_detail = ("把这个延迟任务删掉。\n\n"
                           "● 当前自启列表里已经找不到原自启项『%s』了\n"
                           "  （常见原因：软件升级后换了自启条目名、或清理工具删掉了原条目），\n"
                           "  所以只删任务，不会凭空造一个新的自启项。\n"
                           "● 如果本来就想让它别启动，选『禁止启动』更稳妥（任务留着，随时能开回来）。\n"
                           "命令：%s %s"
                           % (t["name"], t["exe"], t["args"]))
        _t_title = t["name"] + ("（已禁用）" if not t.get("enabled", True) else "")
        add(id="delay_task@" + t["task"], cat="延迟启动", sev="info", name=t["name"],
            src="计划任务",
            title=_t_title,
            short=("已延迟 %s · 可改回立即启动" % _cur if _orig
                   else "已延迟 %s · 原自启项已不存在" % _cur),
            impact="错开登录高峰",
            app=_tapp, prio=-1,
            detail=("这是本工具之前创建的延迟任务，当前延迟 %s。\n\n"
                    "命令：%s %s\n任务名：%s\n\n"
                    "● 延迟启动：按顶部『延迟时长』重新登记（覆盖原任务）。\n"
                    "● 改回立即启动：删任务 + 恢复原自启项，登录后马上启动。\n"
                    "● 禁止启动：任务保留但不再触发（Disable-ScheduledTask），随时可恢复。\n"
                    "● 彻底删除：注销该任务（任务 XML 会备份，可用『还原』重建）。\n\n"
                    "右键这一行可以看它到底是哪个程序、在哪个目录。"
                    % (_cur, t["exe"], t["args"], t["task"])),
            fix={"type": "delay_task_set", "risk": "safe",
                 "items": [{"task": t["task"], "exe": t["exe"], "args": t["args"],
                            "old_delay": t["delay"]}]},
            opts={
                "delay": {"title": _t_title,
                          "short": "按顶部时长重新登记",
                          "impact": "错开登录高峰",
                          "detail": ("按顶部『延迟时长』重新登记该任务（覆盖原任务）。\n\n"
                                     "命令：%s %s\n任务名：%s\n当前延迟：%s%s"
                                     % (t["exe"], t["args"], t["task"], _cur,
                                        "\n当前状态：已禁止（执行后会重新启用）" if _off else "")),
                          "fix": {"type": "delay_task_set", "risk": "safe",
                                  "items": [{"task": t["task"], "exe": t["exe"],
                                             "args": t["args"], "old_delay": t["delay"]}]}},
                "now": {"title": t["name"],
                        "short": _now_short,
                        "impact": "登录后立刻启动（不再延迟）",
                        "detail": _now_detail,
                        "fix": {"type": "delay_task_restore", "risk": "confirm",
                                "items": [{"task": t["task"], "name": t["name"],
                                           "hive": (_orig or {}).get("hive", "HKCU"),
                                           "kindx": (_orig or {}).get("kind", "run"),
                                           "exe": t["exe"], "args": t.get("args", "")}]}},
                "block": {"title": t["name"],
                          "short": "禁止触发（任务保留）",
                          "impact": "登录时不启动",
                          "detail": ("把该延迟任务设为『已禁用』：任务定义保留，只是不再在登录时触发。\n\n"
                                     "随时可以改回延迟启动，或用『还原』恢复。\n"
                                     "命令：%s %s\n任务名：%s" % (t["exe"], t["args"], t["task"])),
                          "fix": {"type": "delay_task_block", "risk": "safe",
                                  "items": [{"task": t["task"], "enabled": t.get("enabled", True)}]}},
                "delete": {"title": t["name"],
                           "short": "注销任务（不再自启）",
                           "impact": "登录时不启动",
                           "detail": ("注销这个计划任务（Unregister-ScheduledTask）。\n\n"
                                      "⚠ 该程序将不再自启（原自启标记在改延迟时已关闭）。\n"
                                      "执行前会把任务 XML 复制到备份目录，可用『还原』重建。\n\n"
                                      "命令：%s %s\n任务名：%s" % (t["exe"], t["args"], t["task"])),
                           "fix": {"type": "delay_task_del", "risk": "confirm",
                                   "items": [{"task": t["task"], "exe": t["exe"],
                                              "args": t["args"], "delay": t["delay"]}]}},
            },
            default=False)

    # ---------------- 服务与残留 ----------------
    res360 = [s for s in svcs if _is_360_residue(s) and s["start"] in (0, 1, 2)]
    if res360:
        add(id="residue_360", cat="服务与残留", sev="high",
            title="360 卸载残留：%d 个驱动/服务仍会随开机加载" % len(res360),
            short="过滤驱动会挂在磁盘 IO 链上",
            impact="每次开机少加载 %d 个驱动" % len(res360),
            detail=("检测到以下 360 相关驱动/服务仍处于启用状态（360 已卸载但残留）：\n\n" +
                    "\n".join("· %s" % s["name"] for s in res360) +
                    "\n\n它们会在每次开机加载（部分作为文件系统过滤驱动常驻），属于无效开销。\n"
                    "建议禁用（随时可还原；建议重启后复检确认不再加载）。"),
            fix={"type": "svc_start", "risk": "safe",
                 "items": {s["name"]: 4 for s in res360}}, default=True)

    ali = [s for s in svcs if s["name"] in ("AlibabaProtect", "AliPaladin") and s["start"] in (0, 1, 2)]
    if ali:
        add(id="residue_ali", cat="服务与残留", sev="mid",
            title="阿里保护组件仍在开机运行 / 重装自身驱动",
            short="AlibabaProtect + AliPaladin",
            impact="减少每次开机的驱动重装",
            detail=("AlibabaProtect 会在每次开机重新安装其内核驱动（AliPaladin），属于无效开销。\n\n"
                    "注意：该组件有驱动级自保护，如果在运行时修改失败，重启后再执行一次即可生效。"),
            fix={"type": "svc_start", "risk": "safe",
                 "items": {"AlibabaProtect": 4, "AliPaladin": 4}}, default=True)

    to_names = _extract_timeout_names(scm)
    plm_svc = next((s for s in svcs if "platform license manager" in s["name"].lower()), None)
    plm_hits = [n for n in to_names if "platform license manager" in n.lower()]
    if plm_svc and plm_svc["start"] in (0, 1, 2):
        cnt = sum(to_names.get(n, 0) for n in plm_hits)
        add(id="svc_intel_plm", cat="服务与残留", sev="mid",
            title="Intel 许可服务每次开机超时报错",
            short=("近 7 天 %d 次" % cnt) if cnt else "事件 7009",
            impact="消除开机等待",
            detail=("该服务与主流程无关，但每次开机系统都会等待它直到超时（事件 7009）。\n"
                    "改为『手动』后不再随开机启动，需要它的软件仍可自行拉起。"),
            fix={"type": "svc_start", "risk": "safe", "items": {plm_svc["name"]: 3}}, default=True)
    elif (not plm_svc) and plm_hits:
        add(id="svc_intel_plm_hist", cat="服务与残留", sev="info",
            title="有历史『Intel 许可服务超时』记录（服务已不在系统中）",
            short="可忽略",
            detail="近期日志里有历史超时记录，但对应服务已不在系统里（可能已处理过），无需操作。")

    others = {n: c for n, c in to_names.items() if "platform license" not in n.lower()}
    if others:
        add(id="svc_timeout_others", cat="开机报错", sev="info",
            title="其他开机超时服务", short="%d 个" % len(others),
            detail="近期开机时等待这些服务超时（多为偶发或原本较慢的服务，未自动处理）：\n\n" +
                   "\n".join("· %s（%d 次）" % (n, c) for n, c in others.items()))

    sur = [s for s in svcs if s["name"] in ("ESRV_SVC_QUEENCREEK", "SystemUsageReportSvc_QUEENCREEK")
           and s["start"] in (0, 1, 2)]
    if sur:
        add(id="residue_intel_sur", cat="服务与残留", sev="low",
            title="Intel 系统遥测组件仍在开机运行",
            short="%d 个服务" % len(sur),
            impact="减少 2 个开机服务",
            detail="Intel System Usage Report（遥测/统计组件），一般用不到，可禁用。",
            fix={"type": "svc_start", "risk": "safe",
                 "items": {s["name"]: 4 for s in sur}}, default=True)

    luafv = [s for s in svcs if s["name"] == "luafv" and s["start"] in (0, 1, 2)]
    if luafv and pw.get("enable_lua") == 0:
        add(id="luafv_noise", cat="服务与残留", sev="low",
            title="luafv 驱动每次开机加载失败（UAC 已关闭）",
            short="纯噪音，可消除",
            detail=("系统已关闭 UAC（EnableLUA=0），导致文件虚拟化驱动 luafv 每次开机都会失败并记一条错误。\n"
                    "禁用该驱动只消除报错，不影响使用；想恢复 UAC 的话请保留本项。"),
            fix={"type": "svc_start", "risk": "safe", "items": {"luafv": 4}}, default=True)

    dead_tmp, dead_other = [], []
    for s in svcs:
        if not s["image"] or s["start"] not in (0, 1, 2, 3):
            continue
        rp = resolve_image_path(s["image"])
        if not rp or image_file_exists(rp):
            continue
        s["_rp"] = rp
        if "\\temp\\" in rp.lower():
            dead_tmp.append(s)
        else:
            dead_other.append(s)
    if dead_tmp:
        add(id="dead_svc_tmp", cat="服务与残留", sev="low",
            title="%d 个失效服务键（指向临时目录、文件已不存在）" % len(dead_tmp),
            short="安全清理",
            detail="这些服务注册项指向的驱动文件已被清理（如工具/virtual 驱动的临时文件），属于无效残留：\n\n" +
                   "\n".join("· %s -> %s" % (s["name"], s["_rp"]) for s in dead_tmp),
            fix={"type": "rm_svc", "risk": "safe",
                 "items": [s["name"] for s in dead_tmp]}, default=True)
    if dead_other:
        add(id="dead_svc_other", cat="服务与残留", sev="info",
            title="%d 个服务指向的文件已不存在" % len(dead_other),
            short="需人工确认",
            detail="这些服务指向的文件找不到了（可能是卸载不干净的软件）。删除服务键前建议确认你不再需要它：\n\n" +
                   "\n".join("· %s -> %s" % (s["name"], s["_rp"]) for s in dead_other),
            fix={"type": "rm_svc", "risk": "confirm",
                 "items": [s["name"] for s in dead_other]}, default=False)

    down = sysd.get("svcAutoDown") or []
    if down:
        add(id="svc_auto_down", cat="服务与残留", sev="info",
            title="自动启动但当前未运行的服务：%d 个" % len(down),
            short="多为按需/守护型",
            detail="这些服务设为自动但当前没在跑（可能是延迟启动、按需启动或启动失败）：\n\n· " +
                   "、".join(down[:40]))

    # ---------------- 开机报错 ----------------
    blk = [e for e in scm if e.get("id") in (7000, 7026)]
    if blk:
        uniq = []
        seen = set()
        for e in blk:
            key = e["msg"][:80]
            if key not in seen:
                seen.add(key)
                uniq.append(e)
        add(id="drv_fail", cat="开机报错", sev="info",
            title="开机时有驱动/服务加载失败记录",
            short="近 7 天 %d 条" % len(blk),
            detail="相关信息（360 / luafv 等已在上方合并处理）：\n\n" +
                   "\n".join("· [%s %s] %s" % (e["time"], e["id"], e["msg"][:120]) for e in uniq[:15]))

    crashes = [e for e in scm if e.get("id") == 7031]
    if crashes:
        add(id="svc_crash", cat="开机报错", sev="info",
            title="有服务异常退出记录：%d 条" % len(crashes),
            short="近 7 天",
            detail="\n".join("· [%s] %s" % (e["time"], e["msg"][:120]) for e in crashes[:10]))

    c7005 = int(ev.get("c7005") or 0)
    c7005_7d = int(ev.get("c7005_7d") or 0)
    c7005_1h = int(ev.get("c7005_1h") or 0)
    gap_min = None
    try:
        _lt = ev.get("last7005") or ""
        if _lt:
            gap_min = (_dt.datetime.now()
                       - _dt.datetime.strptime(_lt, "%Y-%m-%d %H:%M:%S")).total_seconds() / 60.0
    except (ValueError, TypeError):
        gap_min = None
    if c7005 >= 100:
        w7 = ("%d+" % c7005_7d) if c7005_7d >= 8000 else str(c7005_7d)
        stopped = ((gap_min is not None and gap_min >= 6)
                   or (gap_min is None and c7005_1h == 0))
        if stopped:
            gtxt = ("最近一条报错已是 %.0f 分钟前" % gap_min) if gap_min is not None \
                else "近 1 小时无新增"
            add(id="reg_corrupt_hist", cat="开机报错", sev="info",
                title="『配置注册表数据库损坏』历史记录（%s）" % gtxt,
                short="近 7 天 %s 条；疑似已修复" % w7,
                detail=("该报错已停止新增（%s），说明问题大概率已解决；历史计数会随时间自然消退。\n"
                        "该问题常见根因是 C:\\Windows\\ServiceProfiles\\LocalService\\NTUSER.DAT 损坏，"
                        "处理方式为归档旧文件后由系统自动重建（已实机验证）。" % gtxt))
        else:
            gtxt = ("最近报错在 %.0f 分钟前（仍在新增）" % gap_min) if gap_min is not None \
                else "近 1 小时 %d 条" % c7005_1h
            add(id="reg_corrupt", cat="开机报错", sev="high",
                title="『配置注册表数据库损坏』24 小时 %d 条（%s）" % (c7005, gtxt),
                short="近 7 天 %s 条" % w7,
                detail=("系统服务反复加载某个用户配置失败（事件 7005，错误 1009），当前仍在新增。\n\n"
                        "常见根因：C:\\Windows\\ServiceProfiles\\LocalService\\NTUSER.DAT 损坏。\n"
                        "已验证有效的修复（2026-10-15 实机验证，全程可还原）：\n"
                        "1) 把该文件（连同 NTUSER.DAT.LOG1/LOG2）改名或移走备份；\n"
                        "2) Windows 会在下一次配置加载时【自动重建】一个新的（实测约 1 分钟内，无需重启）；\n"
                        "3) 若出现异常，把备份文件改回原名即可复位。\n\n"
                        "本工具暂不自动执行此项（涉及系统配置文件），建议交给有把握的人或让 WorkBuddy 协助。"))
    elif c7005 > 0:
        add(id="reg_corrupt_minor", cat="开机报错", sev="info",
            title="有少量『配置注册表』加载失败记录（24h %d 条）" % c7005,
            short="未达告警线",
            detail="偶发的用户配置加载失败（事件 7005），数量不大时可暂不处理。")

    c7023 = int(ev.get("c7023") or 0)
    if c7023 >= 50:
        add(id="svc_flap", cat="开机报错", sev="low",
            title="有服务反复重启记录（24h %d 次）" % c7023,
            short="例如：连接设备平台服务",
            detail=("某些系统服务在反复启动/停止（事件 7023）。若与『配置注册表损坏』同时出现，"
                    "可通过修复上文 7005 问题一并解决。"))

    # ---------------- 磁盘与其他 ----------------
    vols = sysd.get("vols") or []
    cv = next((v for v in vols if v.get("letter") == "C"), None)
    if cv and cv["total"] > 0:
        pct = cv["free"] / cv["total"]
        if pct < 0.10:
            add(id="disk_c_low", cat="磁盘与其他",
                sev=("high" if pct < 0.05 else "mid"),
                title="C 盘剩余空间偏少（剩 %d GB / %d GB）" % (cv["free"], cv["total"]),
                short="建议保持 15% 以上",
                detail="C 盘空间不足会影响系统更新、休眠文件与整体性能。\n建议清理或把大文件移出 C 盘。")
    disks = sysd.get("disks") or []
    bad = [d for d in disks if d.get("health") and str(d["health"]).lower() != "healthy"]
    if bad:
        add(id="disk_health", cat="磁盘与其他", sev="high",
            title="磁盘健康状态异常：%d 块" % len(bad),
            short="请尽快检查",
            detail="\n".join("· %s（%s）" % (d["name"], d["health"]) for d in bad) +
                   "\n\n建议先备份重要数据，并用厂商工具检查 SMART。")
    tasks = sysd.get("tasks") or []
    if len(tasks) >= 60:
        add(id="tasks_many", cat="磁盘与其他", sev="info",
            title="开机/登录触发的计划任务偏多：%d 个" % len(tasks),
            short="多数为系统自带",
            detail="前 40 个：\n" + "\n".join("· %s" % t for t in tasks[:40]))

    add(id="bios_tip", cat="磁盘与其他", sev="info",
        title="BIOS / 固件层优化建议（可选）",
        short="系统内无法自动处理",
        detail=("开机总耗时里有一段（约 30~70 秒）发生在 Windows 启动之前（BIOS/POST 阶段），"
                "系统内无法优化。如果在意，可进 BIOS：\n"
                "· 开启 Fast Boot / 快速启动\n"
                "· 关闭未使用的控制器、PXE 网络启动\n"
                "· 精简启动顺序（多硬盘时尤其明显）\n\n"
                "本项仅供了解，无需在系统内做任何操作。"))

    # ---------------- 排序 / 计分 ----------------
    # prio 小的排前面：已经改成延迟启动的项（用户最关心）优先于"可以改"的候选项
    F.sort(key=lambda x: (CAT_ORDER.index(x["cat"]) if x["cat"] in CAT_ORDER else 99,
                          x.get("prio", 0), SEV_ORDER.get(x["sev"], 9)))
    for f in F:
        if f.get("opts"):
            apply_op(f, OP_ORDER[0])          # 默认「延迟启动」，与历史行为一致
    for i, f in enumerate(F):
        f["idx"] = i

    score = 100 - sum(SEV_WEIGHT.get(f["sev"], 0) for f in F)
    score = max(0, min(100, score))
    if score >= 85:
        grade = "优秀"
    elif score >= 70:
        grade = "良好"
    elif score >= 50:
        grade = "一般"
    else:
        grade = "较差"

    n_high = sum(1 for f in F if f["sev"] == "high")
    n_mid = sum(1 for f in F if f["sev"] == "mid")
    n_fix = sum(1 for f in F if f.get("fix"))
    if n_fix:
        summary = "发现 %d 个高危、%d 个中危问题；已标记 %d 项可一键修复" % (n_high, n_mid, n_fix)
    else:
        summary = "发现 %d 个高危、%d 个中危问题；当前没有可自动修复的项目" % (n_high, n_mid)

    result = {
        "meta": {
            "scanned_at": raw.get("ts", ""),
            "osName": sysd.get("osName", ""),
            "build": sysd.get("build", ""),
            "ramGB": sysd.get("ramGB"),
            "bootTime": sysd.get("bootTime", ""),
            "admin": raw.get("admin", False),
            "version": VERSION,
        },
        "metrics": {
            "last_boot_s": boots[0]["boot"] if boots else None,
            "profile_s": boots[0]["profile"] if boots else None,
            "explorer_s": boots[0]["explorer"] if boots else None,
            "startup_enabled": len(enabled),
            "startup_total": len(su),
            "svc_auto": sysd.get("svcAuto"),
            "tasks": len(tasks),
            "c_free": cv["free"] if cv else None,
            "c_total": cv["total"] if cv else None,
            "fast_startup_on": bool((pw.get("hiberboot") == 1) and pw.get("hiberfil")),
        },
        "findings": F,
        "score": score,
        "grade": grade,
        "summary": summary,
    }
    log_line("analyze done: score=%s findings=%d" % (score, len(F)))
    return result


# --------------------------------------------------------------------------
# 备份 / 修复 / 还原
# --------------------------------------------------------------------------

def _power_restore_plan(it):
    """按备份决定怎么还原电源设置。返回 (动作, 值)。

    动作：
      powercfg_off —— 原本休眠就是关的，修复时 powercfg /h on 会生成 hiberfil.sys，
                      必须 powercfg /h off 连休眠一起关掉
      reg          —— 只把 HiberbootEnabled 写回备份值（保留休眠）
    只看 hiberboot 会漏掉第一种：原本 hiberboot=1 但 hibernate=0 的机器
    （手动关过休眠的笔记本很常见），还原后休眠会一直开着。
    """
    if it.get("hibernate") == 0:
        return "powercfg_off", None
    if it.get("hiberboot") == 0:
        return "reg", 0
    if it.get("hiberboot") is None:
        return "reg", None
    try:
        return "reg", int(it.get("hiberboot"))
    except (TypeError, ValueError):
        return "reg", None


def _read_start(name):
    return _reg_dword(HKLM, _SVC_BASE + "\\" + name, "Start")


def _read_delayed(name):
    d = _reg_dword(HKLM, _SVC_BASE + "\\" + name, "DelayedAutoStart")
    return int(d or 0)


def _set_service_delayed(name, on, dry_run=False):
    """设置服务『自动（延迟启动）』标记（DelayedAutoStart）。返回 (ok, msg)。"""
    path = _SVC_BASE + "\\" + name
    cur = _read_delayed(name)
    want = 1 if on else 0
    if dry_run:
        return True, "[试运行] %s：延迟启动 %s -> %s" % (name, cur, want)
    try:
        with winreg.OpenKey(HKLM, path, 0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "DelayedAutoStart", 0, winreg.REG_DWORD, want)
    except OSError:
        # 和 _set_service_start 同一口径：服务名经 env 传入，不拼进脚本字符串；
        # 用 -LiteralPath，避免服务名里的 [ ] 被当成通配符
        env = dict(os.environ)
        env["BD_SVC"] = name
        env["BD_VAL"] = str(want)
        ps = ("$p='HKLM:\\SYSTEM\\CurrentControlSet\\Services\\'+$env:BD_SVC;"
              "Set-ItemProperty -LiteralPath $p -Name DelayedAutoStart -Value ([int]$env:BD_VAL)"
              " -Type DWord -ErrorAction SilentlyContinue;"
              "(Get-ItemProperty -LiteralPath $p -Name DelayedAutoStart"
              " -ErrorAction SilentlyContinue).DelayedAutoStart")
        run_ps(ps, timeout=60, env=env)
    now = _read_delayed(name)
    if now == want:
        return True, "%s：延迟启动已%s" % (name, "开启" if want else "关闭")
    return False, "%s：修改失败（当前 %s），可能有自保护，重启后再试" % (name, now)


def _dump_service_values(name):
    out = {"values": [], "subkeys": []}
    base = _SVC_BASE + "\\" + name
    try:
        with winreg.OpenKey(HKLM, base, 0, winreg.KEY_READ) as k:
            n_sub, n_val, _t = winreg.QueryInfoKey(k)
            for i in range(n_sub):
                out["subkeys"].append(winreg.EnumKey(k, i))
            for i in range(n_val):
                vn, vd, vt = winreg.EnumValue(k, i)
                if isinstance(vd, bytes):
                    vd = {"__b64__": base64.b64encode(vd).decode("ascii")}
                out["values"].append([str(vn), int(vt), vd])
    except OSError:
        pass
    return out


def _read_approved_value(hive, kind, name):
    group = "StartupFolder" if kind == "folder" else "Run"
    m = read_approved(hive, group)
    return m.get(name)


def make_backup(findings, backup_root=None, tag=""):
    """对将要修复的项做快照，返回备份目录。"""
    ensure_dirs()
    root = backup_root or BACKUP_DIR
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S") + (("-" + tag) if tag else "")
    bdir = os.path.join(root, stamp)
    os.makedirs(bdir, exist_ok=True)
    snap = {"created": _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "version": VERSION, "items": []}
    for f in findings:
        fx = f.get("fix")
        if not fx:
            continue
        t = fx["type"]
        rid = f.get("id")
        if t == "fast_startup":
            snap["items"].append({"id": rid, "kind": "power",
                                  "hiberboot": _reg_dword(HKLM, _POWR_PATH, "HiberbootEnabled"),
                                  "hibernate": _reg_dword(HKLM, _HIBE_PATH, "HibernateEnabled")})
        elif t == "svc_start":
            for n, v in fx["items"].items():
                snap["items"].append({"id": rid, "kind": "service", "name": n,
                                      "old": _read_start(n), "target": v})
        elif t == "rm_svc":
            for n in fx["items"]:
                snap["items"].append({"id": rid, "kind": "rm_svc", "name": n,
                                      "dump": _dump_service_values(n)})
        elif t == "startup_off":
            for it in fx["items"]:
                old = _read_approved_value(it["hive"], it["kind"], it["name"])
                snap["items"].append({"id": rid, "kind": "startup",
                                      "hive": it["hive"], "kindx": it["kind"],
                                      "name": it["name"],
                                      "old": (bytes(old).hex() if old else None)})
        elif t == "task_off":
            for n in fx["items"]:
                snap["items"].append({"id": rid, "kind": "task", "name": n})
        elif t == "svc_delay":
            for n in fx["items"]:
                snap["items"].append({"id": rid, "kind": "svc_delay", "name": n,
                                      "old_delayed": _read_delayed(n), "old_start": _read_start(n)})
        elif t == "startup_delay":
            for it in fx["items"]:
                old = _read_approved_value(it["hive"], it["kind"], it["name"])
                snap["items"].append({"id": rid, "kind": "startup_delay", "hive": it["hive"],
                                      "kindx": it["kind"], "name": it["name"],
                                      "task": _task_name_for(it["name"]),
                                      "old": (bytes(old).hex() if old else None)})
        elif t == "delay_task_set":
            for it in fx["items"]:
                snap["items"].append({"id": rid, "kind": "delay_task", "task": it["task"],
                                      "exe": it.get("exe"), "args": it.get("args", ""),
                                      "old_delay": it.get("old_delay")})
        elif t == "startup_delete":
            # 删除类：注册表项存原值+原类型；启动文件夹项把文件复制进备份目录
            for it in fx["items"]:
                hive = it.get("hive", "HKCU")
                kindx = it.get("kind", "run")
                name = it.get("name", "")
                sub = it.get("subkey") or r"Software\Microsoft\Windows\CurrentVersion\Run"
                rec = {"id": rid, "kind": "startup_delete", "hive": hive, "kindx": kindx,
                       "name": name, "subkey": sub, "cmd": it.get("cmd", ""),
                       "approved": None, "value": None, "valuetype": None}
                ap = _read_approved_value(hive, kindx, name)
                if ap:
                    rec["approved"] = bytes(ap).hex()
                if kindx == "run":
                    val, typ = _read_startup_value(hive, sub, name)
                    rec["value"], rec["valuetype"] = val, typ
                else:
                    src = it.get("cmd") or ""
                    if src and os.path.isfile(src):
                        try:
                            sub_dir = os.path.join(bdir, "startup")
                            os.makedirs(sub_dir, exist_ok=True)
                            dst = os.path.join(sub_dir, os.path.basename(src))
                            shutil.copy2(src, dst)
                            rec["backup_file"] = os.path.relpath(dst, bdir)
                        except OSError as e:
                            log_line("backup startup file failed: %r" % (e,))
                snap["items"].append(rec)
        elif t == "delay_task_block":
            for it in fx["items"]:
                snap["items"].append({"id": rid, "kind": "delay_task_block", "task": it["task"],
                                      "old_enabled": bool(it.get("enabled", True))})
        elif t == "delay_task_del":
            for it in fx["items"]:
                snap["items"].append({"id": rid, "kind": "delay_task_del", "task": it["task"],
                                      "exe": it.get("exe"), "args": it.get("args", ""),
                                      "delay": it.get("delay"),
                                      "xml_file": _backup_task_xml(it["task"], bdir)})
        elif t == "delay_task_restore":
            # 取消延迟：备份任务 XML（还原时重建任务）+ 原自启标记（还原时恢复禁用状态）
            for it in fx["items"]:
                nm = it.get("name") or it["task"]
                entry = find_startup_entry(nm)
                hive = (entry or {}).get("hive") or it.get("hive", "HKCU")
                kindx = (entry or {}).get("kind") or it.get("kindx", "run")
                ap = _read_approved_value(hive, kindx, nm)
                snap["items"].append({"id": rid, "kind": "delay_task_restore",
                                      "task": it["task"], "name": nm,
                                      "hive": hive, "kindx": kindx,
                                      "old_approved": (bytes(ap).hex() if ap else None),
                                      "exe": it.get("exe"), "args": it.get("args", ""),
                                      "xml_file": _backup_task_xml(it["task"], bdir)})
    with open(os.path.join(bdir, "snapshot.json"), "w", encoding="utf-8") as fp:
        json.dump(snap, fp, ensure_ascii=False, indent=1)
    _write_restore_reg(snap, os.path.join(bdir, "restore-all.reg"))
    with open(os.path.join(bdir, "说明.txt"), "w", encoding="utf-8") as fp:
        fp.write(make_backup_readme_text(snap))
    log_line("backup created: %s (%d items)" % (bdir, len(snap["items"])))
    return bdir


def make_backup_readme_text(snap):
    """生成备份目录里的「说明.txt」。

    必须说清 restore-all.reg 只覆盖注册表：任务类 / 启动文件夹文件类改动它表达不了，
    否则用户以为双击 .reg 就全还原了，实际任务还禁着、自启项还是关的。
    """
    kinds = {str(it.get("kind") or "") for it in snap.get("items") or []}
    reg_only = {
        "service": "服务启动类型", "svc_delay": "服务延迟启动",
        "startup": "自启项启用状态", "startup_delay": "自启项启用状态",
        "delay_task_restore": "自启项启用状态", "startup_delete": "被删的 Run 值",
    }
    app_only = {
        "rm_svc": "被删除的服务键", "task": "被禁用的计划任务",
        "delay_task_del": "被删除的计划任务",
    }
    reg_has = [v for k, v in reg_only.items() if k in kinds]
    need = [v for k, v in app_only.items() if k in kinds]
    if any(it.get("kindx") == "folder" for it in snap.get("items") or []
           if it.get("kind") == "startup_delete"):
        need.append("启动文件夹里被移走的快捷方式")
    out = ["%s v%s 修复备份" % (APP_NAME, VERSION),
           "时间：%s" % snap.get("created", ""),
           "共 %d 项。" % len(snap.get("items") or []),
           "",
           "还原方式：",
           "1) 在本软件里点『还原』选择本备份 —— 唯一完整的方式；",
           "2) 或双击同目录 restore-all.reg 导入；",
           "3) 快速启动类还原请用管理员执行：powercfg /h off",
           ""]
    out.append("注意：restore-all.reg 只能还原注册表里的内容")
    if reg_has:
        out.append("（本备份包含：%s）" % "、".join(dict.fromkeys(reg_has)))
    out[-1] += "。"
    if need:
        out.append("以下内容 .reg 文件管不到，必须用第 1 种方式（软件内还原）：")
        out += ["  · %s" % x for x in dict.fromkeys(need)]
    out.append("")
    out.append("还原前建议先关闭正在运行的相关软件，还原后重启生效。")
    return "\n".join(out) + "\n"


def _reg_value_expr(val, typ):
    """把 Python 值转成 .reg 文件里的右值表达式。"""
    if isinstance(val, dict) and "__b64__" in val:
        b = base64.b64decode(val["__b64__"])
        return "hex:" + ",".join("%02x" % x for x in b)
    if isinstance(val, int):
        return "dword:%08x" % val
    s = str(val)
    if int(typ or 1) == 2:  # REG_EXPAND_SZ 要写成 hex(2)，否则环境变量会被吃掉
        b = (s + "\x00").encode("utf-16-le")
        return "hex(2):" + ",".join("%02x" % x for x in b)
    return '"%s"' % s.replace("\\", "\\\\").replace('"', '\\"')


def _write_restore_reg(snap, path):
    lines = ["Windows Registry Editor Version 5.00", "",
             "; %s v%s - restore file" % (APP_NAME, VERSION), ""]
    for it in snap["items"]:
        if it["kind"] == "service" and it.get("old") is not None:
            lines.append("[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\%s]" % it["name"])
            lines.append('"Start"=dword:%08x' % int(it["old"]))
            lines.append("")
    for it in snap["items"]:
        if it["kind"] == "svc_delay":
            lines.append("[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\%s]" % it["name"])
            lines.append('"DelayedAutoStart"=dword:%08x' % int(it.get("old_delayed") or 0))
            lines.append("")
    for it in snap["items"]:
        if it["kind"] in ("startup", "startup_delay") and it.get("old"):
            grp = "StartupFolder" if it.get("kindx") == "folder" else "Run"
            hive = "HKEY_CURRENT_USER" if it["hive"] == "HKCU" else "HKEY_LOCAL_MACHINE"
            lines.append("[%s\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\%s]" % (hive, grp))
            hexs = ",".join(it["old"][i:i + 2] for i in range(0, len(it["old"]), 2))
            lines.append('"%s"=hex:%s' % (it["name"], hexs))
            lines.append("")
    for it in snap["items"]:
        if it["kind"] == "delay_task_restore" and it.get("old_approved"):
            grp = "StartupFolder" if it.get("kindx") == "folder" else "Run"
            hive = "HKEY_CURRENT_USER" if it.get("hive") == "HKCU" else "HKEY_LOCAL_MACHINE"
            lines.append("[%s\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\%s]" % (hive, grp))
            hexs = ",".join(it["old_approved"][i:i + 2]
                            for i in range(0, len(it["old_approved"]), 2))
            lines.append('"%s"=hex:%s' % (it["name"], hexs))
            lines.append("")
    for it in snap["items"]:
        # 删除类：把自启项原值写回去（启动文件夹的文件无法用 .reg 恢复，走程序内『还原』）
        if it["kind"] == "startup_delete" and it.get("kindx") == "run" and it.get("value") is not None:
            hive = "HKEY_CURRENT_USER" if it["hive"] == "HKCU" else "HKEY_LOCAL_MACHINE"
            lines.append("[%s\\%s]" % (hive, it.get("subkey") or
                                      r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"))
            lines.append('"%s"=%s' % (it["name"],
                                      _reg_value_expr(it["value"], it.get("valuetype"))))
            lines.append("")
    lines.append("; NOTE: fast-startup revert -> run as admin:  powercfg /h off")
    try:
        with open(path, "w", encoding="utf-16", newline="\r\n") as fp:
            fp.write("\n".join(lines))
    except Exception as e:
        log_line("restore.reg write failed: %r" % (e,))


def _set_service_start(name, val, dry_run=False):
    path = _SVC_BASE + "\\" + name
    cur = _read_start(name)
    if dry_run:
        return True, "[试运行] %s：%s -> %s" % (name, cur, val)
    try:
        with winreg.OpenKey(HKLM, path, 0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "Start", 0, winreg.REG_DWORD, int(val))
    except OSError:
        # 权限不够才走 PowerShell 兜底：服务名经 env 传入，不拼进脚本字符串
        # （服务名来自系统枚举，虽然少见，但仍可能带单引号把脚本截断）
        env = dict(os.environ)
        env["BD_SVC"] = name
        env["BD_VAL"] = str(int(val))
        ps = ("$p='HKLM:\\SYSTEM\\CurrentControlSet\\Services\\'+$env:BD_SVC;"
              "$v=[int]$env:BD_VAL;"
              "Set-ItemProperty $p -Name Start -Value $v -Type DWord -ErrorAction SilentlyContinue;"
              "if((Get-ItemProperty $p -Name Start).Start -ne $v){"
              "$a=Get-Acl $p;"
              "$a.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule("
              "[System.Security.Principal.WindowsIdentity]::GetCurrent().Name,'FullControl','Allow')));"
              "Set-Acl $p $a;"
              "Set-ItemProperty $p -Name Start -Value $v -Type DWord -ErrorAction SilentlyContinue};"
              "(Get-ItemProperty $p -Name Start).Start")
        run_ps(ps, timeout=60, env=env)
    now = _read_start(name)
    if now == val:
        return True, "%s：%s -> %s" % (name, cur, val)
    return False, ("%s：修改失败（当前 %s，目标 %s）。该项可能有自保护，重启后再执行一次即可。"
                   % (name, now, val))


def _delete_key_tree(root, sub):
    subs = []
    try:
        with winreg.OpenKey(root, sub, 0, winreg.KEY_READ) as k:
            i = 0
            while True:
                try:
                    subs.append(winreg.EnumKey(k, i))
                except OSError:
                    break
                i += 1
    except OSError:
        return
    for s in subs:
        _delete_key_tree(root, sub + "\\" + s)
    try:
        winreg.DeleteKey(root, sub)
    except OSError as e:
        raise e


def _delete_startup_item(it, dry_run=False):
    """彻底删除一条自启项（注册表值 / 启动文件夹里的快捷方式）。

    与『禁止』的区别：禁止保留条目只打禁用标记；删除是把条目本身移走。
    原值 / 文件在 make_backup 里已备份，可还原。
    """
    name = it.get("name", "")
    kind = it.get("kind", "run")
    if dry_run:
        return True, "[试运行] 删除自启项：%s" % name
    if kind == "folder":
        p = it.get("cmd") or ""
        if not p or not os.path.exists(p):
            return False, "启动文件夹条目不存在：%s" % p
        try:
            os.remove(p)
        except OSError as e:
            return False, "删除快捷方式失败：%s（%s）" % (p, e)
        _drop_approved(name, it.get("hive", "HKCU"), "folder")
        return True, "已删除启动快捷方式：%s" % p
    hive = it.get("hive", "HKCU")
    sub = it.get("subkey") or r"Software\Microsoft\Windows\CurrentVersion\Run"
    try:
        with winreg.OpenKey(_root_of(hive), sub, 0, winreg.KEY_SET_VALUE) as k:
            winreg.DeleteValue(k, name)
    except FileNotFoundError:
        return False, "注册表值已不存在：%s" % name
    except OSError as e:
        return False, "删除注册表值失败：%s（%s）" % (name, e)
    _drop_approved(name, hive, "run")
    return True, "已删除自启项：%s（%s）" % (name, sub)


def _drop_approved(name, hive, kind):
    """清掉 StartupApproved 里的历史标记，避免任务管理器里留『已禁用』幽灵条目。"""
    sub = _APPROVED_BASE + ("\\StartupFolder" if kind == "folder" else "\\Run")
    try:
        with winreg.OpenKey(_root_of(hive), sub, 0, winreg.KEY_SET_VALUE) as k:
            winreg.DeleteValue(k, name)
    except OSError:
        pass


def _set_task_enabled(task_name, on, dry_run=False):
    """启用 / 禁止计划任务（任务定义保留，只是不触发）。"""
    if dry_run:
        return True, "[试运行] %s任务：%s" % ("启用" if on else "禁止", task_name)
    env = dict(os.environ)
    env["BD_TASK"] = task_name
    cmd = "Enable-ScheduledTask" if on else "Disable-ScheduledTask"
    out = run_ps("%s -TaskName $env:BD_TASK -ErrorAction Stop | Out-Null; 'OK'" % cmd,
                 timeout=60, env=env)
    if "OK" in out:
        return True, ("已启用任务：%s" if on else "已禁止任务：%s") % task_name
    return False, "任务%s失败：%s（%s）" % ("启用" if on else "禁止", task_name, out.strip()[:160])


def _restore_immediate_startup(task_name, name=None, hive=None, kindx=None, dry_run=False):
    """取消延迟：删掉延迟任务 + 把原自启项恢复成「登录立刻启动」。

    原自启项还在（Run 值 / 启动文件夹快捷方式）就清掉禁用标记；
    已经不存在就只删任务，绝不凭空造一个自启条目出来。
    """
    name = name or (task_name[len(DELAY_TASK_PREFIX):]
                    if task_name.startswith(DELAY_TASK_PREFIX) else task_name)
    if dry_run:
        return True, "[试运行] 取消延迟：%s（删任务 + 恢复立即启动）" % name
    msgs = []
    ok, msg = _remove_delay_task(task_name, False)
    msgs.append(msg)
    # 任务本来就不在了不算失败，继续把自启标记恢复回去
    ok_all = ok or ("不存在" in msg)
    entry = find_startup_entry(name)
    if entry:
        _drop_approved(name, entry["hive"], entry["kind"])
        msgs.append("已恢复立即启动：%s（%s\\%s）" % (
            name, entry["hive"],
            "StartupFolder" if entry.get("kind") == "folder" else "Run"))
    else:
        _drop_approved(name, hive or "HKCU", kindx or "run")
        msgs.append("原自启项已不存在：只删任务，未新建自启条目")
    return ok_all, "；".join(msgs)


def _register_task_from_xml(task_name, xml_path, dry_run=False):
    """用备份的任务 XML 重新注册计划任务（删除后的还原路径）。"""
    if dry_run:
        return True, "[试运行] 从 XML 重建任务：%s" % task_name
    if not xml_path or not os.path.isfile(xml_path):
        return False, "备份中缺少任务 XML：%s" % task_name
    env = dict(os.environ)
    env["BD_TASK"] = task_name
    env["BD_XML"] = xml_path
    ps = (
        "$b=[IO.File]::ReadAllBytes($env:BD_XML);"
        "if($b.Length -ge 2 -and $b[0] -eq 0xFF -and $b[1] -eq 0xFE){"
        "$x=[Text.Encoding]::Unicode.GetString($b,2,$b.Length-2)}"
        "elseif($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF){"
        "$x=[Text.Encoding]::UTF8.GetString($b,3,$b.Length-3)}"
        "else{$x=[Text.Encoding]::UTF8.GetString($b)};"
        "Register-ScheduledTask -TaskName $env:BD_TASK -Xml $x -Force | Out-Null;'OK'"
    )
    out = run_ps(ps, timeout=90, env=env)
    if "OK" in out:
        return True, "已从 XML 重建任务：%s" % task_name
    return False, "重建任务失败：%s（%s）" % (task_name, out.strip()[:200])


def _backup_task_xml(task_name, bdir):
    """把 C:\\Windows\\System32\\Tasks\\<name> 原样复制到备份目录，返回相对路径。"""
    src = os.path.join(TASKS_DIR, task_name)
    if not os.path.isfile(src):
        return None
    sub = os.path.join(bdir, "tasks")
    try:
        os.makedirs(sub, exist_ok=True)
        dst = os.path.join(sub, task_name + ".xml")
        shutil.copy2(src, dst)
        return os.path.relpath(dst, bdir)
    except OSError as e:
        log_line("backup task xml failed: %s (%r)" % (task_name, e))
        return None


def _read_startup_value(hive, subkey, name):
    """读自启项原值 -> (value, type) 或 (None, None)。"""
    try:
        with winreg.OpenKey(_root_of(hive), subkey, 0, winreg.KEY_READ) as k:
            val, typ = winreg.QueryValueEx(k, name)
        if isinstance(val, bytes):
            val = {"__b64__": base64.b64encode(val).decode("ascii")}
        return val, int(typ)
    except OSError:
        return None, None


def _disable_startup_item(it, dry_run=False):
    hive = it.get("hive", "HKCU")
    folder = (it.get("kind") == "folder")
    sub = _APPROVED_BASE + ("\\StartupFolder" if folder else "\\Run")
    name = it.get("name", "")
    if dry_run:
        return True, "[试运行] 关闭自启：%s" % name
    blob = bytes([3]) + b"\x00" * 11
    try:
        with winreg.CreateKeyEx(_root_of(hive), sub, 0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, name, 0, winreg.REG_BINARY, blob)
    except OSError as e:
        return False, "设置失败：%s（%s）" % (name, e)
    chk = _read_approved_value(hive, it.get("kind", "run"), name)
    ok = bool(chk) and (chk[0] % 2 == 1)
    return ok, ("已关闭自启：%s" % name) if ok else ("设置未生效：%s" % name)


def apply_fixes(findings, backup_dir, progress=None, dry_run=False):
    """执行修复并记录日志。返回结果列表。"""
    results = []
    for f in findings:
        fx = f.get("fix")
        if not fx:
            continue
        res = {"id": f.get("id"), "title": f.get("title"), "ok": True,
               "reboot": False, "msgs": []}
        t = fx["type"]
        if progress:
            progress("执行：%s …" % f.get("title", t))
        try:
            if t == "fast_startup":
                if not dry_run:
                    _run(["powercfg", "/h", "on"], timeout=90)
                    try:
                        _set_dword(HKLM, _POWR_PATH, "HiberbootEnabled", 1)
                    except OSError as e:
                        res["ok"] = False
                        res["msgs"].append("写入注册表失败：%s" % e)
                    _run(["powercfg", "/h", "/type", "reduced"], timeout=90)
                    chk = _reg_dword(HKLM, _POWR_PATH, "HiberbootEnabled")
                    res["msgs"].append("HiberbootEnabled=%s，休眠文件%s" % (
                        chk, "已就绪" if path_exists_raw(r"C:\hiberfil.sys") else "未生成(可能需要重启)"))
                    res["reboot"] = True
                else:
                    res["msgs"].append("[试运行] 开启快速启动")
                res["msgs"].append("快速启动已开启（【关机 → 开机】时生效）")
            elif t == "svc_start":
                for n, v in fx["items"].items():
                    ok, msg = _set_service_start(n, v, dry_run)
                    res["msgs"].append(msg)
                    res["ok"] = res["ok"] and ok
                res["reboot"] = True
            elif t == "rm_svc":
                for n in fx["items"]:
                    if dry_run:
                        res["msgs"].append("[试运行] 删除服务键：%s" % n)
                        continue
                    try:
                        _delete_key_tree(HKLM, _SVC_BASE + "\\" + n)
                        res["msgs"].append("已删除服务键：%s" % n)
                    except OSError as e:
                        res["ok"] = False
                        res["msgs"].append("删除失败：%s（%s）" % (n, e))
            elif t == "startup_off":
                for it in fx["items"]:
                    ok, msg = _disable_startup_item(it, dry_run)
                    res["msgs"].append(msg)
                    res["ok"] = res["ok"] and ok
            elif t == "task_off":
                for n in fx["items"]:
                    if dry_run:
                        res["msgs"].append("[试运行] 禁用任务：%s" % n)
                        continue
                    # 任务名可由任何普通权限程序随意起，必须经 env 传入。
                    # 只把 ' 换成 '' 不够：PowerShell 把 ‘ ’ ‚ ‛ 也当单引号
                    ok, msg = _set_task_enabled(n, False)
                    res["msgs"].append(msg)
                    res["ok"] = res["ok"] and ok
            elif t == "svc_delay":
                for n in fx["items"]:
                    ok, msg = _set_service_delayed(n, True, dry_run)
                    res["msgs"].append(msg)
                    res["ok"] = res["ok"] and ok
                res["reboot"] = True
            elif t == "startup_delay":
                for it in fx["items"]:
                    tname = _task_name_for(it["name"])
                    cmd = it.get("cmd", "")
                    exe, args = (cmd, "") if it.get("kind") == "folder" else split_cmdline(cmd)
                    ok, msg = _create_delay_task(exe, args, tname, dry_run)
                    res["msgs"].append(msg)
                    if not ok:
                        res["ok"] = False
                        continue
                    ok2, msg2 = _disable_startup_item(it, dry_run)
                    res["msgs"].append(msg2)
                    res["ok"] = res["ok"] and ok2
            elif t == "delay_task_set":
                for it in fx["items"]:
                    ok, msg = _create_delay_task(it.get("exe"), it.get("args", ""),
                                                 it["task"], dry_run)
                    res["msgs"].append(msg)
                    res["ok"] = res["ok"] and ok
            elif t == "startup_delete":
                for it in fx["items"]:
                    ok, msg = _delete_startup_item(it, dry_run)
                    res["msgs"].append(msg)
                    res["ok"] = res["ok"] and ok
            elif t == "delay_task_block":
                for it in fx["items"]:
                    ok, msg = _set_task_enabled(it["task"], False, dry_run)
                    res["msgs"].append(msg)
                    res["ok"] = res["ok"] and ok
            elif t == "delay_task_del":
                for it in fx["items"]:
                    ok, msg = _remove_delay_task(it["task"], dry_run)
                    res["msgs"].append(msg)
                    res["ok"] = res["ok"] and ok
            elif t == "delay_task_restore":
                for it in fx["items"]:
                    ok, msg = _restore_immediate_startup(
                        it["task"], it.get("name"), it.get("hive"),
                        it.get("kindx"), dry_run)
                    res["msgs"].append(msg)
                    res["ok"] = res["ok"] and ok
            else:
                res["ok"] = False
                res["msgs"].append("未知修复类型：%s" % t)
        except Exception as e:
            res["ok"] = False
            res["msgs"].append("异常：%r" % (e,))
        results.append(res)
    try:
        with open(os.path.join(backup_dir, "apply_log.txt"), "a", encoding="utf-8") as fp:
            fp.write("\n== %s ==\n" % _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            for r in results:
                fp.write("[%s] %s\n" % ("OK" if r["ok"] else "FAIL", r["title"]))
                for m in r["msgs"]:
                    fp.write("    %s\n" % m)
    except Exception:
        pass
    return results


def restore_backup(backup_dir, progress=None, dry_run=False):
    """按快照还原。返回结果列表。"""
    fp = os.path.join(backup_dir, "snapshot.json")
    try:
        with open(fp, "r", encoding="utf-8") as f:
            snap = json.load(f)
    except Exception as e:
        return [{"kind": "-", "ok": False, "msgs": ["读取快照失败：%r" % (e,)]}]

    results = []
    for it in snap.get("items", []):
        k = it.get("kind")
        res = {"kind": "%s:%s" % (k, it.get("name", it.get("id", ""))), "ok": True, "msgs": []}
        try:
            if k == "service":
                if it.get("old") is None:
                    res["msgs"].append("（快照无原值，跳过）")
                else:
                    ok, msg = _set_service_start(it["name"], int(it["old"]), dry_run)
                    res["ok"] = ok
                    res["msgs"].append(msg)
            elif k == "startup":
                name = it["name"]
                if dry_run:
                    res["msgs"].append("[试运行] 还原自启标记：%s" % name)
                else:
                    sub = _APPROVED_BASE + ("\\StartupFolder" if it.get("kindx") == "folder" else "\\Run")
                    try:
                        with winreg.CreateKeyEx(_root_of(it.get("hive", "HKCU")), sub, 0,
                                                winreg.KEY_SET_VALUE) as kk:
                            if it.get("old"):
                                winreg.SetValueEx(kk, name, 0, winreg.REG_BINARY,
                                                  bytes.fromhex(it["old"]))
                                res["msgs"].append("已还原自启状态：%s" % name)
                            else:
                                try:
                                    winreg.DeleteValue(kk, name)
                                except OSError:
                                    pass
                                res["msgs"].append("已恢复为未管理状态：%s" % name)
                    except OSError as e:
                        res["ok"] = False
                        res["msgs"].append("还原失败：%s（%s）" % (name, e))
            elif k == "rm_svc":
                name = it["name"]
                if dry_run:
                    res["msgs"].append("[试运行] 重建服务键：%s" % name)
                else:
                    dump = it.get("dump") or {}
                    try:
                        with winreg.CreateKeyEx(HKLM, _SVC_BASE + "\\" + name, 0, winreg.KEY_WRITE) as kk:
                            for vn, vt, vd in dump.get("values", []):
                                if isinstance(vd, dict) and "__b64__" in vd:
                                    vd = base64.b64decode(vd["__b64__"])
                                winreg.SetValueEx(kk, vn, 0, int(vt), vd)
                        for sk in dump.get("subkeys", []):
                            winreg.CreateKeyEx(HKLM, _SVC_BASE + "\\" + name + "\\" + str(sk), 0, winreg.KEY_WRITE)
                        res["msgs"].append("已重建服务键：%s" % name)
                    except OSError as e:
                        res["ok"] = False
                        res["msgs"].append("重建失败：%s（%s）" % (name, e))
            elif k == "power":
                if dry_run:
                    res["msgs"].append("[试运行] 还原电源设置")
                else:
                    # 修复时 powercfg /h on 会同时打开「休眠」并生成 hiberfil.sys，
                    # 所以还原必须按备份的 hibernate 判断，只看 hiberboot 会把休眠留在开启状态
                    act, val = _power_restore_plan(it)
                    if act == "powercfg_off":
                        _run(["powercfg", "/h", "off"], timeout=90)
                        res["msgs"].append("已关闭休眠与快速启动（powercfg /h off，休眠文件一并移除）")
                    elif val is None:
                        res["msgs"].append("备份里没有电源状态，跳过")
                    else:
                        try:
                            _set_dword(HKLM, _POWR_PATH, "HiberbootEnabled", int(val))
                            res["msgs"].append("已还原 HiberbootEnabled=%s（保留休眠）" % val)
                        except OSError:
                            res["ok"] = False
                            res["msgs"].append("电源设置还原失败")
                    res["reboot"] = True
            elif k == "task":
                if dry_run:
                    res["msgs"].append("[试运行] 启用任务：%s" % it.get("name"))
                else:
                    ok, msg = _set_task_enabled(str(it.get("name", "")), True)
                    res["msgs"].append(msg if ok else msg + "（可能已删除）")
            elif k == "svc_delay":
                name = it["name"]
                if dry_run:
                    res["msgs"].append("[试运行] 还原延迟启动：%s -> %s" % (name, it.get("old_delayed")))
                else:
                    ok1, m1 = _set_service_delayed(name, int(it.get("old_delayed") or 0) == 1, False)
                    res["msgs"].append(m1)
                    ok2 = True
                    if it.get("old_start") is not None:
                        ok2, m2 = _set_service_start(name, int(it["old_start"]), False)
                        res["msgs"].append(m2)
                    res["ok"] = ok1 and ok2
            elif k == "startup_delay":
                name = it["name"]
                if dry_run:
                    res["msgs"].append("[试运行] 还原延迟启动项：%s" % name)
                else:
                    sub = _APPROVED_BASE + ("\\StartupFolder" if it.get("kindx") == "folder" else "\\Run")
                    try:
                        with winreg.CreateKeyEx(_root_of(it.get("hive", "HKCU")), sub, 0,
                                                winreg.KEY_SET_VALUE) as kk:
                            if it.get("old"):
                                winreg.SetValueEx(kk, name, 0, winreg.REG_BINARY, bytes.fromhex(it["old"]))
                            else:
                                try:
                                    winreg.DeleteValue(kk, name)
                                except OSError:
                                    pass
                        res["msgs"].append("已恢复自启标记：%s" % name)
                    except OSError as e:
                        res["ok"] = False
                        res["msgs"].append("恢复自启标记失败：%s（%s）" % (name, e))
                    if it.get("task"):
                        ok3, m3 = _remove_delay_task(it["task"], False)
                        res["msgs"].append(m3)
                        res["ok"] = res["ok"] and ok3
            elif k == "delay_task":
                if dry_run:
                    res["msgs"].append("[试运行] 还原延迟时长：%s -> %s"
                                       % (it.get("task"), delay_text(it.get("old_delay") or 0)))
                else:
                    ok4, m4 = _create_delay_task(it.get("exe"), it.get("args", ""),
                                                 it["task"], False,
                                                 delay_sec=int(it.get("old_delay") or 0))
                    res["msgs"].append(m4)
                    res["ok"] = ok4
            elif k == "startup_delete":
                name = it.get("name", "")
                if dry_run:
                    res["msgs"].append("[试运行] 重建自启项：%s" % name)
                elif it.get("kindx") == "folder":
                    src = os.path.join(backup_dir, it.get("backup_file") or "")
                    dst = it.get("cmd") or ""
                    if it.get("backup_file") and os.path.isfile(src) and dst:
                        try:
                            os.makedirs(os.path.dirname(dst), exist_ok=True)
                            shutil.copy2(src, dst)
                            res["msgs"].append("已恢复启动快捷方式：%s" % dst)
                        except OSError as e:
                            res["ok"] = False
                            res["msgs"].append("恢复失败：%s（%s）" % (dst, e))
                    else:
                        res["ok"] = False
                        res["msgs"].append("备份中缺少快捷方式文件，无法恢复：%s" % name)
                else:
                    hive = it.get("hive", "HKCU")
                    sub = it.get("subkey") or r"Software\Microsoft\Windows\CurrentVersion\Run"
                    val = it.get("value")
                    typ = int(it.get("valuetype") or 1)
                    if isinstance(val, dict) and "__b64__" in val:
                        val = base64.b64decode(val["__b64__"])
                    if val is None:
                        res["msgs"].append("（快照无原值，跳过）：%s" % name)
                    else:
                        try:
                            with winreg.CreateKeyEx(_root_of(hive), sub, 0,
                                                    winreg.KEY_SET_VALUE) as kk:
                                winreg.SetValueEx(kk, name, 0, typ, val)
                            res["msgs"].append("已恢复自启项：%s（%s）" % (name, sub))
                        except OSError as e:
                            res["ok"] = False
                            res["msgs"].append("恢复失败：%s（%s）" % (name, e))
                # 自启项回来了，StartupApproved 的原状态也一起还原，避免显示成「已禁用」
                if it.get("approved") and not dry_run:
                    try:
                        sub_ap = _APPROVED_BASE + ("\\StartupFolder"
                                                   if it.get("kindx") == "folder" else "\\Run")
                        with winreg.CreateKeyEx(_root_of(it.get("hive", "HKCU")), sub_ap, 0,
                                                winreg.KEY_SET_VALUE) as kk:
                            winreg.SetValueEx(kk, name, 0, winreg.REG_BINARY,
                                              bytes.fromhex(it["approved"]))
                    except OSError:
                        pass
            elif k == "delay_task_block":
                ok5, m5 = _set_task_enabled(it["task"], bool(it.get("old_enabled", True)), dry_run)
                res["msgs"].append(m5)
                res["ok"] = ok5
            elif k == "delay_task_del":
                rel = it.get("xml_file")
                src = os.path.join(backup_dir, rel) if rel else ""
                ok6, m6 = _register_task_from_xml(it["task"], src, dry_run)
                res["msgs"].append(m6)
                res["ok"] = ok6
            elif k == "delay_task_restore":
                nm = it.get("name") or it.get("task")
                rel = it.get("xml_file")
                src = os.path.join(backup_dir, rel) if rel else ""
                ok7, m7 = _register_task_from_xml(it["task"], src, dry_run)
                res["msgs"].append(m7)
                ok8 = True
                if dry_run:
                    res["msgs"].append("[试运行] 恢复自启标记：%s" % nm)
                else:
                    try:
                        sub_ap = _APPROVED_BASE + ("\\StartupFolder"
                                                   if it.get("kindx") == "folder" else "\\Run")
                        with winreg.CreateKeyEx(_root_of(it.get("hive", "HKCU")), sub_ap, 0,
                                                winreg.KEY_SET_VALUE) as kk:
                            if it.get("old_approved"):
                                winreg.SetValueEx(kk, nm, 0, winreg.REG_BINARY,
                                                  bytes.fromhex(it["old_approved"]))
                                res["msgs"].append("已恢复自启标记：%s" % nm)
                            else:
                                try:
                                    winreg.DeleteValue(kk, nm)
                                except OSError:
                                    pass
                                res["msgs"].append("已恢复为未管理状态：%s" % nm)
                    except OSError as e:
                        ok8 = False
                        res["msgs"].append("恢复自启标记失败：%s（%s）" % (nm, e))
                res["ok"] = ok7 and ok8
            else:
                res["msgs"].append("（未知类型，跳过）")
        except Exception as e:
            res["ok"] = False
            res["msgs"].append("异常：%r" % (e,))
        results.append(res)
    try:
        with open(os.path.join(backup_dir, "restore_log.txt"), "a", encoding="utf-8") as f:
            f.write("\n== %s ==\n" % _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            for r in results:
                f.write("[%s] %s\n" % ("OK" if r["ok"] else "FAIL", r["kind"]))
                for m in r["msgs"]:
                    f.write("    %s\n" % m)
    except Exception:
        pass
    return results


def list_backups():
    out = []
    if not os.path.isdir(BACKUP_DIR):
        return out
    for d in sorted(os.listdir(BACKUP_DIR), reverse=True):
        p = os.path.join(BACKUP_DIR, d)
        f = os.path.join(p, "snapshot.json")
        if os.path.isfile(f):
            try:
                with open(f, "r", encoding="utf-8") as fp:
                    snap = json.load(fp)
                out.append({"dir": p, "name": d, "created": snap.get("created", ""),
                            "count": len(snap.get("items", []))})
            except Exception:
                pass
    return out


# --------------------------------------------------------------------------
# 报告
# --------------------------------------------------------------------------

def build_report(result, applied=None):
    m = result.get("meta", {})
    met = result.get("metrics", {})
    lines = []
    lines.append("# 开机体检报告")
    lines.append("")
    lines.append("- 生成时间：%s（%s v%s）" % (
        _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), APP_NAME, VERSION))
    lines.append("- 电脑：%s ｜ 内存 %.1f GB ｜ 上次开机：%s" % (
        m.get("osName", "-"), float(m.get("ramGB") or 0), m.get("bootTime", "-")))
    lines.append("- 体检时间：%s ｜ 健康分：**%s / 100（%s）**" % (
        result.get("meta", {}).get("scanned_at", ""), result.get("score"), result.get("grade")))
    lines.append("")
    lines.append("## 关键指标")
    lines.append("")
    lines.append("| 指标 | 数值 |")
    lines.append("|---|---|")
    if met.get("last_boot_s") is not None:
        lines.append("| 上次开机耗时 | %s 秒（登录阶段 %s 秒） |" % (
            met["last_boot_s"], (met.get("profile_s") or 0) + (met.get("explorer_s") or 0)))
    lines.append("| 快速启动 | %s |" % ("已开启" if met.get("fast_startup_on") else "未开启"))
    lines.append("| 已启用自启项 | %s 个（共盘点 %s 个） |" % (
        met.get("startup_enabled"), met.get("startup_total")))
    lines.append("| 自动服务 | %s 个 |" % met.get("svc_auto"))
    lines.append("| 开机/登录计划任务 | %s 个 |" % met.get("tasks"))
    if met.get("c_total"):
        lines.append("| C 盘剩余 | %s GB / %s GB |" % (met.get("c_free"), met.get("c_total")))
    lines.append("")
    lines.append("## 问题清单")
    for f in result.get("findings", []):
        tag = SEV_CN.get(f["sev"], f["sev"])
        fixable = "🔧 可修复" if f.get("fix") else ""
        lines.append("")
        lines.append("### [%s] %s %s" % (tag, f["title"], fixable))
        if f.get("short"):
            lines.append("> %s" % f["short"])
        lines.append("")
        lines.append(f.get("detail", ""))
    if applied:
        lines.append("")
        lines.append("## 本次执行的修复")
        lines.append("")
        for r in applied:
            lines.append("- [%s] %s" % ("成功" if r.get("ok") else "失败", r.get("title")))
            for msg in r.get("msgs", []):
                lines.append("  - %s" % msg)
    lines.append("")
    lines.append("---")
    lines.append("本报告由 %s v%s 生成；所有修复均可在软件内『还原』。" % (APP_NAME, VERSION))
    return "\n".join(lines)


# --------------------------------------------------------------------------
# 命令行自测入口
# --------------------------------------------------------------------------

if __name__ == "__main__":
    print("%s v%s — 核心库自测（只读）" % (APP_NAME, VERSION))
    def _p(t):
        print("  ·", t)
    r = analyze(collect(progress=_p))
    print()
    print("健康分：%s / 100（%s）" % (r["score"], r["grade"]))
    print(r["summary"])
    print()
    for f in r["findings"]:
        flag = "[可修复]" if f.get("fix") else "        "
        print("%s %s %s" % (flag, SEV_CN[f["sev"]], f["title"]))


# --------------------------------------------------------------------------
# HTML 体检报告
#
# 目标是"能发给别人看"：单文件、不依赖外网（CSS 全内联、图表用纯 div 画），
# 双击就能在浏览器里打开，也能直接打印成 PDF。
# --------------------------------------------------------------------------

_SEV_COLOR = {
    "high": ("#c23b31", "#fdeae7", "高"),
    "mid": ("#96600a", "#fdf4e4", "中"),
    "low": ("#2a5fb4", "#e8f0fd", "低"),
    "info": ("#6d7695", "#eef1fa", "提示"),
}


def _h(s):
    """HTML 转义。"""
    return (str(s if s is not None else "")
            .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


def _boot_chart(boots):
    """开机耗时条形图：纯 div，宽度按秒数比例，颜色分档。"""
    if not boots:
        return "<p class='muted'>没有开机性能记录。</p>"
    rows = list(reversed(boots[:12]))
    mx = max(b["boot"] for b in rows) or 1
    out = ["<div class='chart'>"]
    for b in rows:
        h = b["boot"]
        pct = max(3, int(100.0 * h / mx))
        if h >= 90:
            col = "#c23b31"
        elif h >= 60:
            col = "#d08a1a"
        else:
            col = "#157a4f"
        out.append(
            "<div class='crow'>"
            "<span class='ctime'>%s</span>"
            "<span class='cbar'><i style='width:%d%%;background:%s'></i></span>"
            "<span class='cval' style='color:%s'>%d 秒</span>"
            "</div>" % (_h(b.get("time", "")), pct, col, col, h))
    out.append("</div>")
    avg = sum(b["boot"] for b in rows) // len(rows)
    out.append("<p class='muted'>最近 %d 次开机，平均 %d 秒（目标 &lt; 60 秒）</p>"
               % (len(rows), avg))
    return "".join(out)


def _score_ring(score, grade):
    """健康分：用 conic-gradient 画环形进度。"""
    try:
        s = max(0, min(100, int(score or 0)))
    except (TypeError, ValueError):
        s = 0
    if s >= 85:
        col = "#157a4f"
    elif s >= 70:
        col = "#2a5fb4"
    elif s >= 50:
        col = "#d08a1a"
    else:
        col = "#c23b31"
    return (
        "<div class='ring' style='background:conic-gradient(%s %d%%, #e4e8f5 0)'>"
        "<div class='ring-in'><b>%d</b><span>%s</span></div></div>"
        % (col, s, s, _h(grade or "")))


def _adware_block(res):
    """流氓软件专块：按家族列出，附卸载命令。"""
    aw = res.get("adware") or {}
    items = aw.get("items") or []
    if not items:
        return ""
    fams = aw.get("families") or {}
    out = ["<h2>流氓软件 / 全家桶 <span class='badge'>%d 项</span></h2>" % len(items)]
    out.append("<p class='muted'>比对特征库：目录名 %s 条 · 签名主体 %s 条 · "
               "厂商家族 %s 组（更新于 %s）</p>"
               % (_h(aw.get("db_dirs", "")), _h(aw.get("db_pubs", "")),
                  _h(aw.get("db_fams", "")), _h(aw.get("db_version", ""))))
    for fk, group in sorted(fams.items(), key=lambda kv: -len(kv[1])):
        label = group[0].get("label") or fk
        sev = "high" if any(g.get("sev") == "high" for g in group) else "mid"
        col, bg, cn = _SEV_COLOR.get(sev, _SEV_COLOR["mid"])
        out.append("<div class='card' style='border-left:4px solid %s'>" % col)
        out.append("<div class='cardhead'><b>%s</b>"
                   "<span class='tag' style='color:%s;background:%s'>%s</span></div>"
                   % (_h(label), col, bg, cn))
        out.append("<p class='why'>%s</p>" % _h(group[0].get("why", "")))
        out.append("<table class='tbl'><tr><th>名称</th><th>来源</th><th>说明</th></tr>")
        for g in group[:20]:
            out.append("<tr><td>%s</td><td>%s</td><td class='muted'>%s</td></tr>"
                       % (_h(g.get("name", "")), _h(g.get("source", "")),
                          _h((g.get("company") or "")[:40])))
        out.append("</table>")
        un = next((g.get("uninstall") for g in group if g.get("uninstall")), "")
        if un:
            out.append("<p class='cmd'>卸载命令：<code>%s</code></p>" % _h(un))
        out.append("</div>")
    return "".join(out)


def build_html_report(result, raw=None, applied=None):
    """生成单文件 HTML 报告，返回 HTML 字符串。"""
    m = (raw or {}).get("sys") or result.get("meta") or {}
    met = result.get("metrics") or {}
    findings = result.get("findings") or []
    score = result.get("score")
    grade = result.get("grade") or ""

    # 按分类归组，报告里分节展示
    cats = {}
    for f in findings:
        cats.setdefault(f.get("cat") or "其他", []).append(f)
    order = [c for c in CAT_ORDER if c in cats] + \
            [c for c in cats if c not in CAT_ORDER]

    n_high = sum(1 for f in findings if f.get("sev") == "high")
    n_mid = sum(1 for f in findings if f.get("sev") == "mid")

    css = """
*{box-sizing:border-box}
body{margin:0;padding:0;background:#eef1fa;color:#161b2c;
 font-family:-apple-system,"Segoe UI","Microsoft YaHei UI",sans-serif;
 font-size:14px;line-height:1.65}
.wrap{max-width:960px;margin:0 auto;padding:28px 22px 60px}
header{background:linear-gradient(135deg,#eef4ff 0%,#e3ebfb 50%,#f2eafd 100%);
 border:1px solid #dbe2f5;border-radius:14px;padding:22px 24px;margin-bottom:22px;
 display:flex;align-items:center;gap:24px;flex-wrap:wrap}
h1{margin:0 0 6px;font-size:21px;letter-spacing:.5px}
h2{margin:34px 0 12px;font-size:17px;border-bottom:1px solid #dbe2f5;padding-bottom:7px}
h3{margin:20px 0 8px;font-size:15px}
.muted{color:#6d7695;font-size:13px}
.ring{width:104px;height:104px;border-radius:50%;display:flex;align-items:center;
 justify-content:center;flex:0 0 auto}
.ring-in{width:82px;height:82px;border-radius:50%;background:#fff;
 display:flex;flex-direction:column;align-items:center;justify-content:center}
.ring-in b{font-size:26px;line-height:1}
.ring-in span{font-size:12px;color:#6d7695;margin-top:3px}
.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
 gap:10px;margin:16px 0}
.metric{background:#fff;border:1px solid #e4e8f5;border-radius:10px;padding:11px 14px}
.metric .k{font-size:12px;color:#6d7695}
.metric .v{font-size:17px;font-weight:600;margin-top:2px}
.badge{display:inline-block;background:#dfe2fa;color:#3c44b0;border-radius:10px;
 padding:1px 9px;font-size:12px;font-weight:600;vertical-align:middle}
.card{background:#fff;border:1px solid #e4e8f5;border-radius:10px;padding:14px 16px;
 margin:10px 0}
.cardhead{display:flex;align-items:center;gap:9px;margin-bottom:6px}
.tag{border-radius:6px;padding:1px 8px;font-size:12px;font-weight:600}
.why{margin:4px 0 8px;font-size:13px;color:#4a5474}
.tbl{width:100%;border-collapse:collapse;font-size:13px;margin:6px 0}
.tbl th{text-align:left;color:#6d7695;font-weight:600;font-size:12px;
 padding:5px 8px;border-bottom:1px solid #e4e8f5}
.tbl td{padding:5px 8px;border-bottom:1px solid #f1f4fb;vertical-align:top}
.cmd{margin:8px 0 0;font-size:12px;color:#4a5474}
code{background:#f1f4fb;border-radius:4px;padding:1px 6px;font-size:12px;
 font-family:Consolas,monospace;word-break:break-all}
.chart{margin:8px 0}
.crow{display:flex;align-items:center;gap:10px;margin:4px 0;font-size:12px}
.ctime{color:#6d7695;flex:0 0 108px;white-space:nowrap}
.cbar{flex:1;background:#eef1fa;border-radius:3px;height:12px;overflow:hidden}
.cbar i{display:block;height:100%;border-radius:3px}
.cval{flex:0 0 52px;text-align:right;font-weight:600}
pre.detail{background:#f7f9fe;border:1px solid #e4e8f5;border-radius:8px;
 padding:11px 13px;font-size:12.5px;white-space:pre-wrap;word-break:break-word;
 font-family:inherit;color:#3a4160;margin:6px 0 0}
footer{margin-top:44px;padding-top:14px;border-top:1px solid #dbe2f5;
 color:#8a93ad;font-size:12px;text-align:center}
@media print{
 body{background:#fff}
 .wrap{max-width:none;padding:0}
 header{border:none;background:#fff;border-bottom:2px solid #dbe2f5;border-radius:0}
 .card,.metric{break-inside:avoid;border-color:#ccc}
 h2{break-after:avoid}
}
"""

    h = ["<!DOCTYPE html><html lang='zh-CN'><head><meta charset='utf-8'>",
         "<meta name='viewport' content='width=device-width,initial-scale=1'>",
         "<title>开机体检报告 - %s</title>" % _h(m.get("osName") or "本机"),
         "<style>%s</style></head><body><div class='wrap'>" % css]

    # ---- 头部 ----
    h.append("<header>")
    h.append(_score_ring(score, grade))
    h.append("<div style='flex:1;min-width:240px'>")
    h.append("<h1>开机体检报告</h1>")
    h.append("<p class='muted' style='margin:0'>%s ｜ 内存 %.1f GB ｜ 上次开机 %s</p>"
             % (_h(m.get("osName") or "-"), float(m.get("ramGB") or 0),
                _h(m.get("bootTime") or "-")))
    h.append("<p class='muted' style='margin:4px 0 0'>体检时间 %s ｜ %s v%s</p>"
             % (_h(result.get("meta", {}).get("scanned_at") or
                   _dt.datetime.now().strftime("%Y-%m-%d %H:%M")),
                _h(APP_NAME), _h(VERSION)))
    h.append("</div></header>")

    # ---- 关键指标 ----
    h.append("<div class='metrics'>")
    if met.get("last_boot_s") is not None:
        h.append("<div class='metric'><div class='k'>上次开机耗时</div>"
                 "<div class='v'>%s 秒</div></div>" % met["last_boot_s"])
    h.append("<div class='metric'><div class='k'>健康分</div><div class='v'>%s / 100</div>"
             "</div>" % _h(score))
    h.append("<div class='metric'><div class='k'>高 / 中风险</div><div class='v'>%d / %d</div>"
             "</div>" % (n_high, n_mid))
    h.append("<div class='metric'><div class='k'>自启项</div><div class='v'>%s 个</div></div>"
             % _h(met.get("startup_enabled")))
    h.append("<div class='metric'><div class='k'>自动服务</div><div class='v'>%s 个</div>"
             "</div>" % _h(met.get("svc_auto")))
    if met.get("c_total"):
        h.append("<div class='metric'><div class='k'>C 盘剩余</div><div class='v'>%s GB</div>"
                 "</div>" % _h(met.get("c_free")))
    h.append("</div>")

    # ---- 开机趋势 ----
    boots = ((raw or {}).get("events") or {}).get("boots") or []
    if boots:
        h.append("<h2>开机耗时趋势</h2>")
        h.append(_boot_chart(boots))

    # ---- 流氓软件（单独提到前面，用户最关心） ----
    h.append(_adware_block(raw or {}))

    # ---- 问题清单 ----
    h.append("<h2>问题清单 <span class='badge'>%d 项</span></h2>" % len(findings))
    if not findings:
        h.append("<p class='muted'>没有发现问题。</p>")
    for cat in order:
        fs = cats[cat]
        h.append("<h3>%s <span class='badge'>%d</span></h3>" % (_h(cat), len(fs)))
        for f in fs:
            col, bg, cn = _SEV_COLOR.get(f.get("sev"), _SEV_COLOR["info"])
            h.append("<div class='card' style='border-left:4px solid %s'>" % col)
            h.append("<div class='cardhead'><b>%s</b>"
                     "<span class='tag' style='color:%s;background:%s'>%s</span></div>"
                     % (_h(f.get("title")), col, bg, cn))
            if f.get("short"):
                h.append("<p class='muted' style='margin:0 0 6px'>%s</p>"
                         % _h(f.get("short")))
            if f.get("detail"):
                h.append("<pre class='detail'>%s</pre>" % _h(f.get("detail")))
            if f.get("fix") and f.get("fix_desc"):
                h.append("<p class='cmd'>修复方式：%s</p>" % _h(f.get("fix_desc")))
            h.append("</div>")

    # ---- 已执行的操作 ----
    if applied:
        h.append("<h2>本次执行的操作</h2><div class='card'><table class='tbl'>")
        h.append("<tr><th>项目</th><th>操作</th><th>结果</th></tr>")
        for a in applied:
            h.append("<tr><td>%s</td><td>%s</td><td>%s</td></tr>"
                     % (_h(a.get("title", "")), _h(a.get("op", "")),
                        _h(a.get("result", ""))))
        h.append("</table></div>")

    h.append("<footer>由 %s v%s 生成 ｜ 所有修复均先备份，可在「操作 → 还原备份」回退</footer>"
             % (_h(APP_NAME), _h(VERSION)))
    h.append("</div></body></html>")
    return "".join(h)


def write_html_report(result, raw=None, path=None, applied=None):
    """把 HTML 报告写到磁盘，返回路径。"""
    html = build_html_report(result, raw=raw, applied=applied)
    if not path:
        ensure_dirs()
        ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        path = os.path.join(BASE_DIR, "体检报告-%s.html" % ts)
    with open(path, "w", encoding="utf-8") as fp:
        fp.write(html)
    return path
