# -*- coding: utf-8 -*-
"""拖动卡顿实测：真实鼠标消息拖动窗口，读程序内探针统计。

用法：python _drag_probe.py            # 跑三组对比
     python _drag_probe.py acrylic     # 只跑指定一组
"""
import ctypes
import json
import os
import subprocess
import sys
import time
from ctypes import wintypes

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable
user32 = ctypes.WinDLL("user32", use_last_error=True)

# 64 位下 HWND 是 8 字节指针。不显式声明 argtypes，ctypes 会按 32 位 int 传参，
# 句柄高位被截断 → 操作到错误的窗口，GetWindowRect 返回别人的矩形。
user32.IsWindowVisible.argtypes = [wintypes.HWND]
user32.IsWindowVisible.restype = wintypes.BOOL
user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
user32.GetWindowTextLengthW.restype = ctypes.c_int
user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
user32.GetWindowTextW.restype = ctypes.c_int
user32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
user32.GetWindowRect.restype = wintypes.BOOL
user32.SetForegroundWindow.argtypes = [wintypes.HWND]
user32.SetForegroundWindow.restype = wintypes.BOOL
user32.BringWindowToTop.argtypes = [wintypes.HWND]
user32.BringWindowToTop.restype = wintypes.BOOL
user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT,
                                wintypes.WPARAM, wintypes.LPARAM]
user32.PostMessageW.restype = wintypes.BOOL
user32.GetDpiForWindow.argtypes = [wintypes.HWND]
user32.GetDpiForWindow.restype = wintypes.UINT
user32.GetSystemMetrics.argtypes = [ctypes.c_int]
user32.GetSystemMetrics.restype = ctypes.c_int
user32.SendInput.argtypes = [wintypes.UINT, ctypes.c_void_p, ctypes.c_int]
user32.SendInput.restype = wintypes.UINT
user32.SetCursorPos.argtypes = [ctypes.c_int, ctypes.c_int]
user32.SetCursorPos.restype = wintypes.BOOL
user32.GetCursorPos.argtypes = [ctypes.POINTER(wintypes.POINT)]
user32.GetCursorPos.restype = wintypes.BOOL
user32.IsWindow.argtypes = [wintypes.HWND]
user32.IsWindow.restype = wintypes.BOOL
user32.IsIconic.argtypes = [wintypes.HWND]
user32.IsIconic.restype = wintypes.BOOL
user32.GetForegroundWindow.restype = wintypes.HWND
user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
user32.ShowWindow.restype = wintypes.BOOL
user32.SetWindowPos.argtypes = [wintypes.HWND, wintypes.HWND, ctypes.c_int,
                               ctypes.c_int, ctypes.c_int, ctypes.c_int,
                               wintypes.UINT]
user32.SetWindowPos.restype = wintypes.BOOL
user32.SwitchToThisWindow.argtypes = [wintypes.HWND, wintypes.BOOL]
user32.SwitchToThisWindow.restype = None
SW_RESTORE = 9

# DWM 合成节拍：DwmFlush 会阻塞到下一帧提交完成。
# 拖动时如果 DWM 每帧都要重算亚克力模糊，这里就会从 ~16.7ms 涨上去。
dwmapi = ctypes.WinDLL("dwmapi")
dwmapi.DwmFlush.restype = ctypes.c_long

_SAMPLE = {"on": False, "gaps": []}


def _frame_sampler():
    import threading

    def loop():
        while _SAMPLE["on"]:
            a = time.perf_counter()
            dwmapi.DwmFlush()
            b = time.perf_counter()
            _SAMPLE["gaps"].append((b - a) * 1000.0)

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return t


def frame_sample_start():
    _SAMPLE["on"] = True
    _SAMPLE["gaps"] = []
    return _frame_sampler()


def frame_sample_stop():
    _SAMPLE["on"] = False
    time.sleep(0.05)
    g = sorted(_SAMPLE["gaps"])
    if not g:
        return "n=0"
    def q(p):
        return g[min(len(g) - 1, int(len(g) * p))]
    return ("n=%d p50=%.1f p90=%.1f p99=%.1f max=%.1f 掉帧(>20ms)=%d"
            % (len(g), q(0.5), q(0.9), q(0.99), g[-1],
               sum(1 for v in g if v > 20.0)))

# ---------------- SendInput 结构 ----------------
class MOUSEINPUT(ctypes.Structure):
    _fields_ = [("dx", wintypes.LONG), ("dy", wintypes.LONG),
                ("mouseData", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                ("time", wintypes.DWORD), ("dwExtraInfo", ctypes.c_void_p)]


class KEYBDINPUT(ctypes.Structure):
    _fields_ = [("wVk", wintypes.WORD), ("wScan", wintypes.WORD),
                ("dwFlags", wintypes.DWORD), ("time", wintypes.DWORD),
                ("dwExtraInfo", ctypes.c_void_p)]


class HARDWAREINPUT(ctypes.Structure):
    _fields_ = [("uMsg", wintypes.DWORD), ("wParamL", wintypes.WORD),
                ("wParamH", wintypes.WORD)]


class _INPUTUNION(ctypes.Union):
    _fields_ = [("mi", MOUSEINPUT), ("ki", KEYBDINPUT), ("hi", HARDWAREINPUT)]


class INPUT(ctypes.Structure):
    _anonymous_ = ("u",)
    _fields_ = [("type", wintypes.DWORD), ("u", _INPUTUNION)]


assert ctypes.sizeof(INPUT) == 40, ctypes.sizeof(INPUT)   # x64 下必须是 40

MOVE, LEFTDOWN, LEFTUP, ABSOLUTE = 0x0001, 0x0002, 0x0004, 0x8000


def _send(flags, x=0, y=0):
    inp = INPUT(type=0)
    inp.mi = MOUSEINPUT(dx=x, dy=y, mouseData=0, dwFlags=flags, time=0, dwExtraInfo=None)
    user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(INPUT))


def _abs(x, y):
    vx = user32.GetSystemMetrics(76)   # SM_CXVIRTUALSCREEN
    vy = user32.GetSystemMetrics(77)
    ox = user32.GetSystemMetrics(78)   # SM_XVIRTUALSCREEN
    oy = user32.GetSystemMetrics(79)
    return (int((x - ox) * 65535 / max(1, vx - 1)),
            int((y - oy) * 65535 / max(1, vy - 1)))


def move_to(x, y):
    """SetCursorPos 用和 GetWindowRect 同一套坐标系，不会被 DPI 虚拟化搞偏；
    再补一个相对 0 移动，让系统真的生成 WM_MOUSEMOVE。"""
    user32.SetCursorPos(int(x), int(y))
    _send(MOVE, 0, 0)


def cursor_pos():
    pt = wintypes.POINT()
    user32.GetCursorPos(ctypes.byref(pt))
    return pt.x, pt.y


def find_window(substr):
    found = []

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def cb(hwnd, _lp):
        if not user32.IsWindowVisible(hwnd):
            return True
        n = user32.GetWindowTextLengthW(hwnd)
        if n <= 0:
            return True
        buf = ctypes.create_unicode_buffer(n + 2)
        user32.GetWindowTextW(hwnd, buf, n + 2)
        if substr in buf.value:
            found.append((hwnd, buf.value))
        return True

    user32.EnumWindows(cb, 0)
    return found


def rect_of(hwnd):
    r = wintypes.RECT()
    user32.GetWindowRect(hwnd, ctypes.byref(r))
    return r.left, r.top, r.right, r.bottom


def drag(hwnd, distance=360, steps=60, settle=0.0, track=None, mode="move"):
    """在标题栏空白处按下，横向拖 distance 物理像素，再松手。"""
    try:
        dpi = user32.GetDpiForWindow(hwnd) or 96
    except Exception:
        dpi = 96
    scale = dpi / 96.0
    l, t, r, b = rect_of(hwnd)
    w = r - l
    if mode == "resize":                  # 抓右边缘往左拖 = 缩小窗口
        x0 = r - 4
        y0 = t + (b - t) // 2
    else:
        x0 = l + int(w * 0.52)
        y0 = t + int(15 * scale)          # 菜单栏垂直中心
    move_to(x0, y0)
    time.sleep(0.12)
    _send(LEFTDOWN)
    time.sleep(settle)
    t_start = time.perf_counter()
    iconic = -1
    valid = 0
    for i in range(1, steps + 1):
        move_to(x0 + int(distance * i / steps), y0)
        if track is not None:
            if user32.IsIconic(hwnd):
                if iconic < 0:
                    iconic = i
            else:
                tl, tt, tr, tb = rect_of(hwnd)
                if (tr - tl) > 300 and (tb - tt) > 200:
                    track.append(tl if mode != "resize" else tr)
                    valid += 1
        # 模拟人手：每步间隔 ~8ms（125Hz 鼠标）
        time.sleep(0.008)
    t_end = time.perf_counter()
    _send(LEFTUP)
    drag.last_iconic = iconic
    drag.last_valid = valid
    return (t_end - t_start) * 1000.0, steps


def run(tag, env_extra, prof_path, size=None, mode="move", script="boot_doctor.py"):
    env = dict(os.environ)
    env.update(env_extra)
    env["BOOTDOC_PROF"] = prof_path
    env["BOOTDOC_NOSCAN"] = "1"
    if os.path.exists(prof_path):
        os.remove(prof_path)
    proc = subprocess.Popen([PY, os.path.join(HERE, script)],
                            cwd=HERE, env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    before = after = None
    follower = -1
    track = []
    ms = steps = 0.0
    fg_ok = None
    iconic_at = -1
    valid_n = 0
    fs = "n=0"
    try:
        hwnd = None
        for _ in range(80):
            time.sleep(0.25)
            hits = [h for h in find_window("开机体检") if h[0]]
            if hits:
                hwnd = hits[0][0]
                break
        if not hwnd:
            return {"tag": tag, "error": "窗口没出现"}
        time.sleep(1.8)                        # 等首次绘制 / 自动扫描第一波过去
        # 强行把窗口切到前台：脚本进程通常没有前台权限，SetForegroundWindow 会静默失败，
        # 那样所有 SendInput 都会被别人收走，测出来全是"没动"。
        user32.ShowWindow(hwnd, SW_RESTORE)
        user32.SwitchToThisWindow(hwnd, True)
        user32.SetForegroundWindow(hwnd)
        time.sleep(0.35)
        fg_ok = (user32.GetForegroundWindow() == hwnd)
        if size:
            user32.SetWindowPos(hwnd, None, 120, 120, int(size[0]), int(size[1]), 0x0004)
        else:
            user32.SetWindowPos(hwnd, None, 120, 120, 0, 0, 0x0001 | 0x0004)  # NOSIZE|NOZORDER
        time.sleep(0.4)
        # 先点一下表格区把窗口激活（无边框窗口首次点击只激活，不进入拖动）
        bl, bt, br, bb = rect_of(hwnd)
        move_to(bl + 200, bt + 200)
        time.sleep(0.1)
        _send(LEFTDOWN)
        time.sleep(0.05)
        _send(LEFTUP)
        time.sleep(0.5)
        move_to(60, 60)                        # 鼠标离开窗口
        time.sleep(0.3)
        before = rect_of(hwnd)

        dist = -300 if mode == "resize" else 360
        if mode == "click":                # 只点一下标题栏，不移动：验证会不会闪
            l2, t2, r2, b2 = rect_of(hwnd)
            move_to(l2 + (r2 - l2) // 2, t2 + 15)
            time.sleep(0.15)
            _send(LEFTDOWN)
            time.sleep(0.12)
            _send(LEFTUP)
            time.sleep(0.4)
            track = []
            frame_sample_start()
            time.sleep(0.5)
            fs = frame_sample_stop()
            ms, steps = 0.0, 0
        else:
            # 预热一次，避免首次拖动把冷启动算进去
            drag(hwnd, distance=dist, steps=20, mode=mode)
            time.sleep(0.7)
            track = []
            frame_sample_start()
            ms, steps = drag(hwnd, distance=dist, steps=60, track=track, mode=mode)
            fs = frame_sample_stop()
        time.sleep(0.6)
        after = rect_of(hwnd)
        # 是否真的跟手：移动看左边界右移，缩放看右边界左移
        follower = 0
        if track:
            if mode == "resize":
                base = before[2]
                follower = sum(1 for v in track if v < base - 1)
            else:
                base = before[0]
                follower = sum(1 for v in track if v > base + 1)
        iconic_at = getattr(drag, "last_iconic", -1)
        valid_n = getattr(drag, "last_valid", 0)
        # 关窗口，让探针落盘
        user32.PostMessageW(hwnd, 0x0010, 0, 0)   # WM_CLOSE
    finally:
        for _ in range(60):
            if proc.poll() is not None:
                break
            time.sleep(0.1)
        if proc.poll() is None:
            proc.kill()
        try:
            proc.wait(timeout=5)
        except Exception:
            pass
    out = {"tag": tag, "drag_ms": round(ms, 1), "steps": steps,
           "before": before, "after": after, "follower": follower,
           "fg_ok": fg_ok, "iconic_at": iconic_at, "valid_rect": valid_n,
           "frames": fs,
           "track_head": track[:4], "track_tail": track[-4:]}
    if os.path.exists(prof_path):
        out["prof"] = open(prof_path, encoding="utf-8").read().strip()
    else:
        out["prof"] = "(没有输出)"
    return out


_OLD = "boot_doctor.py.bak_拖动卡顿20261122"
_ON = {"BOOTDOC_ACRYLIC": "1", "BOOTDOC_CHROME": "1"}

CASES = {
    "move_now":   dict(env=_ON),
    "move_old":   dict(env=_ON, script=_OLD),
    "small_now":  dict(env=_ON, size=(1300, 860)),
    "small_old":  dict(env=_ON, size=(1300, 860), script=_OLD),
    "resize_now": dict(env=_ON, mode="resize"),
    "resize_old": dict(env=_ON, mode="resize", script=_OLD),
    "resize_low1": dict(env=dict(_ON, BOOTDOC_LOW_STATE="1"), mode="resize"),
    "resize_low4": dict(env=dict(_ON, BOOTDOC_LOW_STATE="4"), mode="resize"),
    "click":      dict(env=_ON, mode="click"),
    "blur3":      dict(env={"BOOTDOC_ACRYLIC": "1", "BOOTDOC_CHROME": "1",
                           "BOOTDOC_ACCENT": "3"}),
}


def main():
    only = sys.argv[1] if len(sys.argv) > 1 else None
    keys = [only] if only in CASES else list(CASES)
    for k in keys:
        prof = os.path.join(HERE, "_prof_%s.txt" % k)
        cfg = CASES[k]
        r = run(k, cfg.get("env", {}), prof, size=cfg.get("size"),
                mode=cfg.get("mode", "move"), script=cfg.get("script", "boot_doctor.py"))
        print("=" * 60)
        print("[%s] drag_total_ms=%s  steps=%s  before=%s  after=%s"
              % (r["tag"], r.get("drag_ms"), r.get("steps"), r.get("before"), r.get("after")))
        print("  前台成功=%s  最小化于第%s步  有效rect数=%s  跟手步数=%s"
              % (r.get("fg_ok"), r.get("iconic_at"), r.get("valid_rect"), r.get("follower")))
        print("  DWM 帧间隔: %s" % r.get("frames"))
        print("  head=%s tail=%s" % (r.get("track_head"), r.get("track_tail")))
        if r.get("error"):
            print("  ERROR:", r["error"])
        print(r.get("prof", ""))
        sys.stdout.flush()


if __name__ == "__main__":
    main()
