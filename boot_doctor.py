# -*- coding: utf-8 -*-
"""开机体检大师 · GUI 主程序

用法：
    双击 启动体检.bat （自动请求管理员权限）
    或 python boot_doctor.py

设计取向：Windows 管理工具（AutoRuns / 任务管理器）那一类——菜单 + 工具栏 + 密集表格 +
属性面板，不做卡片堆叠。所有修复前自动备份，可随时还原。
"""
import ctypes
import csv
import html
import inspect
import os
import subprocess
import sys
import time
import traceback

from PyQt5.QtCore import (QEvent, QFileInfo, QObject, QRect, QSize, Qt, QThread, QTimer,
                          pyqtSignal)
from PyQt5.QtGui import (QBrush, QColor, QCursor, QFont, QIcon, QLinearGradient,
                         QPainter, QPalette, QPen, QPixmap, QTextOption)
from PyQt5.QtWidgets import QProxyStyle, QStyleOptionViewItem
from PyQt5.QtWidgets import (
    QAbstractItemView, QAction, QApplication, QButtonGroup, QCheckBox, QComboBox,
    QDialog, QDialogButtonBox, QFileDialog, QFileIconProvider, QFrame, QGridLayout, QHBoxLayout,
    QHeaderView, QLabel, QLineEdit, QListWidget, QListWidgetItem, QMainWindow, QMenu,
    QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QRadioButton, QSizePolicy,
    QSpinBox, QSplitter, QStackedWidget, QStyle, QTabWidget, QTextBrowser, QToolBar,
    QTreeWidget,
    QTreeWidgetItem, QVBoxLayout, QWidget,
)

import boot_core as bc

# --------------------------------------------------------------------------
# 性能探针：BOOTDOC_PROF=<输出文件> 时启用，未设置时全部走 if not _PROF_PATH 直接返回
# 用途只有一个——拖动窗口卡平时，搞清楚时间到底花在 Qt 重绘还是别的地方
# --------------------------------------------------------------------------
_PROF_PATH = os.environ.get("BOOTDOC_PROF") or ""
PROF = {}


def _prof_reset():
    PROF.clear()
    PROF.update({
        "paint": [0, 0.0, 0.0],      # 次数 / 总秒 / 最大秒
        "hittest": [0, 0.0, 0.0],
        "resize": [0, 0.0, 0.0],
        "sizes": set(),
        "gaps": [],                  # 相邻两帧间隔（毫秒），用来看实际帧率
        "paint_ms": [],
        "_last_t": 0.0,
    })


_prof_reset()


def _prof_flush():
    if not _PROF_PATH:
        return
    try:
        d = PROF
        def row(k):
            n, tot, mx = d[k]
            avg = (tot * 1000.0 / n) if n else 0.0
            return "%s: n=%d avg=%.2fms max=%.2fms total=%.0fms" % (
                k, n, avg, mx * 1000.0, tot * 1000.0)
        gaps = sorted(d["gaps"])
        pm = sorted(d["paint_ms"])
        def pct(arr, q):
            if not arr:
                return 0.0
            return arr[min(len(arr) - 1, int(len(arr) * q))]
        lines = [
            "acrylic_on=%s  theme=%s" % (_ACRYLIC_ON, _THEME),
            row("paint"),
            row("hittest"),
            row("resize"),
            "move: n=%d" % (d.get("move") or [0])[0],
            "win_sizes=%s" % sorted(d["sizes"]),
            "frame_gap_ms: n=%d p50=%.1f p90=%.1f max=%.1f" % (
                len(gaps), pct(gaps, 0.5), pct(gaps, 0.9), gaps[-1] if gaps else 0),
            "paint_ms: n=%d p50=%.2f p90=%.2f max=%.2f" % (
                len(pm), pct(pm, 0.5), pct(pm, 0.9), pm[-1] if pm else 0),
        ]
        for t in (d.get("trace") or [])[:20]:
            lines.append("trace: " + t)
        with open(_PROF_PATH, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    except Exception:
        pass


import atexit as _atexit
_atexit.register(_prof_flush)


# --------------------------------------------------------------------------
# 毛玻璃外观：优先 DWM 亚克力（真模糊），不支持时降级为渐变伪毛玻璃
# --------------------------------------------------------------------------

USE_ACRYLIC = os.environ.get("BOOTDOC_ACRYLIC", "1") != "0"
USE_CUSTOM_CHROME = os.environ.get("BOOTDOC_CHROME", "1") != "0"
ACRYLIC_ACRYLIC = 4     # ACCENT_ENABLE_ACRYLICBLURBEHIND
ACRYLIC_BLUR = 3        # ACCENT_ENABLE_BLURBEHIND（Win10 早期版本没有亚克力时用）

_ACRYLIC_ON = False     # 运行时状态：DWM 有没有真的接手。影响窗口渐变是否带透明度


class _ACCENT_POLICY(ctypes.Structure):
    _fields_ = [("AccentState", ctypes.c_int),
                ("AccentFlags", ctypes.c_int),
                ("GradientColor", ctypes.c_uint),
                ("AnimationId", ctypes.c_int)]


class _WINCOMPATTRDATA(ctypes.Structure):
    _fields_ = [("Attribute", ctypes.c_int),
                ("Data", ctypes.POINTER(ctypes.c_int)),
                ("SizeOfData", ctypes.c_size_t)]


def _abgr(rgb, alpha):
    """DWM 的 GradientColor 是 AABBGGRR，不是 AARRGGBB。"""
    r, g, b = rgb
    return (int(alpha) << 24) | (b << 16) | (g << 8) | r


def _set_accent(hwnd, state, flags, color):
    try:
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        accent = _ACCENT_POLICY()
        accent.AccentState = state
        accent.AccentFlags = flags
        accent.GradientColor = color
        data = _WINCOMPATTRDATA()
        data.Attribute = 19                       # WCA_ACCENT_POLICY
        data.Data = ctypes.cast(ctypes.pointer(accent), ctypes.POINTER(ctypes.c_int))
        data.SizeOfData = ctypes.sizeof(accent)
        fn = user32.SetWindowCompositionAttribute
        fn.argtypes = [ctypes.c_void_p, ctypes.POINTER(_WINCOMPATTRDATA)]
        fn.restype = ctypes.c_bool
        return bool(fn(ctypes.c_void_p(hwnd), ctypes.byref(data)))
    except Exception:
        return False


def _set_dark_title(hwnd, dark):
    """标题栏跟随深色主题（Win10 19041+ 支持；不支持就算了，不影响功能）。"""
    try:
        dwm = ctypes.WinDLL("dwmapi", use_last_error=True)
        v = ctypes.c_int(1 if dark else 0)
        for attr in (20, 19):     # DWMWA_USE_IMMERSIVE_DARK_MODE，新旧版本编号不同
            if dwm.DwmSetWindowAttribute(ctypes.c_void_p(hwnd), attr,
                                         ctypes.byref(v), ctypes.sizeof(v)) == 0:
                return True
    except Exception:
        pass
    return False


ACRYLIC_TINT = {
    "light": _abgr((240, 243, 255), 0x74),
    "dark": _abgr((10, 15, 36), 0xA8),
}


def _accent_state():
    """默认亚克力。BOOTDOC_ACCENT 可强制指定 AccentState，供拖动性能对比用。"""
    v = os.environ.get("BOOTDOC_ACCENT") or ""
    if v.isdigit():
        return int(v)
    return ACRYLIC_ACRYLIC


def enable_glass(win, theme):
    """给顶层窗口开亚克力。成功返回 True；任何异常或系统不支持都静默降级。"""
    global _ACRYLIC_ON
    if not USE_ACRYLIC:
        return _ACRYLIC_ON
    try:
        hwnd = int(win.winId())
        if not hwnd:
            return False
        _set_dark_title(hwnd, theme == "dark")
        win.setAttribute(Qt.WA_TranslucentBackground, True)
        win.setAutoFillBackground(False)
        tint = ACRYLIC_TINT["dark" if theme == "dark" else "light"]
        st = _accent_state()
        ok = _set_accent(hwnd, st, 2 if st == ACRYLIC_ACRYLIC else 0, tint)
        if not ok:
            ok = _set_accent(hwnd, ACRYLIC_BLUR, 0, tint)
        if not ok:
            win.setAttribute(Qt.WA_TranslucentBackground, False)
            _ACRYLIC_ON = False
            return False
        _ACRYLIC_ON = True
        return True
    except Exception:
        try:
            win.setAttribute(Qt.WA_TranslucentBackground, False)
        except Exception:
            pass
        _ACRYLIC_ON = False
        return False


def retint_glass(win, theme):
    """切主题时只换 DWM 染色，不动窗口属性。"""
    if not _ACRYLIC_ON:
        return
    try:
        hwnd = int(win.winId())
        tint = ACRYLIC_TINT["dark" if theme == "dark" else "light"]
        if _GLASS_LOW:
            _set_accent(hwnd, ACRYLIC_BLUR, 0, tint)
        elif not _set_accent(hwnd, ACRYLIC_ACRYLIC, 2, tint):
            _set_accent(hwnd, ACRYLIC_BLUR, 0, tint)
        _set_dark_title(hwnd, theme == "dark")
    except Exception:
        pass


_GLASS_LOW = False       # 当前是否处于"拖动降级"状态
# 降级时用哪个 AccentState：3=BLURBEHIND（有模糊），1=纯透明渐变（无模糊）
# 用环境变量只为了做对比实验，正常运行时走默认 3。
_LOW_STATE = int(os.environ.get("BOOTDOC_LOW_STATE") or ACRYLIC_BLUR)


def set_glass_low(win, low):
    """拖动 / 缩放期间把亚克力降到 BLURBEHIND，松手恢复。

    为什么必须这么做（实测，不是推测）：
      _drag_probe.py 用 DwmFlush 量合成节拍，同一份代码只改 AccentState：
        state=4 亚克力        p50=32.6ms  (30fps)  掉帧 16/25
        state=3 BLURBEHIND    p50=16.6ms  (60fps)  掉帧 0/41
        state=5 HOSTBACKDROP  p50=16.5ms           掉帧 1/42
        state=1 无模糊渐变    p50=16.7ms            掉帧 0/43
      同时 Qt 侧 paint 全程只画了 4 帧、单帧 4.5ms —— 卡的根本不是 Python，
      是 DWM 在窗口每移动一个像素就要对整窗背后的桌面重新采样 + 高斯模糊。
      BLURBEHIND 只做一次模糊、不清洗背景，成本低一个量级，视觉上仍是真毛玻璃。
    """
    global _GLASS_LOW
    low = bool(low)
    if not _ACRYLIC_ON or _GLASS_LOW == low:
        return
    try:
        hwnd = int(win.winId())
        tint = ACRYLIC_TINT["dark" if is_dark() else "light"]
        if low:
            ok = _set_accent(hwnd, _LOW_STATE, 0, tint)
        else:
            ok = _set_accent(hwnd, ACRYLIC_ACRYLIC, 2, tint)
            if not ok:
                _set_accent(hwnd, ACRYLIC_BLUR, 0, tint)
        if ok or low:
            _GLASS_LOW = low
            if _PROF_PATH:
                PROF.setdefault("trace", []).append("glass_low=%s" % low)
    except Exception:
        pass


# --------------------------------------------------------------------------
# 配色：整套界面只从这里取色，浅色 / 深色共用一套键
# 前缀 g_ 的是"玻璃层"专用值，只给 QSS 用（半透明叠在渐变上才有层次）；
# 没有前缀的保持十六进制，因为 QColor() / 富文本也要用，认不了 rgba()。
# --------------------------------------------------------------------------

PAL = {}

_LIGHT = {
    "bg": "#eef1fa", "panel": "#ffffff", "input": "#ffffff", "head": "#e9edf9",
    "alt": "#f6f8fe", "border": "#d5dbef", "border_soft": "#e4e8f5",
    "text": "#161b2c", "muted": "#4a5474", "faint": "#6d7695",
    "accent": "#4f57c8", "accent_dark": "#3c44b0", "hover": "#e9edf9",
    "sel": "#dfe2fa", "dis": "#e5e8f2",
    "ok": "#157a4f", "warn": "#96600a", "err": "#c23b31", "info": "#2a5fb4",
    "ok_bg": "#e7f6ee", "warn_bg": "#fdf4e4", "err_bg": "#fdeae7", "info_bg": "#e8f0fd",
    "code": "#6b7490",
    # 窗口渐变（浅色：冷蓝 → 淡紫），带透明度时才能透出亚克力模糊
    "win_stops": ((0.00, (235, 241, 253)), (0.48, (223, 232, 250)), (1.00, (240, 231, 253))),
    "win_alpha": 0.92,
    "t_area": "#f7f9fe",
    "g_panel": "rgba(255, 255, 255, 150)",
    "g_panel_soft": "rgba(255, 255, 255, 105)",
    "g_panel_grad": "qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 rgba(255,255,255,232), "
                    "stop:1 rgba(255,255,255,205))",
    "g_card": "rgba(255, 255, 255, 190)",
    "g_head": "rgba(240, 244, 255, 235)",
    "g_alt": "rgba(232, 238, 252, 150)",
    "g_line": "rgba(255, 255, 255, 240)",
    "g_line_soft": "rgba(122, 134, 186, 51)",
    "g_hover": "rgba(255, 255, 255, 199)",
    "sel_solid": "#d9ddf7",
    "g_sel": "rgba(90, 98, 214, 46)",
    "g_sel_grad": "qlineargradient(x1:0, y1:0, x2:1, y2:0, "
                  "stop:0 rgba(90, 98, 214, 66), stop:1 rgba(122, 96, 220, 33))",
    "g_menu": "rgba(252, 253, 255, 245)",
    "g_scroll": "rgba(86, 96, 150, 82)",
    "g_scroll_hover": "rgba(86, 96, 150, 133)",
    "g_btn": "qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 rgba(255,255,255,242), "
             "stop:1 rgba(237,241,253,230))",
    "g_btn_hover": "qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 rgba(255,255,255,252), "
                   "stop:1 rgba(229,234,251,240))",
    "g_primary": "qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #5a63dd, stop:1 #4a3ab4)",
    "g_primary_hover": "qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #6a73ea, stop:1 #5745c6)",
    "g_hdr": "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 rgba(255,255,255,179), "
             "stop:0.55 rgba(236,240,255,133), stop:1 rgba(240,236,255,112))",
    "g_opbar": "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 rgba(255,255,255,158), "
               "stop:1 rgba(244,246,255,179))",
}

_DARK = {
    "bg": "#0b1020", "panel": "#151a2e", "input": "#1b2138", "head": "#1c2340",
    "alt": "#131a2d", "border": "#2b3459", "border_soft": "#232c4a",
    "text": "#e6e9f6", "muted": "#a3abd2", "faint": "#7d87b0",
    "accent": "#6b79ff", "accent_dark": "#8b96ff", "hover": "#1f2745",
    "sel": "#2b3369", "dis": "#1a2036",
    "ok": "#5fd6a2", "warn": "#f0b45c", "err": "#ff7d86", "info": "#79b6ff",
    "ok_bg": "#123328", "warn_bg": "#332810", "err_bg": "#3a1d24", "info_bg": "#132640",
    "code": "#95a0c6",
    # 窗口渐变（深色：近黑蓝 → 藏青 → 深蓝紫）
    "win_stops": ((0.00, (11, 16, 32)), (0.50, (23, 32, 65)), (1.00, (13, 27, 58))),
    "win_alpha": 0.88,
    "t_area": "#1b2338",
    "g_panel": "rgba(255, 255, 255, 18)",
    "g_panel_soft": "rgba(255, 255, 255, 13)",
    "g_panel_grad": "qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 rgba(255,255,255,26), "
                    "stop:1 rgba(255,255,255,10))",
    "g_card": "rgba(255, 255, 255, 26)",
    "g_head": "rgba(255, 255, 255, 11)",
    "g_alt": "rgba(255, 255, 255, 12)",
    "g_line": "rgba(255, 255, 255, 33)",
    "g_line_soft": "rgba(255, 255, 255, 18)",
    "g_hover": "rgba(255, 255, 255, 26)",
    "sel_solid": "#2c3559",
    "g_sel": "rgba(107, 121, 255, 66)",
    "g_sel_grad": "qlineargradient(x1:0, y1:0, x2:1, y2:0, "
                  "stop:0 rgba(107, 121, 255, 87), stop:1 rgba(146, 110, 255, 41))",
    "g_menu": "rgba(24, 30, 52, 247)",
    "g_scroll": "rgba(190, 200, 240, 56)",
    "g_scroll_hover": "rgba(190, 200, 240, 97)",
    "g_btn": "qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 rgba(255,255,255,31), "
             "stop:1 rgba(255,255,255,13))",
    "g_btn_hover": "qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 rgba(255,255,255,51), "
                   "stop:1 rgba(255,255,255,23))",
    "g_primary": "qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #3f5bd6, stop:1 #6d3fc4)",
    "g_primary_hover": "qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #4f6bec, stop:1 #7d4bd6)",
    "g_hdr": "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 rgba(255,255,255,26), "
             "stop:0.55 rgba(255,255,255,13), stop:1 rgba(120,140,255,18))",
    "g_opbar": "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 rgba(255,255,255,15), "
               "stop:1 rgba(120,140,255,15))",
}


_THEME = "light"


def use_theme(name):
    global _THEME
    _THEME = "dark" if name == "dark" else "light"
    PAL.clear()
    PAL.update(_DARK if name == "dark" else _LIGHT)


def is_dark():
    return _THEME == "dark"


use_theme("light")

SEV_KEY = {"high": "err", "mid": "warn", "low": "info", "info": "faint"}


def sev_color(sev):
    return PAL[SEV_KEY.get(sev, "faint")]


def sev_tint(sev):
    return PAL[{"high": "err_bg", "mid": "warn_bg",
                "low": "info_bg"}.get(sev, "head")]


def _win_gradient(p, alpha=None):
    """窗口底色渐变。开了亚克力就带透明度，让底下的模糊透上来。"""
    if alpha is None:
        a = p["win_alpha"] if _ACRYLIC_ON else 1.0
    else:
        a = alpha if _ACRYLIC_ON else 1.0
    a255 = max(0, min(255, int(round(a * 255))))
    stops = []
    for pos, rgb in p["win_stops"]:
        stops.append("stop:%.2f rgba(%d, %d, %d, %d)"
                     % (pos, rgb[0], rgb[1], rgb[2], a255))
    return "qlineargradient(x1:0, y1:0, x2:1, y2:1, %s)" % ", ".join(stops)


_BRUSH_CACHE = {}


def win_brush(w, h):
    """窗口底色画刷。开了亚克力时要带透明度，模糊才透得上来。

    注意：QMainWindow 在 WA_TranslucentBackground 下不会绘制 QSS 里的 background，
    必须在 paintEvent 里自己填，否则整窗透明、只剩窗外模糊。

    这里做了缓存：拖动 / 缩放窗口时 paintEvent 每帧都调，QLinearGradient 的构造
    和 3 次 setColorAt 虽然不贵，但完全没必要每帧重做。
    """
    key = (int(w), int(h), _ACRYLIC_ON, _THEME)
    hit = _BRUSH_CACHE.get(key)
    if hit is not None:
        return hit
    a = 224 if _ACRYLIC_ON else 255
    g = QLinearGradient(0, 0, max(1, w), max(1, h))
    for pos, rgb in PAL["win_stops"]:
        g.setColorAt(pos, QColor(rgb[0], rgb[1], rgb[2], a))
    br = QBrush(g)
    # 只留最近几个尺寸，避免拖动时无限增长
    if len(_BRUSH_CACHE) > 8:
        _BRUSH_CACHE.clear()
    _BRUSH_CACHE[key] = br
    return br


def build_qss():
    p = dict(PAL)
    p["g_win"] = _win_gradient(p)
    p["g_dlg"] = _win_gradient(p, 0.985)
    return """
QWidget { color: %(text)s; font-family: "Segoe UI", "Microsoft YaHei UI", sans-serif; }
QMainWindow { background: %(g_win)s; }
QDialog { background: %(g_dlg)s; }
QMenuBar { background: transparent; border-bottom: 1px solid %(g_line_soft)s;
           min-height: 28px; }
QMenuBar::item { background: transparent; padding: 5px 10px; margin: 2px 1px;
                 border-radius: 5px; }
QMenuBar::item:selected { background: %(g_hover)s; }
QMenu { background: %(g_menu)s; border: 1px solid %(g_line)s; border-radius: 8px;
        padding: 4px; }
QMenu::item { padding: 6px 30px 6px 24px; border-radius: 5px; }
QMenu::item:selected { background: %(g_sel_grad)s; color: %(text)s; }
QMenu::item:disabled { color: %(faint)s; }
QMenu::separator { height: 1px; background: %(g_line_soft)s; margin: 4px 8px; }
QToolBar { background: transparent; border: none;
           border-bottom: 1px solid %(g_line_soft)s;
           padding: 4px 8px; spacing: 4px; }
QToolBar::separator { background: %(g_line_soft)s; width: 1px; margin: 5px 7px; }
QToolButton { background: transparent; border: 1px solid transparent; border-radius: 6px;
              padding: 4px 8px; color: %(text)s; }
QToolButton:hover { background: %(g_hover)s; border-color: %(g_line)s; }
QToolButton:pressed { background: %(g_sel)s; }
QToolButton:disabled { color: %(faint)s; }
QFrame#hdr { background: %(g_hdr)s; border: none;
             border-bottom: 1px solid %(g_line)s; }
QFrame#opbar { background: %(g_opbar)s; border: none;
               border-top: 1px solid %(g_line)s; }
QFrame#apphead { background: %(g_card)s; border: 1px solid %(g_line)s;
                 border-radius: 10px; }
QLabel#score { font-size: 26px; font-weight: 600; }
QLabel#grade { font-size: 13px; font-weight: 600; }
QLabel#summary { font-size: 12px; color: %(muted)s; }
QLabel#meta { font-size: 11px; color: %(faint)s; }
QLabel#hint { font-size: 11px; color: %(faint)s; }
QLabel#adminOk { color: %(ok)s; font-size: 11px; }
QLabel#adminNo { color: %(warn)s; font-size: 11px; }
QLabel#appname { font-size: 13px; font-weight: 600; }
QListWidget#nav { background: %(g_panel_soft)s; border: none;
                  border-right: 1px solid %(g_line_soft)s; outline: 0; padding: 8px 6px; }
QListWidget#nav::item { padding: 9px 10px; margin: 1px 0; border-radius: 7px;
                        color: %(muted)s; }
QListWidget#nav::item:hover { background: %(g_hover)s; color: %(text)s; }
QListWidget#nav::item:selected { background: %(g_sel_grad)s; color: %(text)s; }
QLabel#pageTitle { font-size: 15px; font-weight: 600; }
QPushButton { background: %(g_btn)s; border: 1px solid %(g_line)s; border-radius: 6px;
              padding: 5px 14px; min-height: 16px; }
QPushButton:hover { background: %(g_btn_hover)s; border-color: %(accent)s; }
QPushButton:pressed { background: %(g_sel)s; }
QPushButton:disabled { color: %(faint)s; background: %(g_panel_soft)s;
                       border-color: %(g_line_soft)s; }
QPushButton#primary { background: %(g_primary)s; border: 1px solid rgba(255,255,255,56);
                      color: #ffffff; font-weight: 600; padding: 5px 16px; }
QPushButton#primary:hover { background: %(g_primary_hover)s; }
QPushButton#primary:pressed { background: %(accent_dark)s; }
QPushButton#primary:disabled { background: %(dis)s; border-color: %(border)s;
                               color: %(faint)s; }
QPushButton#cap { background: transparent; border: none; border-radius: 5px; }
QPushButton#cap:hover { background: %(g_hover)s; }
QPushButton#cap:pressed { background: %(g_sel)s; }
QPushButton#capClose { background: transparent; border: none; border-radius: 5px; }
QPushButton#capClose:hover { background: #d63a3a; }
QPushButton#capClose:pressed { background: #b32d2d; }
QPushButton#flat { background: transparent; border: 1px solid transparent;
                   color: %(muted)s; padding: 3px 8px; }
QPushButton#flat:hover { background: %(g_hover)s; color: %(text)s; border-radius: 6px; }
QTreeWidget { background: %(g_panel_grad)s; border: 1px solid %(g_line)s;
              border-radius: 10px; alternate-background-color: %(g_alt)s;
              outline: none; padding: 2px;
              show-decoration-selected: 1; }
QTreeWidget::item { height: 22px; border: 0; }
QTreeWidget::item:hover { background: %(g_hover)s; }
QTreeWidget::item:selected { background: %(g_sel_grad)s; color: %(text)s;
                             border-radius: 4px; }
QTreeWidget::branch { background: transparent; }
QHeaderView { background: transparent; }
QHeaderView::section { background: %(g_head)s; border: none;
                       border-right: 1px solid %(g_line_soft)s;
                       border-bottom: 1px solid %(g_line)s;
                       padding: 5px 6px; color: %(muted)s; font-weight: 600; }
QHeaderView::section:first { border-top-left-radius: 9px; }
QHeaderView::section:last { border-right: none; border-top-right-radius: 9px; }
QTextBrowser, QPlainTextEdit { background: %(t_area)s;
                               border: 1px solid %(g_line_soft)s; border-radius: 10px;
                               padding: 8px; color: %(text)s; }
QPlainTextEdit { font-family: Consolas, "Courier New", monospace; font-size: 11px;
                 color: %(muted)s; }
QLineEdit, QComboBox, QSpinBox { background: %(g_panel)s; border: 1px solid %(g_line)s;
                                 border-radius: 6px; padding: 3px 8px; min-height: 16px; }
QLineEdit:focus, QComboBox:focus, QSpinBox:focus { border-color: %(accent)s; }
QComboBox::drop-down { border: none; width: 18px; }
QComboBox QAbstractItemView { background: %(g_menu)s; border: 1px solid %(g_line)s;
                              border-radius: 8px; padding: 3px;
                              selection-background-color: %(accent)s;
                              selection-color: #ffffff; outline: none; }
QListWidget { background: %(g_panel)s; border: 1px solid %(g_line)s; border-radius: 8px; }
/* 复选框：Fusion 的 indicator 在部分 DPI 下比 sizeHint 算的宽，
   文字最后一两个字会被裁掉。留 6px 余量，别让布局刚好卡在边界上。 */
QCheckBox, QRadioButton { spacing: 6px; padding-right: 6px; }
QProgressBar { border: none; background: %(g_line_soft)s; height: 4px;
               border-radius: 2px; text-align: center; }
QProgressBar::chunk { background: %(g_primary)s; border-radius: 2px; }
QSplitter::handle { background: transparent; }
QSplitter::handle:horizontal { width: 8px; }
QSplitter::handle:hover { background: %(g_line_soft)s; }
QStatusBar { background: transparent; border-top: 1px solid %(g_line_soft)s;
             color: %(muted)s; }
QStatusBar::item { border: none; }
QTabWidget::pane { border: 1px solid %(g_line)s; background: %(g_panel_soft)s;
                   border-radius: 8px; top: -1px; }
QTabBar::tab { background: transparent; border: 1px solid %(g_line_soft)s;
               border-bottom: none; border-top-left-radius: 7px;
               border-top-right-radius: 7px; padding: 5px 14px; margin-right: 3px;
               color: %(muted)s; }
QTabBar::tab:selected { background: %(g_panel)s; color: %(text)s;
                        border-color: %(g_line)s; }
QToolTip { background: %(g_menu)s; color: %(text)s; border: 1px solid %(g_line)s;
           border-radius: 6px; padding: 4px 8px; }
QScrollBar:vertical { background: transparent; width: 10px; margin: 2px; }
QScrollBar::handle:vertical { background: %(g_scroll)s; min-height: 24px;
                              border-radius: 4px; }
QScrollBar::handle:vertical:hover { background: %(g_scroll_hover)s; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: transparent; }
QScrollBar:horizontal { background: transparent; height: 10px; margin: 2px; }
QScrollBar::handle:horizontal { background: %(g_scroll)s; min-width: 24px;
                                border-radius: 4px; }
QScrollBar::handle:horizontal:hover { background: %(g_scroll_hover)s; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal { background: transparent; }
""" % p


# --------------------------------------------------------------------------
# 通用：异常护栏
# --------------------------------------------------------------------------

def guard(fn):
    try:
        sig = inspect.signature(fn)
        params = list(sig.parameters.values())
        has_var = any(p.kind == inspect.Parameter.VAR_POSITIONAL for p in params)
        n_pos = len([p for p in params if p.kind in (
            inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)])
    except (TypeError, ValueError):
        has_var, n_pos = True, 0

    def wrapper(*a, **kw):
        try:
            if has_var:
                return fn(*a, **kw)
            return fn(*a[:n_pos], **kw)
        except Exception:
            err = traceback.format_exc()
            bc.log_line("GUI exception in %s:\n%s" % (getattr(fn, "__name__", "?"), err))
            try:
                QMessageBox.critical(None, "出错了", err[-1600:])
            except Exception:
                pass
    return wrapper


class GlassItemStyle(QProxyStyle):
    """透明窗口（WA_TranslucentBackground）下 Fusion 画的复选框会变成黑块。

    原因：QStyle 走的是不带 alpha 的绘制路径，indicator 的透明部分被当成黑色。
    这里只拦 CE_ItemViewItem 里的 checkbox，改成自己画圆角方框 + 勾，
    其它绘制全部交回 Fusion，保证表格观感一致。
    """

    def drawPrimitive(self, elem, opt, painter, widget=None):
        if elem == QStyle.PE_IndicatorItemViewItemCheck:
            # 自绘失败就退回 Fusion，宁可画成黑块也不能崩进程
            try:
                self._paint_check(opt, painter)
                return
            except Exception:
                pass
        super().drawPrimitive(elem, opt, painter, widget)

    @staticmethod
    def _paint_check(opt, painter):
        if opt is None or painter is None or not painter.isActive():
            return
        r = opt.rect
        side = int(min(r.width(), r.height())) - 2
        if side < 6:
            return
        box = QRect(int(r.x() + (r.width() - side) // 2),
                    int(r.y() + (r.height() - side) // 2), side, side)
        on = bool(opt.state & QStyle.State_On)
        painter.save()
        painter.setRenderHint(QPainter.Antialiasing, True)
        if on:
            painter.setPen(QPen(QColor(PAL["accent"]), 1))
            painter.setBrush(QBrush(QColor(PAL["accent"])))
            painter.drawRoundedRect(box, 3, 3)
            painter.setPen(QPen(QColor("#ffffff"), 2))
            # drawLine 只接受整数坐标，传 float 在部分 PyQt 版本会抛 TypeError
            l, t = box.left(), box.top()
            painter.drawLine(l + int(side * 0.26), t + int(side * 0.52),
                             l + int(side * 0.44), t + int(side * 0.70))
            painter.drawLine(l + int(side * 0.44), t + int(side * 0.70),
                             l + int(side * 0.76), t + int(side * 0.32))
        else:
            # 深色下千万别填白，否则整行最左就是一块白斑；只留一圈淡边框
            painter.setPen(QPen(QColor(255, 255, 255, 62) if is_dark()
                                else QColor(PAL["faint"]), 1))
            painter.setBrush(QBrush(Qt.NoBrush) if is_dark()
                             else QBrush(QColor(255, 255, 255, 215)))
            painter.drawRoundedRect(box, 3, 3)
        painter.restore()


class DialogChrome(QObject):
    """给所有对话框同步深色系统标题栏（只改颜色，不动窗口行为）。"""

    def eventFilter(self, obj, ev):
        try:
            # 嵌进主窗口当页面用的对话框（弹窗拦截页）不是顶层窗口：对它调 winId()
            # 会把它变成原生子窗口，在毛玻璃主窗口里会黑底 / 闪烁
            if ev.type() == QEvent.Show and isinstance(obj, QDialog) and obj.isWindow():
                _set_dark_title(int(obj.winId()), is_dark())
        except Exception:
            pass
        return False


def _excepthook(tp, val, tb):
    txt = "".join(traceback.format_exception(tp, val, tb))
    bc.log_line("UNCAUGHT:\n" + txt)


# --------------------------------------------------------------------------
# 后台线程
# --------------------------------------------------------------------------

class ScanWorker(QThread):
    sig_progress = pyqtSignal(str)
    sig_done = pyqtSignal(object, object)
    sig_fail = pyqtSignal(str)

    def run(self):
        try:
            raw = bc.collect(progress=lambda t: self.sig_progress.emit(t))
            res = bc.analyze(raw)
            # 顺手把签名校验做掉（AutoRuns 同款列），结果进缓存，界面上直接读。
            # WinVerifyTrust 是阻塞的系统调用（ctypes 会释放 GIL），多线程并行；
            # analyze 里为「冒充微软」检查已经预热过一批，这里只补剩下的
            apps = [f.get("app") or {} for f in res.get("findings", [])]
            n = sum(1 for a in apps if a.get("path") and a.get("exists"))
            if n:
                self.sig_progress.emit("校验程序签名（%d 个）…" % n)
                bc.warm_signatures(apps)
            self.sig_done.emit(raw, res)
        except Exception:
            self.sig_fail.emit(traceback.format_exc())


class FixWorker(QThread):
    sig_progress = pyqtSignal(str)
    sig_done = pyqtSignal(object, str)
    sig_fail = pyqtSignal(str)

    def __init__(self, findings, parent=None):
        super().__init__(parent)
        self.findings = findings

    def run(self):
        try:
            bdir = bc.make_backup(self.findings)
            res = bc.apply_fixes(self.findings, bdir,
                                 progress=lambda t: self.sig_progress.emit(t))
            self.sig_done.emit(res, bdir)
        except Exception:
            self.sig_fail.emit(traceback.format_exc())


class RestoreWorker(QThread):
    sig_progress = pyqtSignal(str)
    sig_done = pyqtSignal(object)
    sig_fail = pyqtSignal(str)

    def __init__(self, bdir, parent=None):
        super().__init__(parent)
        self.bdir = bdir

    def run(self):
        try:
            res = bc.restore_backup(self.bdir, progress=lambda t: self.sig_progress.emit(t))
            self.sig_done.emit(res)
        except Exception:
            self.sig_fail.emit(traceback.format_exc())


class AiWorker(QThread):
    """本地 AI 判断（batch = 整份清单，one = 单项解读）。"""
    sig_progress = pyqtSignal(str)
    sig_done = pyqtSignal(str, object)
    sig_fail = pyqtSignal(str)

    def __init__(self, mode, findings, parent=None):
        super().__init__(parent)
        self.mode = mode
        self.findings = list(findings or [])

    def run(self):
        try:
            if self.mode == "batch":
                adv, err = bc.ai_advise(
                    self.findings, progress=lambda t: self.sig_progress.emit(t))
                self.sig_done.emit("batch", (adv, err))
            else:
                txt, err = bc.ai_explain(self.findings[0])
                self.sig_done.emit("one", (txt, err))
        except Exception:
            self.sig_fail.emit(traceback.format_exc())


class DbUpdateWorker(QThread):
    """在线更新流氓软件特征库（走后台线程，别让界面卡住等网络）。"""
    sig_progress = pyqtSignal(str)
    sig_done = pyqtSignal(object)
    sig_fail = pyqtSignal(str)

    def run(self):
        try:
            rep = bc.update_adware_db(
                progress=lambda t: self.sig_progress.emit(t))
            self.sig_done.emit(rep)
        except Exception:
            self.sig_fail.emit(traceback.format_exc())


# --------------------------------------------------------------------------
# 开机耗时趋势（对照 Autorun Organizer 的启动耗时图表）
# --------------------------------------------------------------------------

class BootTrendDialog(QDialog):
    """开机耗时条形图（原生控件画，别用富文本凑）。"""

    def __init__(self, parent, raw):
        super().__init__(parent)
        self.setWindowTitle("开机耗时趋势")
        self.resize(600, 430)
        boots = ((raw or {}).get("events") or {}).get("boots") or []
        rows = list(reversed(boots[:12]))
        v = QVBoxLayout(self)
        v.setContentsMargins(14, 12, 14, 12)
        v.setSpacing(8)
        if not rows:
            v.addWidget(QLabel("还没有开机性能记录。先执行一次体检。"))
        else:
            mx = max(b["boot"] for b in rows) or 1
            avg = sum(b["boot"] for b in rows) // len(rows)
            v.addWidget(QLabel("最近 %d 次开机，平均 %d 秒（目标 < 60 秒）"
                               % (len(rows), avg)))
            grid = QGridLayout()
            grid.setContentsMargins(0, 4, 0, 0)
            grid.setHorizontalSpacing(10)
            grid.setVerticalSpacing(4)
            for i, b in enumerate(rows):
                h = b["boot"]
                col = PAL["err"] if h >= 90 else (PAL["warn"] if h >= 60 else PAL["ok"])
                lb = QLabel(b["time"])
                lb.setObjectName("hint")
                grid.addWidget(lb, i, 0)
                bar = QProgressBar()
                bar.setRange(0, mx)
                bar.setValue(h)
                bar.setTextVisible(False)
                bar.setFixedHeight(10)
                bar.setStyleSheet(
                    "QProgressBar{border:none;background:%s;border-radius:3px;}"
                    "QProgressBar::chunk{background:%s;border-radius:3px;}"
                    % (PAL["g_line_soft"], col))
                grid.addWidget(bar, i, 1)
                val = QLabel("%d 秒" % h)
                val.setStyleSheet("color:%s;font-size:11px;" % col)
                val.setFixedWidth(52)
                grid.addWidget(val, i, 2)
            grid.setColumnStretch(1, 1)
            holder = QWidget()
            holder.setLayout(grid)
            v.addWidget(holder, 1)
        bb = QDialogButtonBox(QDialogButtonBox.Close)
        bb.button(QDialogButtonBox.Close).setText("关闭")
        bb.rejected.connect(self.reject)
        bb.clicked.connect(self.accept)
        v.addWidget(bb)


# --------------------------------------------------------------------------
# 设置对话框（AI 接口在这里对外开放，不再藏在右键里）
# --------------------------------------------------------------------------

class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("设置")
        self.resize(560, 400)
        base, model = bc.get_ai_cfg()
        self._theme = bc.get_setting("theme", "light")

        v = QVBoxLayout(self)
        v.setContentsMargins(14, 12, 14, 12)
        v.setSpacing(10)

        tabs = QTabWidget()
        v.addWidget(tabs, 1)

        # ---- AI ----
        ai = QWidget()
        f = QVBoxLayout(ai)
        f.setContentsMargins(14, 14, 14, 10)
        f.setSpacing(8)
        self.chk_ai = QCheckBox("启用 AI 辅助判断（不勾选则完全不发请求）")
        self.chk_ai.setChecked(bool(bc.get_setting("ai_enabled", True)))
        f.addWidget(self.chk_ai)

        grid = QHBoxLayout()
        grid.setSpacing(6)
        lab = QLabel("接口地址")
        lab.setFixedWidth(74)
        grid.addWidget(lab)
        self.ed_base = QLineEdit(base)
        self.ed_base.setPlaceholderText("http://127.0.0.1:3425")
        grid.addWidget(self.ed_base, 1)
        f.addLayout(grid)

        grid2 = QHBoxLayout()
        grid2.setSpacing(6)
        lab2 = QLabel("模型")
        lab2.setFixedWidth(74)
        grid2.addWidget(lab2)
        self.ed_model = QLineEdit(model)
        self.ed_model.setPlaceholderText("workbuddy-ai/hy4flash-free")
        grid2.addWidget(self.ed_model, 1)
        f.addLayout(grid2)

        grid3 = QHBoxLayout()
        grid3.setSpacing(6)
        lab3 = QLabel("超时")
        lab3.setFixedWidth(74)
        grid3.addWidget(lab3)
        self.sp_timeout = QSpinBox()
        self.sp_timeout.setRange(5, 300)
        self.sp_timeout.setSuffix(" 秒")
        self.sp_timeout.setValue(int(bc.get_setting("ai_timeout", 60) or 60))
        grid3.addWidget(self.sp_timeout)
        grid3.addStretch(1)
        self.btn_test = QPushButton("测试连接")
        self.btn_test.clicked.connect(self.on_test)
        grid3.addWidget(self.btn_test)
        f.addLayout(grid3)

        self.lbl_test = QLabel("")
        self.lbl_test.setObjectName("meta")
        self.lbl_test.setWordWrap(True)
        f.addWidget(self.lbl_test)

        note = QLabel("需要 OpenAI 兼容接口（POST /v1/chat/completions）。"
                      "配好后点『AI 帮我判断』，它会逐项说明这是什么程序、开机要不要留。"
                      "本地网关、公司内网模型、LM Studio、Ollama 代理都可以填这里。")
        note.setObjectName("hint")
        note.setWordWrap(True)
        f.addWidget(note)
        f.addStretch(1)
        tabs.addTab(ai, "AI 接口")

        # ---- 通用 ----
        gen = QWidget()
        g = QVBoxLayout(gen)
        g.setContentsMargins(14, 14, 14, 10)
        g.setSpacing(8)
        self.chk_autoscan = QCheckBox("启动时自动体检")
        self.chk_autoscan.setChecked(bool(bc.get_setting("autoscan", True)))
        g.addWidget(self.chk_autoscan)
        self.chk_lastscan = QCheckBox("启动时先显示上次的体检结果（后台再刷新）")
        self.chk_lastscan.setChecked(bool(bc.get_setting("show_last_scan", True)))
        g.addWidget(self.chk_lastscan)
        self.chk_refresh = QCheckBox("处理完自动重新体检")
        self.chk_refresh.setChecked(bool(bc.get_setting("autorefresh", True)))
        g.addWidget(self.chk_refresh)
        g.addStretch(1)
        tabs.addTab(gen, "通用")

        # ---- 外观 ----
        ui = QWidget()
        u = QVBoxLayout(ui)
        u.setContentsMargins(14, 14, 14, 10)
        u.setSpacing(8)
        lb_theme = QLabel("界面主题（立即生效）")
        u.addWidget(lb_theme)
        th = QHBoxLayout()
        self.rb_light = QRadioButton("浅色")
        self.rb_dark = QRadioButton("深色")
        self.grp_theme = QButtonGroup(self)
        self.grp_theme.addButton(self.rb_light)
        self.grp_theme.addButton(self.rb_dark)
        (self.rb_dark if self._theme == "dark" else self.rb_light).setChecked(True)
        th.addWidget(self.rb_light)
        th.addWidget(self.rb_dark)
        th.addStretch(1)
        u.addLayout(th)
        u.addStretch(1)
        tabs.addTab(ui, "外观")

        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.button(QDialogButtonBox.Ok).setText("确定")
        bb.button(QDialogButtonBox.Ok).setObjectName("primary")
        bb.button(QDialogButtonBox.Cancel).setText("取消")
        bb.accepted.connect(self.on_ok)
        bb.rejected.connect(self.reject)
        v.addWidget(bb)

    def values(self):
        return {
            "ai_enabled": self.chk_ai.isChecked(),
            "ai_base": self.ed_base.text().strip() or bc.AI_BASE_DEFAULT,
            "ai_model": self.ed_model.text().strip() or bc.AI_MODEL_DEFAULT,
            "ai_timeout": self.sp_timeout.value(),
            "autoscan": self.chk_autoscan.isChecked(),
            "show_last_scan": self.chk_lastscan.isChecked(),
            "autorefresh": self.chk_refresh.isChecked(),
            "theme": "dark" if self.rb_dark.isChecked() else "light",
        }

    @guard
    def on_test(self):
        old_base, old_model = bc.get_ai_cfg()
        bc.set_ai_cfg(self.ed_base.text().strip(), self.ed_model.text().strip())
        self.btn_test.setEnabled(False)
        self.lbl_test.setText("正在连接 …")
        QApplication.processEvents()
        try:
            ok = bc.ai_available(timeout=4)
        except Exception as e:
            ok = False
            self.lbl_test.setText("连接失败：%r" % (e,))
        if ok:
            self.lbl_test.setText("连接正常：%s / %s" % (self.ed_base.text().strip(),
                                                     self.ed_model.text().strip()))
        elif not self.lbl_test.text().startswith("连接失败"):
            self.lbl_test.setText("连不上。请确认网关在运行、地址和模型名没写错。")
        bc.set_ai_cfg(old_base, old_model)
        self.btn_test.setEnabled(True)

    @guard
    def on_ok(self):
        self.accept()


# --------------------------------------------------------------------------
# 主窗口
# --------------------------------------------------------------------------

MODE_ALL = "all"
MODE_TODO = "todo"


class PopupDialog(QDialog):
    """弹窗拦截：先指认「是谁在弹」，再决定关 / 拦 / 放行，最后可开后台守护。"""

    COLS = ("判定", "窗口标题", "进程", "发布者", "路径")
    JUDGE_TEXT = {"adware": "广告弹窗", "suspicious": "疑似", "unsign": "无厂商",
                  "normal": "正常"}

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("弹窗拦截")
        self.resize(1020, 680)
        self.items = []
        self._timer = QTimer(self)
        self._timer.setInterval(3000)
        self._timer.timeout.connect(lambda: self.refresh(keep_sel=True))

        v = QVBoxLayout(self)
        v.setContentsMargins(14, 12, 14, 10)
        v.setSpacing(8)

        self.lbl_head = QLabel("")
        self.lbl_head.setObjectName("hint")
        self.lbl_head.setWordWrap(True)
        v.addWidget(self.lbl_head)

        bar = QHBoxLayout()
        bar.setSpacing(6)
        self.btn_refresh = QPushButton("刷新")
        self.btn_refresh.setIcon(self.style().standardIcon(QStyle.SP_BrowserReload))
        self.btn_refresh.setShortcut("F5")
        self.btn_refresh.clicked.connect(lambda: self.refresh())
        bar.addWidget(self.btn_refresh)

        self.btn_pick = QPushButton("选取窗口…")
        self.btn_pick.setToolTip("3 秒内把鼠标移到弹窗上（不用点），自动认出它的进程 / 类名 / 标题")
        self.btn_pick.clicked.connect(self.on_pick)
        bar.addWidget(self.btn_pick)

        self.btn_close_win = QPushButton("关闭这个窗口")
        self.btn_close_win.clicked.connect(self.on_close_win)
        bar.addWidget(self.btn_close_win)

        self.btn_block = QPushButton("加入拦截…")
        self.btn_block.setToolTip("按进程 / 标题 / 窗口类 / 路径加规则，命中后自动关")
        self.btn_block.clicked.connect(self.on_add_block)
        bar.addWidget(self.btn_block)

        self.btn_allow = QPushButton("加入白名单")
        self.btn_allow.setToolTip("这个窗口以后不再拦（按同样的选择方式）")
        self.btn_allow.clicked.connect(self.on_add_allow)
        bar.addWidget(self.btn_allow)

        self.btn_open = QPushButton("打开位置")
        self.btn_open.clicked.connect(self.on_open_path)
        bar.addWidget(self.btn_open)

        bar.addStretch(1)
        v.addLayout(bar)

        # 选项放第二行：和按钮挤一行时，1040 宽下复选框文字会被裁掉（Qt 只压缩不换行）
        bar2 = QHBoxLayout()
        bar2.setSpacing(14)
        self.chk_only = QCheckBox("只看可疑")
        self.chk_only.setChecked(False)
        self.chk_only.setToolTip("不看就取消勾选，可列出桌面上全部窗口")
        self.chk_only.stateChanged.connect(lambda _s: self._fill())
        bar2.addWidget(self.chk_only)

        self.chk_hidden = QCheckBox("含隐藏窗口")
        self.chk_hidden.setToolTip("有些弹窗先隐藏驻留、到点才显示，勾上能提前看到")
        self.chk_hidden.stateChanged.connect(lambda _s: self.refresh())
        bar2.addWidget(self.chk_hidden)

        self.chk_auto = QCheckBox("自动刷新(3s)")
        self.chk_auto.setToolTip("每 3 秒重新枚举一次桌面窗口")
        self.chk_auto.stateChanged.connect(self._toggle_timer)
        bar2.addWidget(self.chk_auto)
        bar2.addStretch(1)
        v.addLayout(bar2)

        self.tree = QTreeWidget()
        self.tree.setColumnCount(len(self.COLS))
        self.tree.setHeaderLabels(list(self.COLS))
        self.tree.setRootIsDecorated(False)
        self.tree.setAlternatingRowColors(True)
        self.tree.setSelectionMode(QAbstractItemView.SingleSelection)
        self.tree.setUniformRowHeights(True)
        self.tree.setSortingEnabled(False)
        hh = self.tree.header()
        hh.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(1, QHeaderView.Interactive)
        hh.setSectionResizeMode(2, QHeaderView.Interactive)
        hh.setSectionResizeMode(3, QHeaderView.Interactive)
        hh.setSectionResizeMode(4, QHeaderView.Stretch)
        self.tree.setColumnWidth(1, 320)
        self.tree.setColumnWidth(2, 170)
        self.tree.setColumnWidth(3, 190)
        self.tree.itemDoubleClicked.connect(lambda *_: self.on_close_win())

        self.watch = QTreeWidget()
        self.watch.setColumnCount(5)
        self.watch.setHeaderLabels(["时间", "判定", "窗口标题", "进程", "路径"])
        self.watch.setRootIsDecorated(False)
        self.watch.setAlternatingRowColors(True)
        self.watch.setUniformRowHeights(True)
        wh = self.watch.header()
        wh.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        wh.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        wh.setSectionResizeMode(2, QHeaderView.Interactive)
        wh.setSectionResizeMode(3, QHeaderView.Interactive)
        wh.setSectionResizeMode(4, QHeaderView.Stretch)
        self.watch.setColumnWidth(2, 300)
        self.watch.setColumnWidth(3, 160)
        self.watch.itemDoubleClicked.connect(lambda *_: self.on_block_watch())

        self.as_tree = QTreeWidget()
        self.as_tree.setColumnCount(6)
        self.as_tree.setHeaderLabels(["时间", "变化", "名称", "来源", "命令", "判定"])
        self.as_tree.setRootIsDecorated(False)
        self.as_tree.setAlternatingRowColors(True)
        self.as_tree.setUniformRowHeights(True)
        ah = self.as_tree.header()
        for c in (0, 1):
            ah.setSectionResizeMode(c, QHeaderView.ResizeToContents)
        for c in (2, 3, 5):
            ah.setSectionResizeMode(c, QHeaderView.Interactive)
        ah.setSectionResizeMode(4, QHeaderView.Stretch)
        self.as_tree.setColumnWidth(2, 200)
        self.as_tree.setColumnWidth(3, 150)
        self.as_tree.setColumnWidth(5, 140)
        self.as_tree.itemDoubleClicked.connect(lambda *_: self.on_handle_autostart())
        as_box = QWidget()
        av = QVBoxLayout(as_box)
        av.setContentsMargins(0, 6, 0, 0)
        av.setSpacing(6)
        ab = QHBoxLayout()
        self.chk_watch_as = QCheckBox("守护运行时监控开机自启（新增 / 被重新启用 / 命令被改，立即在托盘提醒）")
        self.chk_watch_as.setChecked(bool(bc.load_popup_rules().get("watch_autostart", True)))
        self.chk_watch_as.toggled.connect(self.on_toggle_watch_autostart)
        ab.addWidget(self.chk_watch_as)
        ab.addStretch(1)
        self.btn_as_handle = QPushButton("到体检里处理")
        self.btn_as_handle.setToolTip("跳到「开机体检」页并定位到这一项，在那里禁止 / 延迟 / 删除")
        self.btn_as_handle.clicked.connect(self.on_handle_autostart)
        ab.addWidget(self.btn_as_handle)
        av.addLayout(ab)
        av.addWidget(self.as_tree, 1)

        self.tabs = QTabWidget()
        self.tabs.addTab(self.tree, "当前窗口")
        self.tabs.addTab(self.watch, "窗口记录")
        self.tabs.addTab(as_box, "自启变动")
        self.tabs.currentChanged.connect(self._on_tab)
        v.addWidget(self.tabs, 1)

        self.lbl_guard = QLabel("")
        self.lbl_guard.setObjectName("meta")
        self.lbl_guard.setWordWrap(True)
        v.addWidget(self.lbl_guard)

        foot = QHBoxLayout()
        foot.setSpacing(6)
        self.chk_boot = QCheckBox("开机自动拦截")
        self.chk_boot.setToolTip(
            "登录 Windows 后自动在后台静默拦截（托盘小图标，不开窗口）。\n"
            "守护是独立进程，关掉本程序也继续工作。")
        self.chk_boot.toggled.connect(self.on_toggle_autostart)
        foot.addWidget(self.chk_boot)
        foot.addStretch(1)

        self.btn_import = QPushButton("导入规则…")
        self.btn_import.setToolTip("支持本项目格式，以及社区常见的 conditions/action 格式")
        self.btn_import.clicked.connect(self.on_import_rules)
        foot.addWidget(self.btn_import)

        self.btn_edit_rules = QPushButton("编辑规则")
        self.btn_edit_rules.clicked.connect(self.on_edit_rules)
        foot.addWidget(self.btn_edit_rules)

        self.btn_guard = QPushButton("")
        self.btn_guard.clicked.connect(self.on_toggle_guard)
        foot.addWidget(self.btn_guard)
        v.addLayout(foot)

        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumHeight(96)
        self.log.setPlaceholderText("拦截记录（最近 20 条）")
        v.addWidget(self.log)

        self.refresh()
        self._sync_guard()

    # ---------------- 数据 ----------------
    def refresh(self, keep_sel=False):
        sel = self._cur_item()
        sel_key = (sel.get("hwnd"), sel.get("proc")) if sel else None
        try:
            self.items = bc.enum_popups(include_hidden=self.chk_hidden.isChecked())
        except Exception as e:
            self.items = []
            self.lbl_head.setText("枚举窗口失败：%s" % e)
        self._fill(sel_key if keep_sel else None)
        self._fill_watch()
        st = bc.popup_stats(self.items)
        self.lbl_head.setText(
            "当前 %d 个窗口：广告弹窗 %d 个、疑似 %d 个、无厂商信息 %d 个。"
            "「关闭」只发 WM_CLOSE，不会杀进程；「加入拦截」后可交给后台守护自动关。"
            % (st["total"], st["adware"], st["suspicious"], st["unsign"]))

    def _fill(self, sel_key=None):
        only = self.chk_only.isChecked()
        self.tree.clear()
        n = 0
        for it in self.items:
            if only and it["judge"] not in ("adware", "suspicious"):
                continue
            ti = QTreeWidgetItem([
                self.JUDGE_TEXT.get(it["judge"], it["judge"]),
                it["title"] or "(无标题)",
                it["proc"] or it["pid"],
                it["company"] or "—",
                it["path"] or "—",
            ])
            ti.setData(0, Qt.UserRole, it)
            ti.setToolTip(0, it.get("why") or "")
            ti.setToolTip(1, it.get("why") or "")
            if it["judge"] == "adware":
                ti.setForeground(0, QBrush(QColor(sev_color("high"))))
            elif it["judge"] == "suspicious":
                ti.setForeground(0, QBrush(QColor(sev_color("mid"))))
            else:
                ti.setForeground(0, QBrush(QColor(sev_color("low"))))
            if not it["visible"]:
                ti.setForeground(1, QBrush(PAL["faint"]))
                ti.setText(1, (it["title"] or "(无标题)") + "（隐藏）")
            self.tree.addTopLevelItem(ti)
            if sel_key and (it["hwnd"], it["proc"]) == sel_key:
                self.tree.setCurrentItem(ti)
            n += 1
        self.btn_close_win.setEnabled(n > 0)
        self.btn_block.setEnabled(n > 0)
        self.btn_allow.setEnabled(n > 0)
        self.btn_open.setEnabled(n > 0)
        if n and self.tree.currentItem() is None:
            self.tree.setCurrentItem(self.tree.topLevelItem(0))

    def _cur_item(self):
        ti = self.tree.currentItem() if hasattr(self, "tree") else None
        return ti.data(0, Qt.UserRole) if ti else None

    def _toggle_timer(self, state):
        if state and self.isVisible():
            self._timer.start()
        else:
            self._timer.stop()

    # 作为主窗口里的一页时，切到别的页就停掉自动刷新，切回来再接上（以前关了对话框才停）
    def showEvent(self, ev):
        super().showEvent(ev)
        if self.chk_auto.isChecked():
            self._timer.start()
        self._sync_guard()

    def hideEvent(self, ev):
        self._timer.stop()
        super().hideEvent(ev)

    # ---------------- 操作 ----------------
    def on_close_win(self):
        it = self._cur_item()
        if not it:
            return
        r = QMessageBox.question(
            self, "关闭窗口",
            "向这个窗口发送关闭请求？\n\n%s\n%s\n\n"
            "只是 WM_CLOSE（等于点右上角 ×），不杀进程、不动文件。"
            % (it["title"] or "(无标题)", it["path"] or it["proc"]))
        if r != QMessageBox.Yes:
            return
        try:
            ctypes.windll.user32.PostMessageW(int(it["hwnd"]), 0x0010, 0, 0)
            bc.log_line("popup close by user: %s (%s)" % (it["title"], it["proc"]))
        except Exception as e:
            QMessageBox.warning(self, "关闭失败", str(e))
        QTimer.singleShot(400, lambda: self.refresh(keep_sel=True))

    def on_add_block(self):
        self._add_rule("block")

    def on_add_allow(self):
        self._add_rule("allow")

    def _fill_watch(self):
        """窗口记录：守护见过的窗口（火绒同款），可以回溯"刚才那个弹窗是谁"）。"""
        try:
            rows = bc.popup_watch_log(200)
        except Exception:
            rows = []
        self.watch.clear()
        for r in rows:
            ti = QTreeWidgetItem([
                r.get("t", ""),
                self.JUDGE_TEXT.get(r.get("judge"), r.get("judge") or ""),
                r.get("title") or "(无标题)",
                r.get("proc") or "",
                r.get("path") or "",
            ])
            ti.setData(0, Qt.UserRole, r)
            j = r.get("judge")
            if j == "adware":
                ti.setForeground(1, QBrush(QColor(sev_color("high"))))
            elif j == "suspicious":
                ti.setForeground(1, QBrush(QColor(sev_color("mid"))))
            self.watch.addTopLevelItem(ti)
        if not rows:
            self.tabs.setTabText(1, "窗口记录")
        else:
            self.tabs.setTabText(1, "窗口记录(%d)" % len(rows))

    def _on_tab(self, i):
        if i == 1:
            self._fill_watch()
        elif i == 2:
            self._fill_autostart()

    def _fill_autostart(self):
        """守护记下的开机自启变化（新增 / 被重新启用 / 命令被改），最新在前。"""
        rows = bc.autostart_watch_log(200)
        self.as_tree.clear()
        for r in rows:
            ti = QTreeWidgetItem([
                r.get("t", ""), bc.AUTOSTART_CHANGE_CN.get(r.get("change"), r.get("change") or ""),
                r.get("name") or "", r.get("source") or "", r.get("cmd") or "",
                ("流氓软件：%s" % r["adware"]) if r.get("adware") else "",
            ])
            ti.setData(0, Qt.UserRole, r)
            ti.setToolTip(4, (r.get("cmd") or "") + (
                "\n原命令：%s" % r["old_cmd"] if r.get("old_cmd") else ""))
            if r.get("adware"):
                ti.setForeground(5, QBrush(QColor(sev_color("high"))))
            if r.get("change") in ("reenabled", "changed"):
                ti.setForeground(1, QBrush(QColor(sev_color("mid"))))
            self.as_tree.addTopLevelItem(ti)
        self.tabs.setTabText(2, "自启变动(%d)" % len(rows) if rows else "自启变动")
        self.btn_as_handle.setEnabled(bool(rows))

    @guard
    def on_toggle_watch_autostart(self, on):
        r = bc.load_popup_rules()
        r["watch_autostart"] = bool(on)
        bc.save_popup_rules(r)
        if bc.guard_running():
            QMessageBox.information(self, "开机自启监控",
                                    "已%s。重启一次后台守护后生效。" % ("开启" if on else "关闭"))

    @guard
    def on_handle_autostart(self):
        ti = self.as_tree.currentItem()
        if not ti:
            return
        r = ti.data(0, Qt.UserRole) or {}
        w = self.window()
        if hasattr(w, "show_page") and hasattr(w, "ed_search"):
            w.show_page("scan")
            w.ed_search.setText(r.get("name") or "")
            if not (w.scan_worker and w.scan_worker.isRunning()):
                w.start_scan()             # 新加的自启，旧的体检结果里还没有

    def on_block_watch(self):
        ti = self.watch.currentItem()
        if not ti:
            return
        r = ti.data(0, Qt.UserRole) or {}
        if not r.get("proc"):
            QMessageBox.information(self, "没有进程信息", "这条记录只存了标题，没法定位进程。")
            return
        self._add_rule("block", dict(r))

    def on_pick(self):
        """选取窗口：把鼠标移到弹窗上，3 秒后自动识别（不用点，避开假关闭按钮）。"""
        QMessageBox.information(
            self, "选取弹窗",
            "点「确定」后，把鼠标移到要拦的那个弹窗上（不要点击），3 秒后自动识别。\n\n"
            "识别到的是窗口本身，不是鼠标下面的按钮，所以点到“假关闭”也不会误事。")
        self.hide()
        self._hud = QLabel("3 秒后识别鼠标下的窗口…", None,
                           Qt.Window | Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
        self._hud.setStyleSheet(
            "background: rgba(24,28,40,235); color: #fff; padding: 10px 18px;"
            "border-radius: 8px; font-size: 13px;")
        scr = QApplication.primaryScreen().availableGeometry()
        self._hud.adjustSize()
        self._hud.move(scr.center().x() - self._hud.width() // 2,
                       scr.bottom() - self._hud.height() - 80)
        self._hud.show()
        self._cd = 3
        self._cd_timer = QTimer(self)
        self._cd_timer.timeout.connect(self._tick_pick)
        self._cd_timer.start(1000)

    def _tick_pick(self):
        self._cd -= 1
        if self._cd > 0:
            self._hud.setText("%d 秒后识别鼠标下的窗口…" % self._cd)
            return
        self._cd_timer.stop()
        try:
            self._hud.close()
            self._hud.deleteLater()
        except Exception:
            pass
        self.show()
        self.raise_()
        it = bc.popup_pick_window()
        if not it:
            QMessageBox.warning(self, "没认出来", "鼠标下面没有可识别的窗口，换个位置再试。")
            return
        msg = ("标题：%s\n进程：%s\n窗口类：%s\n发布者：%s\n路径：%s\n\n判定：%s\n\n加入拦截名单吗？"
               % (it["title"] or "(无标题)", it["proc"], it["cls"] or "—",
                  it["company"] or "—", it["path"] or "—",
                  it.get("why") or self.JUDGE_TEXT.get(it["judge"], it["judge"])))
        if QMessageBox.question(self, "识别结果", msg) == QMessageBox.Yes:
            self._add_rule("block", it)

    def _add_rule(self, target, it=None):
        it = it or self._cur_item()
        if not it:
            return
        m = QMenu(self)
        opts = [
            ("按进程拦截（%s）" % (it["proc"] or "?"), "proc", it["proc"]),
            ("按窗口标题拦截（%s）" % (it["title"] or "?")[:24], "title", it["title"]),
            ("按窗口类拦截（%s）" % (it["cls"] or "?"), "class", it["cls"]),
            ("按安装路径拦截（%s…）" % (it["path"] or "?")[:40], "path", it["path"]),
        ]
        chosen = {}
        for label, kind, val in opts:
            val = (val or "").strip()
            if not val:
                continue
            act = m.addAction(label)
            act.triggered.connect(lambda _c=False, k=kind, v=val: chosen.update(k=k, v=v))
        if not m.actions():
            QMessageBox.information(self, "没法加规则", "这个窗口没有可用的进程 / 标题 / 类信息。")
            return
        m.exec_(self.btn_block.mapToGlobal(self.btn_block.rect().bottomLeft()))
        if not chosen:
            return
        rules = bc.load_popup_rules()
        key = "block" if target == "block" else "allow"
        rules[key].append({"kind": chosen["k"], "pattern": chosen["v"],
                           "note": "%s / %s" % (it["proc"], (it["title"] or "")[:30])})
        rules["enabled"] = True
        if not bc.save_popup_rules(rules):
            QMessageBox.warning(self, "保存失败", "规则文件写不进去：%s" % bc.POPUP_RULES_PATH)
            return
        self.refresh(keep_sel=True)
        self._sync_guard()
        QMessageBox.information(
            self, "已加入%s" % ("拦截名单" if key == "block" else "白名单"),
            "规则已保存，下次扫描立即生效。\n\n后台守护要开着才会自动关闭——"
            "点右下角「%s」。" % ("停止后台拦截" if bc.guard_running() else "开始后台拦截"))

    def on_open_path(self):
        it = self._cur_item()
        if not it or not it.get("path"):
            return
        try:
            subprocess.Popen(["explorer", "/select,", it["path"]])
        except Exception:
            pass

    # ---------------- 守护 ----------------
    def _sync_guard(self):
        on = bc.guard_running()
        self.btn_guard.setText("停止后台拦截" if on else "开始后台拦截")
        self.btn_guard.setObjectName("danger" if on else "primary")
        st = self.btn_guard.style()
        st.unpolish(self.btn_guard)
        st.polish(self.btn_guard)
        pid = bc.guard_pid()
        rules = bc.load_popup_rules()
        boot_state = bc.guard_autostart()[0]
        self.chk_boot.blockSignals(True)
        self.chk_boot.setChecked(boot_state != "off")
        self.chk_boot.blockSignals(False)
        self.lbl_guard.setText(
            "守护：%s　开机自启：%s　规则：拦截 %d / 放行 %d　自动拦特征库：%s"
            % ("运行中 (PID %d)" % pid if on else "未启动",
               "开" if boot_state == "on" else ("路径已失效" if boot_state == "stale" else "关"),
               len(rules.get("block") or []), len(rules.get("allow") or []),
               "开" if rules.get("auto_adware") else "关"))
        tail = bc.popup_log_tail(20)
        self.log.setPlainText("\n".join(tail) if tail else "（还没有拦截记录）")

    @guard
    def on_toggle_autostart(self, on):
        ok, msg = bc.set_guard_autostart(bool(on))
        if not ok:
            QMessageBox.warning(self, "开机自启", msg)
        elif on and not bc.guard_running():
            # 想开机拦，通常也想现在就拦：顺手把守护拉起来
            ok2, msg2 = bc.start_popup_guard()
            if not ok2:
                QMessageBox.warning(self, "后台拦截", msg2)
        self._sync_guard()

    @guard
    def on_toggle_guard(self):
        if bc.guard_running():
            ok, msg = bc.stop_popup_guard()
        else:
            ok, msg = bc.start_popup_guard()
        self._sync_guard()
        if not ok:
            QMessageBox.warning(self, "后台拦截", msg)
        else:
            QMessageBox.information(self, "后台拦截", msg)

    # ---------------- 规则文件 ----------------
    @guard
    def on_import_rules(self):
        p, _ = QFileDialog.getOpenFileName(self, "选择规则文件", "",
                                           "规则文件 (*.json);;所有文件 (*.*)")
        if not p:
            return
        ok, n, msg = bc.import_popup_rules(p)
        if not ok:
            QMessageBox.warning(self, "导入失败", msg)
            return
        self.refresh(keep_sel=True)
        self._sync_guard()
        QMessageBox.information(self, "导入完成", msg)

    def on_edit_rules(self):
        try:
            if not os.path.exists(bc.POPUP_RULES_PATH):
                bc.save_popup_rules(bc.load_popup_rules())
            os.startfile(bc.POPUP_RULES_PATH)
        except Exception as e:
            QMessageBox.warning(self, "打不开规则文件", str(e))



class NotifyPage(QWidget):
    """通知管理：右下角的系统通知不是独立窗口，弹窗守护拦不到，这里按应用直接关。"""

    COLS = ("通知", "应用", "发布者", "最近一次通知", "判定", "应用 ID")

    def __init__(self, parent=None, root_sub=None):
        super().__init__(parent)
        self.root_sub = root_sub
        self.apps = []
        v = QVBoxLayout(self)
        v.setContentsMargins(14, 12, 14, 10)
        v.setSpacing(8)
        t = QLabel("通知管理")
        t.setObjectName("pageTitle")
        v.addWidget(t)
        hint = QLabel("右下角弹出的系统通知（含不少软件的「推荐」「热点」）不是独立窗口，弹窗拦截管不到。"
                      "在这里按应用关掉，和「设置 → 系统 → 通知」里的开关是同一个。"
                      "个别应用要注销重新登录后才完全生效。")
        hint.setObjectName("hint")
        hint.setWordWrap(True)
        v.addWidget(hint)

        bar = QHBoxLayout()
        bar.setSpacing(6)
        self.btn_refresh = QPushButton("刷新")
        self.btn_refresh.clicked.connect(self.refresh)
        bar.addWidget(self.btn_refresh)
        self.btn_off = QPushButton("关闭所选应用的通知")
        self.btn_off.setObjectName("primary")
        self.btn_off.clicked.connect(lambda: self.set_selected(False))
        bar.addWidget(self.btn_off)
        self.btn_on = QPushButton("恢复通知")
        self.btn_on.clicked.connect(lambda: self.set_selected(True))
        bar.addWidget(self.btn_on)
        self.btn_adware_off = QPushButton("")
        self.btn_adware_off.setToolTip("把命中流氓软件特征库、且还在发通知的应用一次性全部关掉")
        self.btn_adware_off.clicked.connect(self.off_adware)
        bar.addWidget(self.btn_adware_off)
        self.chk_hide_sys = QCheckBox("隐藏系统自带")
        self.chk_hide_sys.setChecked(True)
        self.chk_hide_sys.stateChanged.connect(lambda _s: self._fill())
        bar.addWidget(self.chk_hide_sys)
        bar.addStretch(1)
        self.lbl_count = QLabel("")
        self.lbl_count.setObjectName("hint")
        bar.addWidget(self.lbl_count)
        v.addLayout(bar)

        self.tree = QTreeWidget()
        self.tree.setColumnCount(len(self.COLS))
        self.tree.setHeaderLabels(list(self.COLS))
        self.tree.setRootIsDecorated(False)
        self.tree.setAlternatingRowColors(True)
        self.tree.setUniformRowHeights(True)
        self.tree.setSelectionMode(QAbstractItemView.ExtendedSelection)
        hh = self.tree.header()
        hh.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        for c in (1, 2, 3, 4):
            hh.setSectionResizeMode(c, QHeaderView.Interactive)
        hh.setSectionResizeMode(5, QHeaderView.Stretch)
        self.tree.setColumnWidth(1, 230)
        self.tree.setColumnWidth(2, 190)
        self.tree.setColumnWidth(3, 130)
        self.tree.setColumnWidth(4, 150)
        self.tree.itemDoubleClicked.connect(lambda it, _c: self._toggle_item(it))
        self.tree.itemSelectionChanged.connect(self._sync_buttons)
        v.addWidget(self.tree, 1)
        self.refresh()

    def refresh(self):
        try:
            self.apps = bc.list_notify_apps(self.root_sub)
        except Exception as e:
            bc.log_line("list_notify_apps failed: %r" % (e,))
            self.apps = []
        self._fill()

    def stats(self):
        return {"total": len(self.apps),
                "on": sum(1 for a in self.apps if a["enabled"]),
                "adware_on": sum(1 for a in self.apps if a["enabled"] and a["adware"])}

    def _fill(self):
        self.tree.clear()
        hide_sys = self.chk_hide_sys.isChecked()
        shown = 0
        for a in self.apps:
            if hide_sys and a["system"] and not a["adware"]:
                continue
            it = QTreeWidgetItem([
                "开" if a["enabled"] else "关", a["name"], a["company"], a["last"],
                ("流氓软件：%s" % a["adware"]) if a["adware"] else "", a["aumid"]])
            it.setData(0, Qt.UserRole, a["aumid"])
            it.setToolTip(1, a["path"] or a["aumid"])
            it.setForeground(0, QBrush(QColor(PAL["ok"] if a["enabled"] else PAL["faint"])))
            if a["adware"]:
                it.setForeground(4, QBrush(QColor(PAL["err"])))
            self.tree.addTopLevelItem(it)
            shown += 1
        st = self.stats()
        self.lbl_count.setText("显示 %d / 共 %d 个应用，%d 个允许通知" % (shown, st["total"], st["on"]))
        self.btn_adware_off.setText("关闭所有流氓软件的通知（%d）" % st["adware_on"])
        self.btn_adware_off.setVisible(st["adware_on"] > 0)
        self._sync_buttons()

    def _sync_buttons(self):
        n = len(self.tree.selectedItems())
        self.btn_off.setEnabled(n > 0)
        self.btn_on.setEnabled(n > 0)
        self.btn_off.setText("关闭所选应用的通知" + ("（%d）" % n if n > 1 else ""))

    def _toggle_item(self, it):
        aumid = it.data(0, Qt.UserRole)
        a = next((x for x in self.apps if x["aumid"] == aumid), None)
        if a:
            self._apply([aumid], not a["enabled"])

    @guard
    def off_adware(self):
        hits = [a for a in self.apps if a["enabled"] and a["adware"]]
        if not hits:
            return
        names = "\n".join("· %s（%s）" % (a["name"], a["adware"]) for a in hits[:12])
        if len(hits) > 12:
            names += "\n… 共 %d 个" % len(hits)
        if QMessageBox.question(
                self, "关闭流氓软件的通知",
                "将关闭这 %d 个应用的系统通知：\n\n%s\n\n之后可以随时在这里恢复。" % (len(hits), names),
                QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes) != QMessageBox.Yes:
            return
        self._apply([a["aumid"] for a in hits], False)

    @guard
    def set_selected(self, on):
        ids = [it.data(0, Qt.UserRole) for it in self.tree.selectedItems()]
        if ids:
            self._apply(ids, on)

    def _apply(self, ids, on):
        fails = []
        for aumid in ids:
            ok, msg = bc.set_notify_enabled(aumid, on, self.root_sub)
            if not ok:
                fails.append(msg)
        self.refresh()
        if fails:
            QMessageBox.warning(self, "通知管理", "\n".join(fails[:10]))
        w = self.window()
        if hasattr(w, "_sync_nav_badges"):
            w._sync_nav_badges()


class BackupPage(QWidget):
    """备份与还原：每次修复前的快照都在这里，选一个就能回到当时的状态。"""

    def __init__(self, main, parent=None):
        super().__init__(parent)
        self.main = main
        v = QVBoxLayout(self)
        v.setContentsMargins(14, 12, 14, 10)
        v.setSpacing(8)
        t = QLabel("备份与还原")
        t.setObjectName("pageTitle")
        v.addWidget(t)
        hint = QLabel("每次执行修复前都会自动备份。还原会把这次修复改过的启动项、服务、计划任务改回原样。")
        hint.setObjectName("hint")
        hint.setWordWrap(True)
        v.addWidget(hint)

        bar = QHBoxLayout()
        bar.setSpacing(6)
        self.btn_restore = QPushButton("还原所选备份")
        self.btn_restore.setObjectName("primary")
        self.btn_restore.clicked.connect(self.on_restore)
        bar.addWidget(self.btn_restore)
        self.btn_dir = QPushButton("打开备份目录")
        self.btn_dir.clicked.connect(lambda: self.main.open_backup_dir())
        bar.addWidget(self.btn_dir)
        self.btn_refresh = QPushButton("刷新")
        self.btn_refresh.clicked.connect(self.refresh)
        bar.addWidget(self.btn_refresh)
        bar.addStretch(1)
        v.addLayout(bar)

        split = QSplitter(Qt.Horizontal)
        split.setChildrenCollapsible(False)
        self.tree = QTreeWidget()
        self.tree.setColumnCount(3)
        self.tree.setHeaderLabels(["备份时间", "改动项数", "目录"])
        self.tree.setRootIsDecorated(False)
        self.tree.setAlternatingRowColors(True)
        self.tree.setUniformRowHeights(True)
        hh = self.tree.header()
        hh.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(2, QHeaderView.Stretch)
        self.tree.currentItemChanged.connect(lambda cur, _p: self._show(cur))
        split.addWidget(self.tree)
        self.detail = QTextBrowser()
        self.detail.setOpenExternalLinks(False)
        split.addWidget(self.detail)
        split.setSizes([420, 520])
        v.addWidget(split, 1)
        self.refresh()

    def refresh(self):
        self.backups = bc.list_backups()
        self.tree.clear()
        for b in self.backups:
            it = QTreeWidgetItem([b["created"] or b["name"], str(b["count"]), b["dir"]])
            it.setData(0, Qt.UserRole, b["dir"])
            self.tree.addTopLevelItem(it)
        if self.backups:
            self.tree.setCurrentItem(self.tree.topLevelItem(0))
        else:
            self.detail.setPlainText("还没有备份。执行第一次修复时会自动创建。")
        self.btn_restore.setEnabled(bool(self.backups))

    def _show(self, it):
        if not it:
            return
        d = it.data(0, Qt.UserRole)
        txt = ""
        for fn in ("说明.txt", "README.txt"):
            p = os.path.join(d, fn)
            if os.path.isfile(p):
                try:
                    with open(p, "r", encoding="utf-8", errors="replace") as fp:
                        txt = fp.read()
                except OSError:
                    pass
                break
        self.detail.setPlainText(txt or d)

    @guard
    def on_restore(self):
        it = self.tree.currentItem()
        if it:
            self.main.restore_dir(it.data(0, Qt.UserRole))


class MainWindow(QMainWindow):
    def __init__(self, autoscan=None):
        super().__init__()
        self._custom_chrome = bool(USE_CUSTOM_CHROME)
        if self._custom_chrome:
            # 去掉系统标题栏那条白条：菜单栏顶上自带窗口按钮，拖动/缩放走系统原生
            self.setWindowFlags(Qt.Window | Qt.FramelessWindowHint |
                                Qt.WindowMinMaxButtonsHint)
        self.setWindowTitle("%s %s" % (bc.APP_NAME, bc.VERSION))
        # 尺寸按屏幕可用区（逻辑像素）算。
        # 注意别写死 1400x900 之类的上限：4K 屏开 150% 缩放后逻辑分辨率是 2560x1440，
        # 上限压到 1400 会让窗口只占半屏；而 1080p 上又太大。按比例取才两边都对。
        try:
            scr = QApplication.primaryScreen()
            avail = scr.availableGeometry()
            aw, ah = avail.width(), avail.height()
            w = int(aw * 0.86)
            h = int(ah * 0.88)
            # 下限保证内容能放下，上限别超出可用区
            w = max(min(1180, aw), min(w, aw - 40))
            h = max(min(700, ah), min(h, ah - 60))
            # 最小尺寸也要跟着屏幕走：小屏（1366x768）上写死 960x600 会顶到边，
            # 再小一点的屏（虚拟桌面 800x600）直接超出可用区，窗口被裁掉一块
            min_w = min(960, max(640, aw - 20))
            min_h = min(600, max(480, ah - 40))
        except Exception:
            w, h = 1280, 820
            min_w, min_h = 960, 600
        self.resize(w, h)
        self.setMinimumSize(min_w, min_h)
        self.result = None
        self._raw = None
        self._filling = False
        self._ops = {}          # finding id -> 用户选的处理方式
        self._cur_app = {}
        self._icon_cache = {}
        self._icon_provider = QFileIconProvider()
        self._sort_col = -1
        self._sort_desc = False
        self._stale = False          # 界面上显示的是不是上次的缓存结果（正在后台刷新）
        self.scan_worker = None
        self.fix_worker = None
        self.restore_worker = None
        self.ai_worker = None
        self._build_ui()
        # 真毛玻璃：拿到窗口句柄后才能调 DWM。失败就留在渐变伪毛玻璃，不影响任何功能
        self._glass = enable_glass(self, _THEME)
        if self._glass:
            QApplication.instance().setStyleSheet(build_qss())
        self._update_admin_badge()
        self._refresh_restore_state()
        self._show_welcome()
        if autoscan is None:
            autoscan = bool(bc.get_setting("autoscan", True))
        if os.environ.get("BOOTDOC_NOSCAN"):
            autoscan = False
        if autoscan:
            QTimer.singleShot(0, self._show_cached_then_scan)

    # ---------------- 界面骨架 ----------------
    def paintEvent(self, ev):
        """毛玻璃模式下自己铺窗口渐变（QSS 的 QMainWindow background 在透明窗口里不生效）。"""
        _t0 = time.perf_counter() if _PROF_PATH else 0.0
        super().paintEvent(ev)
        if _ACRYLIC_ON:
            try:
                p = QPainter(self)
                p.fillRect(self.rect(), win_brush(self.width(), self.height()))
                if self._custom_chrome and not self.isMaximized():
                    # 无边框后没有系统阴影，用一圈亮线把窗口从桌面上"托"起来
                    p.setPen(QColor(255, 255, 255, 38 if is_dark() else 200))
                    r = self.rect().adjusted(0, 0, -1, -1)
                    p.drawRect(r)
                p.end()
            except Exception:
                pass
        if _PROF_PATH:
            _t1 = time.perf_counter()
            d = PROF
            d["paint"][0] += 1
            d["paint"][1] += _t1 - _t0
            d["paint"][2] = max(d["paint"][2], _t1 - _t0)
            d["paint_ms"].append((_t1 - _t0) * 1000.0)
            d["sizes"].add((self.width(), self.height()))
            _lt = d["_last_t"]
            if _lt:
                d["gaps"].append((_t1 - _lt) * 1000.0)
            d["_last_t"] = _t1

    def _ic(self, sp):
        return self.style().standardIcon(sp)

    def _act(self, text, slot, shortcut=None, icon=None):
        a = QAction(text, self)
        if shortcut:
            a.setShortcut(shortcut)
        if icon is not None:
            a.setIcon(self._ic(icon))
        a.triggered.connect(lambda _c=False: slot())
        return a

    def _build_ui(self):
        self._build_menu()
        if self._custom_chrome:
            self._build_caption()
        self._build_toolbar()

        root = QWidget()
        self.setCentralWidget(root)
        v = QVBoxLayout(root)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)

        # 左侧导航 + 右侧分页。「开机体检」页就是原来的整套界面，一行没改，只是搬进了第一页
        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)
        self.nav = QListWidget()
        self.nav.setObjectName("nav")
        self.nav.setFixedWidth(158)        # 放得下「开机体检　100」「弹窗拦截　守护中」
        self.nav.setIconSize(QSize(16, 16))
        self.nav.setFocusPolicy(Qt.NoFocus)
        self.nav.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.nav.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        body.addWidget(self.nav)
        self.pages = QStackedWidget()
        body.addWidget(self.pages, 1)
        v.addLayout(body, 1)

        scan_page = QWidget()
        sv = QVBoxLayout(scan_page)
        sv.setContentsMargins(0, 0, 0, 0)
        sv.setSpacing(0)
        sv.addWidget(self._build_header())
        split = QSplitter(Qt.Horizontal)
        split.setChildrenCollapsible(False)
        split.addWidget(self._build_table())
        split.addWidget(self._build_right())
        split.setSizes([int(self.width() * 0.63), int(self.width() * 0.37)])
        sv.addWidget(split, 1)
        sv.addWidget(self._build_opbar())

        # (key, 标题, 图标, 构建函数)。除第一页外都是首次打开时才建：
        # 弹窗页一建就要枚举全部窗口，放到启动时会拖慢打开
        self._page_defs = [
            ("scan", "开机体检", QStyle.SP_BrowserReload, lambda: scan_page),
            ("popup", "实时防护", QStyle.SP_ComputerIcon, self._make_popup_page),
            ("notify", "通知管理", QStyle.SP_MessageBoxInformation, lambda: NotifyPage(self)),
            ("backup", "备份还原", QStyle.SP_DialogSaveButton, lambda: BackupPage(self)),
        ]
        self._page_built = {}
        for key, title, icon, _mk in self._page_defs:
            it = QListWidgetItem(self._ic(icon), title)
            it.setData(Qt.UserRole, key)
            self.nav.addItem(it)
            self.pages.addWidget(QWidget())                 # 占位，首次进入时替换
        self.nav.currentRowChanged.connect(self._on_nav)
        self.nav.setCurrentRow(0)

        self.log_edit = QPlainTextEdit()
        self.log_edit.setReadOnly(True)
        self.log_edit.setFixedHeight(140)
        self.log_edit.hide()
        v.addWidget(self.log_edit)

        sb = self.statusBar()
        sb.showMessage("就绪")
        self.lbl_status = QLabel("延迟 %s" % bc.delay_text())
        self.lbl_status.setObjectName("hint")
        sb.addPermanentWidget(self.lbl_status)
        self.lbl_bk = QLabel("")
        self.lbl_bk.setObjectName("hint")
        sb.addPermanentWidget(self.lbl_bk)
        self.lbl_admin = QLabel("")
        sb.addPermanentWidget(self.lbl_admin)
        self.btn_elevate = QPushButton("以管理员重启")
        self.btn_elevate.setObjectName("flat")
        self.btn_elevate.setCursor(Qt.PointingHandCursor)
        self.btn_elevate.clicked.connect(self.on_elevate)
        sb.addPermanentWidget(self.btn_elevate)
        self.btn_log = QPushButton("运行日志")
        self.btn_log.setObjectName("flat")
        self.btn_log.setCursor(Qt.PointingHandCursor)
        self.btn_log.clicked.connect(self.on_toggle_log)
        sb.addPermanentWidget(self.btn_log)

    # ---------------- 分页 ----------------
    def _page_index(self, key):
        for i, d in enumerate(self._page_defs):
            if d[0] == key:
                return i
        return -1

    def page_widget(self, key, build=True):
        """取某一页的控件；build=True 时没建过就现在建。"""
        i = self._page_index(key)
        if i < 0:
            return None
        if key not in self._page_built and build:
            w = self._page_defs[i][3]()
            old = self.pages.widget(i)
            self.pages.insertWidget(i, w)
            self.pages.removeWidget(old)
            old.deleteLater()
            self._page_built[key] = w
        return self._page_built.get(key)

    def show_page(self, key):
        i = self._page_index(key)
        if i >= 0:
            self.nav.setCurrentRow(i)          # 触发 _on_nav

    def current_page(self):
        it = self.nav.currentItem()
        return it.data(Qt.UserRole) if it else "scan"

    @guard
    def _on_nav(self, row):
        if row < 0:
            return
        key = self._page_defs[row][0]
        self.page_widget(key)
        self.pages.setCurrentIndex(row)
        # 搜索 / 分类过滤 / 延迟时长只对「开机体检」页有意义，别的页藏起来，免得以为能筛别的页
        for act in getattr(self, "_scan_only_acts", []):
            act.setVisible(key == "scan")
        self._sync_nav_badges()

    def _make_popup_page(self):
        dlg = PopupDialog(self)
        dlg.setWindowFlags(Qt.Widget)          # 对话框当普通控件嵌进来
        return dlg

    def _sync_nav_badges(self):
        """导航项后面挂一句状态：分数 / 守护是否在跑 / 有几个流氓软件还在发通知 / 备份数。"""
        if not hasattr(self, "nav") or not hasattr(self, "_page_defs"):
            return
        texts = {"scan": "开机体检", "popup": "实时防护", "notify": "通知管理", "backup": "备份还原"}
        if self.result and self.result.get("score") is not None:
            texts["scan"] += "　%s" % self.result.get("score")
        try:
            texts["popup"] += "　%s" % ("守护中" if bc.guard_running() else "未开")
        except Exception:
            pass
        npage = self._page_built.get("notify")
        if npage is not None:
            n = npage.stats().get("adware_on", 0)
            if n:
                texts["notify"] += "　%d" % n
        try:
            nb = len(bc.list_backups())
            if nb:
                texts["backup"] += "　%d" % nb
        except Exception:
            pass
        for i, d in enumerate(self._page_defs):
            it = self.nav.item(i)
            if it and it.text() != texts[d[0]]:
                it.setText(texts[d[0]])

    @staticmethod
    def _cap_pix(kind, color, size=13):
        """自己画 − □ ✕：系统的 SP_TitleBar* 图标带一圈方框，压在玻璃上很脏。"""
        pm = QPixmap(size, size)
        pm.fill(Qt.transparent)
        p = QPainter(pm)
        p.setRenderHint(QPainter.Antialiasing, True)
        p.setPen(QPen(QColor(color), 1.4))
        m = 3
        if kind == "min":
            p.drawLine(m + 1, size // 2, size - m - 1, size // 2)
        elif kind == "max":
            p.drawRect(m, m, size - 2 * m, size - 2 * m)
        elif kind == "restore":
            p.drawRect(m, m + 2, size - 2 * m - 2, size - 2 * m - 2)
            p.drawLine(m + 2, m, size - m, m)
            p.drawLine(size - m, m, size - m, size - m - 2)
        elif kind == "close":
            p.drawLine(m + 1, m + 1, size - m - 1, size - m - 1)
            p.drawLine(size - m - 1, m + 1, m + 1, size - m - 1)
        p.end()
        return pm

    def _cap_icons(self):
        if not self._custom_chrome:
            return
        col = PAL["muted"] if is_dark() else PAL["text"]
        self.btn_cap_min.setIcon(QIcon(self._cap_pix("min", col)))
        self.btn_cap_max.setIcon(QIcon(self._cap_pix(
            "restore" if self.isMaximized() else "max", col)))
        self.btn_cap_close.setIcon(QIcon(self._cap_pix("close", PAL["text"])))

    def _build_caption(self):
        """菜单栏右上角的 − □ ×。菜单栏同时也是拖动区（双击最大化）。"""
        box = QWidget()
        h = QHBoxLayout(box)
        h.setContentsMargins(0, 0, 4, 0)
        h.setSpacing(2)
        def mk(tip, name, slot):
            b = QPushButton()
            b.setObjectName(name)
            b.setIconSize(QSize(13, 13))
            b.setFixedSize(34, 24)
            b.setToolTip(tip)
            b.setFocusPolicy(Qt.NoFocus)
            b.setCursor(Qt.PointingHandCursor)
            b.clicked.connect(slot)
            h.addWidget(b)
            return b

        self.btn_cap_min = mk("最小化", "cap", self.on_minimize)
        self.btn_cap_max = mk("最大化", "cap", self.on_toggle_max)
        self.btn_cap_close = mk("关闭", "capClose", self.close)
        self._cap_icons()
        self.menuBar().setCornerWidget(box, Qt.TopRightCorner)
        self.menuBar().installEventFilter(self)
        self.menuBar().setMouseTracking(True)

    @guard
    def on_minimize(self):
        self.showMinimized()

    @guard
    def on_toggle_max(self):
        if self.isMaximized():
            self.showNormal()
        else:
            self.showMaximized()
        QTimer.singleShot(0, self._sync_caption)

    def _sync_caption(self):
        if not self._custom_chrome or self.btn_cap_max is None:
            return
        self.btn_cap_max.setToolTip("向下还原" if self.isMaximized() else "最大化")
        self._cap_icons()

    def changeEvent(self, ev):
        super().changeEvent(ev)
        if ev.type() == QEvent.WindowStateChange:
            self._sync_caption()

    def eventFilter(self, obj, ev):
        """菜单栏空白处按下 = 拖窗口；双击 = 最大化/还原。菜单项本身不受影响。"""
        if obj is self.menuBar() and self._custom_chrome:
            t = ev.type()
            if t == QEvent.MouseButtonPress and ev.button() == Qt.LeftButton:
                act = self.menuBar().actionAt(ev.pos())
                if act is None:
                    wh = self.windowHandle()
                    if wh is not None and hasattr(wh, "startSystemMove"):
                        ok = wh.startSystemMove()
                        if _PROF_PATH:
                            PROF.setdefault("trace", []).append(
                                "press local=%s startSystemMove=%r" % (ev.pos(), ok))
                        return True
                elif _PROF_PATH:
                    PROF.setdefault("trace", []).append(
                        "press local=%s hit_action=%r（没拖动，点到菜单项了）"
                        % (ev.pos(), act.text()))
            elif t == QEvent.MouseButtonDblClick:
                if self.menuBar().actionAt(ev.pos()) is None:
                    self.on_toggle_max()
                    return True
        return super().eventFilter(obj, ev)

    def nativeEvent(self, eventType, message):
        """无边框窗口的边缘缩放：把边框交还给系统做 HTxxx 命中测试。

        坐标系统一定要对齐，否则鼠标在窗口内部也会被判成"边缘"，光标变成缩放箭头：
          WM_NCHITTEST 的 lParam 是 **物理像素**（屏幕坐标系，不受 DPI 缩放影响）
          frameGeometry() 在开了 HighDpiScaling 后是 **逻辑像素**
        两者在 150% 缩放下差 1.5 倍、200% 下差 2 倍。直接用会整体偏移，
        表现为"鼠标明明在中间，却显示成右下角的缩放光标"。

        解法：把 lParam 除以 devicePixelRatio 换算到逻辑坐标，再和 frameGeometry 比。
        """
        if eventType == b"windows_generic_MSG":
            _t0 = time.perf_counter() if _PROF_PATH else 0.0
            try:
                import ctypes.wintypes as wt
                msg = wt.MSG.from_address(int(message))
                # 拖动 / 缩放开始与结束：这两个消息不区分有没有自绘标题栏，
                # 只要开着亚克力就得降级，否则 DWM 每帧重算整窗模糊 → 30fps。
                if msg.message == 0x0231:          # WM_ENTERSIZEMOVE
                    set_glass_low(self, True)
                elif msg.message == 0x0232:        # WM_EXITSIZEMOVE
                    set_glass_low(self, False)
                    try:
                        self._fit_columns()        # 拖动期间跳过的列宽对齐，这里补上
                    except Exception:
                        pass
                elif self._custom_chrome and msg.message == 0x0084 \
                        and not self.isMaximized():                 # WM_NCHITTEST
                    # 物理像素坐标（有符号 16 位）
                    px = ctypes.c_short(msg.lParam & 0xFFFF).value
                    py = ctypes.c_short((msg.lParam >> 16) & 0xFFFF).value
                    # 换算到逻辑坐标
                    ratio = self._dpr()
                    x = int(px / ratio)
                    y = int(py / ratio)
                    g = self.frameGeometry()
                    b = max(4, int(6 / ratio))     # 抓边宽度也跟着缩放，否则 200% 下太宽
                    left = x < g.left() + b
                    right = x >= g.right() - b
                    top = y < g.top() + b
                    bottom = y >= g.bottom() - b
                    # 只有真的落在边缘带里才返回 HTxxx，否则交回系统当客户区处理
                    if top and left:
                        hit = 13
                    elif top and right:
                        hit = 14
                    elif bottom and left:
                        hit = 16
                    elif bottom and right:
                        hit = 17
                    elif left:
                        hit = 10
                    elif right:
                        hit = 11
                    elif top:
                        hit = 12
                    elif bottom:
                        hit = 15
                    else:
                        # 落在客户区：明确告诉系统这是客户区，避免继承到缩放光标
                        hit = 1             # HTCLIENT
                    if _PROF_PATH:
                        _t1 = time.perf_counter()
                        d = PROF
                        d["hittest"][0] += 1
                        d["hittest"][1] += _t1 - _t0
                        d["hittest"][2] = max(d["hittest"][2], _t1 - _t0)
                    return True, hit
            except Exception:
                pass
        return super().nativeEvent(eventType, message)

    @staticmethod
    def _dpr():
        """当前窗口所在屏幕的 devicePixelRatio（拿不到就按 1 算）。"""
        try:
            scr = QApplication.screenAt(QCursor.pos()) or QApplication.primaryScreen()
            return float(scr.devicePixelRatio()) or 1.0
        except Exception:
            try:
                return float(QApplication.primaryScreen().devicePixelRatio()) or 1.0
            except Exception:
                return 1.0

    def _build_menu(self):
        mb = self.menuBar()
        m_file = mb.addMenu("文件(&F)")
        m_file.addAction(self._act("重新体检", self.on_scan, "F5", QStyle.SP_BrowserReload))
        m_file.addSeparator()
        m_file.addAction(self._act("导出体检报告…", self.on_export))
        m_file.addAction(self._act("导出清单 CSV…", self.on_export_csv))
        m_file.addAction(self._act("导出 HTML 报告…", self.on_export_html, "Ctrl+Shift+H"))
        m_file.addSeparator()
        m_file.addAction(self._act("退出", self.close, "Ctrl+Q"))

        m_edit = mb.addMenu("编辑(&E)")
        m_edit.addAction(self._act("全选", lambda: self.tree.selectAll(), "Ctrl+A"))
        m_edit.addAction(self._act("全部勾选", lambda: self._check_all(True)))
        m_edit.addAction(self._act("全部取消勾选", lambda: self._check_all(False)))
        m_edit.addSeparator()
        m_edit.addAction(self._act("查找…", self.focus_search, "Ctrl+F"))

        m_view = mb.addMenu("视图(&V)")
        for _n, (_k, _t) in enumerate((("scan", "开机体检"), ("popup", "实时防护"),
                                       ("notify", "通知管理"), ("backup", "备份还原")), 1):
            m_view.addAction(self._act(_t, lambda _k=_k: self.show_page(_k), "Ctrl+%d" % _n))
        m_view.addSeparator()
        m_view.addAction(self._act("展开全部", lambda: self.tree.expandAll()))
        m_view.addAction(self._act("收起全部", lambda: self.tree.collapseAll()))
        m_view.addSeparator()
        m_view.addAction(self._act("开机耗时趋势…", self.on_boot_trend))
        m_view.addAction(self._act("运行日志", self.on_toggle_log))
        m_view.addSeparator()
        m_view.addAction(self._act("设置…", self.on_settings, "Ctrl+,",
                                   QStyle.SP_FileDialogDetailedView))

        m_op = mb.addMenu("操作(&O)")
        m_op.addAction(self._act("智能优化（执行勾选项）", self.on_apply,
                                 "Ctrl+Enter", QStyle.SP_DialogApplyButton))
        m_op.addAction(self._act("立即执行选中项", self.on_apply_one))
        m_op.addSeparator()
        m_op.addAction(self._act("流氓软件 / 全家桶扫描", self.on_adware_only,
                                 "Ctrl+Shift+A", QStyle.SP_MessageBoxWarning))
        m_op.addAction(self._act("更新流氓软件特征库…", self.on_update_db, None,
                                 QStyle.SP_DriveNetIcon))
        m_op.addAction(self._act("弹窗拦截…", self.on_popup_dialog, "Ctrl+Shift+P",
                                 QStyle.SP_ComputerIcon))
        m_op.addSeparator()
        m_op.addAction(self._act("AI 帮我判断", self.on_ai, None,
                                 QStyle.SP_MessageBoxQuestion))
        m_op.addSeparator()
        m_op.addAction(self._act("还原备份…", self.on_restore))
        m_op.addAction(self._act("通知管理…", lambda: self.show_page("notify")))
        m_op.addAction(self._act("查看备份目录", self.open_backup_dir))

        m_help = mb.addMenu("帮助(&H)")
        m_help.addAction(self._act("使用说明", self._show_welcome))
        m_help.addAction(self._act("关于", self.on_about))

    def _build_toolbar(self):
        tb = QToolBar("主工具栏")
        tb.setMovable(False)
        tb.setFloatable(False)
        tb.setIconSize(QSize(16, 16))
        tb.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self.addToolBar(tb)
        self.tb = tb

        self.btn_scan = QPushButton(" 体检")
        self.btn_scan.setIcon(self._ic(QStyle.SP_BrowserReload))
        self.btn_scan.setObjectName("primary")
        self.btn_scan.setToolTip("重新扫描开机链路（F5）")
        self.btn_scan.clicked.connect(self.on_scan)
        tb.addWidget(self.btn_scan)

        self.btn_apply = QPushButton("智能优化（0）")
        self.btn_apply.setIcon(self._ic(QStyle.SP_DialogApplyButton))
        self.btn_apply.setToolTip("执行勾选项中选定的处理方式（Ctrl+Enter），执行前自动备份")
        self.btn_apply.clicked.connect(self.on_apply)
        tb.addWidget(self.btn_apply)

        self.btn_ai = QPushButton("AI 判断")
        self.btn_ai.setIcon(self._ic(QStyle.SP_MessageBoxQuestion))
        self.btn_ai.clicked.connect(self.on_ai)
        tb.addWidget(self.btn_ai)
        self._refresh_ai_button()

        self._scan_only_acts = [tb.addSeparator()]

        self.ed_search = QLineEdit()
        self.ed_search.setPlaceholderText("搜索项目 / 应用 / 发布者 …")
        self.ed_search.setClearButtonEnabled(True)
        self.ed_search.setFixedWidth(190)
        self.ed_search.textChanged.connect(lambda _t: self._apply_view())
        self._scan_only_acts.append(tb.addWidget(self.ed_search))

        self.cb_cat = QComboBox()
        self.cb_cat.setFixedWidth(104)
        self.cb_cat.addItem("全部分类", MODE_ALL)
        self.cb_cat.addItem("只看要处理", MODE_TODO)
        for c in bc.CAT_ORDER:
            self.cb_cat.addItem(c, c)
        self.cb_cat.currentIndexChanged.connect(lambda _i: self._apply_view())
        self._scan_only_acts.append(tb.addWidget(self.cb_cat))

        self.chk_third = QCheckBox("只看第三方")
        self.chk_third.setToolTip("隐藏微软 / Windows 自带组件")
        self.chk_third.stateChanged.connect(lambda _s: self._apply_view())
        self._scan_only_acts.append(tb.addWidget(self.chk_third))

        self.lbl_count = QLabel("")
        self.lbl_count.setObjectName("hint")
        self._scan_only_acts.append(tb.addWidget(self.lbl_count))

        self._scan_only_acts.append(tb.addSeparator())

        lbl_delay = QLabel("延迟")
        lbl_delay.setObjectName("meta")
        self._scan_only_acts.append(tb.addWidget(lbl_delay))
        self.cb_delay = QComboBox()
        for sec, label in bc.DELAY_CHOICES:
            self.cb_delay.addItem(label, sec)
        _di = self.cb_delay.findData(bc.get_delay_seconds())
        self.cb_delay.setCurrentIndex(_di if _di >= 0 else 1)
        self.cb_delay.setFixedWidth(84)
        self.cb_delay.setToolTip("「延迟启动」使用多久：新建延迟任务或修改已有任务时生效")
        self.cb_delay.currentIndexChanged.connect(self.on_delay_changed)
        self._scan_only_acts.append(tb.addWidget(self.cb_delay))

        tb.addSeparator()

        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        tb.addWidget(spacer)

        self.btn_db = QPushButton("特征库")
        self.btn_db.setIcon(self._ic(QStyle.SP_DriveNetIcon))
        self.btn_db.clicked.connect(self.on_update_db)
        tb.addWidget(self.btn_db)
        self._sync_db_btn()

        self.btn_settings = QPushButton("设置")
        self.btn_settings.setIcon(self._ic(QStyle.SP_FileDialogDetailedView))
        self.btn_settings.setToolTip("设置：AI 接口 / 通用 / 外观（Ctrl+,）")
        self.btn_settings.clicked.connect(self.on_settings)
        tb.addWidget(self.btn_settings)

        # 还原 / 导出 放在菜单里（低频），这里保留按钮对象做状态同步（不显示）
        self.btn_restore = QPushButton("还原", self)
        self.btn_restore.setVisible(False)
        self.btn_export = QPushButton("导出", self)
        self.btn_export.setVisible(False)

    def _refresh_ai_button(self):
        base, model = bc.get_ai_cfg()
        enabled = bool(bc.get_setting("ai_enabled", True))
        self.btn_ai.setText("AI 判断" if enabled else "AI（已关）")
        if enabled:
            self.btn_ai.setToolTip("用本地 AI（%s）逐项判断：这是什么软件、能不能关。\n"
                                   "网关：%s\n接口在「设置 → AI 接口」里改。" % (model, base))
        else:
            self.btn_ai.setToolTip("AI 已在设置里关闭。点开「设置 → AI 接口」启用。")

    def _build_header(self):
        f = QFrame()
        f.setObjectName("hdr")
        h = QHBoxLayout(f)
        h.setContentsMargins(14, 8, 14, 8)
        h.setSpacing(14)

        col = QVBoxLayout()
        col.setSpacing(0)
        cap = QLabel("健康分")
        cap.setObjectName("hint")
        col.addWidget(cap)
        self.lbl_score = QLabel("—")
        self.lbl_score.setObjectName("score")
        col.addWidget(self.lbl_score)
        h.addLayout(col)

        col2 = QVBoxLayout()
        col2.setSpacing(3)
        row = QHBoxLayout()
        row.setSpacing(8)
        self.lbl_grade = QLabel("尚未体检")
        self.lbl_grade.setObjectName("grade")
        row.addWidget(self.lbl_grade)
        self.lbl_meta = QLabel("")
        self.lbl_meta.setObjectName("meta")
        row.addWidget(self.lbl_meta)
        row.addStretch(1)
        col2.addLayout(row)
        self.lbl_summary = QLabel("点「体检」扫描开机链路的健康状态。")
        self.lbl_summary.setObjectName("summary")
        self.lbl_summary.setWordWrap(True)
        col2.addWidget(self.lbl_summary)
        h.addLayout(col2, 1)

        self.bar = QProgressBar()
        self.bar.setRange(0, 100)
        self.bar.setValue(0)
        self.bar.setTextVisible(False)
        self.bar.setFixedWidth(140)
        self.bar.setFixedHeight(4)
        h.addWidget(self.bar, 0, Qt.AlignVCenter)
        return f

    def _build_table(self):
        self.tree = QTreeWidget()
        self.tree.setColumnCount(6)
        self.tree.setHeaderLabels(["项目", "等级", "应用", "状态 / 说明", "发布者", "签名"])
        self.tree.setRootIsDecorated(True)
        self.tree.setAlternatingRowColors(True)
        self.tree.setUniformRowHeights(True)
        self.tree.setIconSize(QSize(16, 16))
        self.tree.setAllColumnsShowFocus(True)
        self.tree.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.on_tree_menu)
        self.tree.itemChanged.connect(self.on_item_changed)
        self.tree.currentItemChanged.connect(self.on_cur_changed)
        self.tree.itemSelectionChanged.connect(self.on_sel_changed)
        self.tree.itemDoubleClicked.connect(self.on_tree_dblclick)
        self.tree.header().setStretchLastSection(False)
        self.tree.header().setHighlightSections(False)
        self.tree.header().setSectionsClickable(True)
        self.tree.header().sectionClicked.connect(self.on_header_click)
        for i, w in ((0, 300), (1, 42), (2, 190), (3, 190), (4, 110), (5, 66)):
            self.tree.setColumnWidth(i, w)
        self.tree.setColumnWidth(1, 42)
        self._tree_palette()
        return self.tree

    def _tree_palette(self):
        """树的缩进区（branch）用 QPalette 上色，QSS 管不到它。

        不设的话，选中行最左边那条缩进带会用系统 Highlight（深色主题下是亮白），
        看起来像一块白斑。
        """
        try:
            pal = self.tree.palette()
            pal.setColor(QPalette.Base, QColor(PAL["panel"]))
            pal.setColor(QPalette.AlternateBase, QColor(PAL["alt"]))
            pal.setColor(QPalette.Text, QColor(PAL["text"]))
            pal.setColor(QPalette.WindowText, QColor(PAL["text"]))
            pal.setColor(QPalette.Highlight, QColor(PAL["sel_solid"]))
            pal.setColor(QPalette.HighlightedText, QColor(PAL["text"]))
            self.tree.setPalette(pal)
            vp = self.tree.viewport()
            vp.setPalette(pal)
            vp.setAutoFillBackground(True)
        except Exception:
            pass

    def _build_right(self):
        right = QWidget()
        rv = QVBoxLayout(right)
        rv.setContentsMargins(6, 6, 6, 6)
        rv.setSpacing(0)

        self.app_head = QFrame()
        self.app_head.setObjectName("apphead")
        ah = QHBoxLayout(self.app_head)
        ah.setContentsMargins(10, 7, 10, 7)
        ah.setSpacing(10)
        self.app_head_icon = QLabel()
        self.app_head_icon.setFixedSize(32, 32)
        ah.addWidget(self.app_head_icon, 0, Qt.AlignTop)
        acv = QVBoxLayout()
        acv.setSpacing(1)
        self.app_head_name = QLabel("")
        self.app_head_name.setObjectName("appname")
        self.app_head_name.setWordWrap(True)
        acv.addWidget(self.app_head_name)
        self.app_head_meta = QLabel("")
        self.app_head_meta.setObjectName("meta")
        self.app_head_meta.setWordWrap(True)
        acv.addWidget(self.app_head_meta)
        ah.addLayout(acv, 1)
        self.app_head_sig = QLabel("")
        self.app_head_sig.setObjectName("meta")
        ah.addWidget(self.app_head_sig, 0, Qt.AlignTop)
        self.btn_app_more = QPushButton("详情")
        self.btn_app_more.setObjectName("flat")
        self.btn_app_more.clicked.connect(self.on_app_more)
        ah.addWidget(self.btn_app_more, 0, Qt.AlignTop)
        self.app_head.setVisible(False)
        rv.addWidget(self.app_head)

        self.detail = QTextBrowser()
        self.detail.setOpenExternalLinks(True)
        self.detail.setWordWrapMode(QTextOption.WrapAtWordBoundaryOrAnywhere)
        self.detail.setFrameShape(QFrame.NoFrame)
        _df = QFont("Microsoft YaHei UI", 9)
        self.detail.setFont(_df)
        self.detail.document().setDefaultFont(_df)
        rv.addWidget(self.detail, 1)
        return right

    def _build_opbar(self):
        self.op_bar = QFrame()
        self.op_bar.setObjectName("opbar")
        oh = QHBoxLayout(self.op_bar)
        oh.setContentsMargins(14, 7, 14, 7)
        oh.setSpacing(12)

        self.lbl_op = QLabel("处理方式")
        self.lbl_op.setObjectName("meta")
        oh.addWidget(self.lbl_op)

        self.op_group = QButtonGroup(self)
        self.op_group.setExclusive(True)
        self.op_btns = {}
        for key in bc.OP_ORDER:
            rb = QRadioButton(bc.OP_LABELS[key])
            self.op_btns[key] = rb
            self.op_group.addButton(rb)
            oh.addWidget(rb)

        self.lbl_op_hint = QLabel("")
        self.lbl_op_hint.setObjectName("hint")
        oh.addWidget(self.lbl_op_hint)
        oh.addStretch(1)

        self.btn_apply_one = QPushButton("立即执行此项")
        self.btn_apply_one.setObjectName("primary")
        self.btn_apply_one.setToolTip("立刻按所选方式处理（多选时处理全部选中项；执行前自动备份）")
        self.btn_apply_one.clicked.connect(self.on_apply_one)
        oh.addWidget(self.btn_apply_one)
        self.op_bar.setVisible(False)
        self.op_group.buttonClicked.connect(self.on_op_clicked)
        return self.op_bar

    # ---------------- 小工具 ----------------
    def _dot_icon(self, color):
        """等级前面的小圆点。按颜色缓存：一共就几种颜色，没必要每次重建。"""
        key = str(color)
        cache = getattr(self, "_dot_cache", None)
        if cache is None:
            cache = self._dot_cache = {}
        if key in cache:
            return cache[key]
        side = max(8, int(round(8 * self._dpr())))
        pm = QPixmap(side, side)
        pm.fill(Qt.transparent)
        p = QPainter(pm)
        p.setRenderHint(QPainter.Antialiasing)
        p.setBrush(QColor(color))
        p.setPen(Qt.NoPen)
        p.drawEllipse(0, 0, side, side)
        p.end()
        pm.setDevicePixelRatio(self._dpr())
        ic = QIcon(pm)
        cache[key] = ic
        return ic

    def _fit_columns(self):
        """按可用宽度分列：窄屏先收起「发布者」「签名」，保证项目/状态看得全。"""
        # 减去竖直滚动条与边框，避免列总宽恰好等于视口又冒出横向滚动条
        w = self.tree.viewport().width() - 18
        if w <= 80:
            return
        show_pub = w >= 720
        show_sig = w >= 560
        if self.tree.isColumnHidden(4) == show_pub:
            self.tree.setColumnHidden(4, not show_pub)
        if self.tree.isColumnHidden(5) == show_sig:
            self.tree.setColumnHidden(5, not show_sig)
        c1 = 44
        c5 = 78 if show_sig else 0
        c4 = (max(72, int(w * 0.12)) if show_pub else 0)
        fixed = c1 + c4 + c5
        rest = max(0, w - fixed)
        c0 = max(170, int(rest * 0.44))
        c2 = max(100, int(rest * 0.25))
        c3 = max(80, rest - c0 - c2)
        for i, val in ((0, c0), (2, c2), (3, c3)):
            if self.tree.columnWidth(i) != val:
                self.tree.setColumnWidth(i, val)
        for i, val in ((1, c1), (4, c4), (5, c5)):
            if val and self.tree.columnWidth(i) != val:
                self.tree.setColumnWidth(i, val)

    def resizeEvent(self, ev):
        _t0 = time.perf_counter() if _PROF_PATH else 0.0
        super().resizeEvent(ev)
        # 拖动 / 缩放过程中不重排列宽：每次改列宽都会让表头和表格重排一遍，
        # 60 次 resize 就是 60 次多余布局，帧间隔从 16ms 抖到 30ms+。
        # 松手时（WM_EXITSIZEMOVE）补一次即可。
        if not _GLASS_LOW:
            try:
                self._fit_columns()
            except Exception:
                pass
        if _PROF_PATH:
            _t1 = time.perf_counter()
            d = PROF
            d["resize"][0] += 1
            d["resize"][1] += _t1 - _t0
            d["resize"][2] = max(d["resize"][2], _t1 - _t0)

    def moveEvent(self, ev):
        super().moveEvent(ev)
        if _PROF_PATH:
            PROF.setdefault("move", [0, 0.0, 0.0])
            PROF["move"][0] += 1

    def _app_icon(self, path):
        """取程序图标。

        关键：这里必须返回**已经缩放好**的图标，不能直接把 QFileIconProvider 给的
        原始 QIcon 塞进表格。原始图标通常是 32x32 甚至 48x48，表格只要 16x16，
        于是每次重绘每一行都要做一次高质量缩放；高 DPI 下还要再乘 dpr。
        实测 28 行表格：直接塞原图 42ms/帧，预缩放后 15ms/帧，差 27ms。
        """
        if not path:
            return None
        key = str(path).lower()
        if key in self._icon_cache:
            return self._icon_cache[key]
        ic = None
        try:
            src = self._icon_provider.icon(QFileInfo(path))
            if src.isNull():
                ic = None
            else:
                # 按当前 DPI 预渲染到目标像素，绘制时直接 blit
                side = int(round(16 * self._dpr()))
                pm = src.pixmap(side, side)
                if pm.isNull():
                    ic = None
                else:
                    if pm.width() != side or pm.height() != side:
                        pm = pm.scaled(side, side, Qt.KeepAspectRatio,
                                       Qt.SmoothTransformation)
                    pm.setDevicePixelRatio(self._dpr())
                    ic = QIcon(pm)
        except Exception:
            ic = None
        self._icon_cache[key] = ic
        return ic

    def _app_of(self, f):
        if not f:
            return {}
        app = f.get("app")
        if isinstance(app, dict) and app.get("path"):
            return app
        fx = f.get("fix") or {}
        items = fx.get("items")
        if isinstance(items, list):
            for it in items:
                if isinstance(it, dict):
                    cand = it.get("exe") or it.get("cmd")
                    if cand:
                        app = bc.describe_app(cand, it.get("args", ""))
                        f["app"] = app
                        return app
        elif isinstance(items, dict):
            for n in list(items)[:1]:
                for s in (self._raw or {}).get("services", []):
                    if s.get("name") == n:
                        app = bc.describe_app(s.get("image", ""))
                        f["app"] = app
                        return app
        return {}

    def _sig_of(self, app):
        if not app or not app.get("path") or not app.get("exists"):
            return {"label": "", "state": "unknown", "detail": ""}
        return bc.app_signature(app)

    def _update_app_head(self, f):
        app = self._app_of(f) if f else {}
        if not app:
            self.app_head.setVisible(False)
            self._cur_app = {}
            return
        self._cur_app = app
        self.app_head_name.setText(bc.app_label(app))
        sig = self._sig_of(app)
        bits = [x for x in (app.get("company"), app.get("version")) if x]
        if not app.get("exists"):
            bits.insert(0, "文件不存在（卸载/改名后的残留）")
        # 公司名是文件自己填的，签名者才是证书上的名字；两边对不上时把真实签名者亮出来
        signer = (sig.get("signer") or "").strip()
        comp = (app.get("company") or "").strip().lower()
        mismatch = bool(signer and comp and signer.lower() not in comp
                        and comp not in signer.lower())
        if signer and (mismatch or not comp):
            bits.append("签名者：%s" % signer)
        self.app_head_meta.setText("　·　".join(bits) or (app.get("path") or ""))
        self.app_head_meta.setStyleSheet(
            "color:%s;" % (PAL["err"] if (not app.get("exists") or (
                mismatch and "microsoft" in comp and not bc._ms_ish(signer))) else PAL["faint"]))
        ic = self._app_icon(app.get("path") if app.get("exists") else "")
        if ic is not None:
            self.app_head_icon.setPixmap(ic.pixmap(32, 32))
        else:
            self.app_head_icon.clear()
        self.app_head_sig.setText(sig.get("label") or "")
        self.app_head_sig.setToolTip(sig.get("detail") or "")
        self.app_head_sig.setStyleSheet(
            "color:%s;" % {"valid": PAL["ok"], "catalog": PAL["info"],
                           "invalid": PAL["err"], "missing": PAL["err"]}.get(
                               sig.get("state"), PAL["faint"]))
        self.app_head.setToolTip(app.get("path") or "")
        self.app_head.setVisible(True)

    @guard
    def on_app_more(self):
        f = self._cur_finding()
        if f:
            self.show_app_detail(f)

    def _log(self, text):
        self.log_edit.appendPlainText("[%s] %s" % (time.strftime("%H:%M:%S"), text))

    # ---------------- 等待动画 ----------------
    # 体检 2~4 秒，期间界面只是几个静态字，看着像卡死。这里给一个「秒表 + 转圈 +
    # 不确定进度条」的组合：进度条走 Qt 自带的 busy 动画，文字每 120ms 转一格。
    _SPIN = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def _start_busy_anim(self, status=None):
        self._busy_t0 = time.perf_counter()
        self._busy_step = (status or "处理中").rstrip("… ").strip() or "处理中"
        self._busy_frame = 0
        self.bar.setRange(0, 0)              # 0/0 = 不确定进度，Qt 自己会动
        t = getattr(self, "_busy_timer", None)
        if t is None:
            t = QTimer(self)
            t.setInterval(120)
            t.timeout.connect(self._tick_busy)
            self._busy_timer = t
        t.start()
        self._tick_busy()

    def _tick_busy(self):
        t = getattr(self, "_busy_timer", None)
        if t is None or not t.isActive():
            return
        f = self._SPIN[self._busy_frame % len(self._SPIN)]
        self._busy_frame += 1
        dt = time.perf_counter() - getattr(self, "_busy_t0", time.perf_counter())
        self.lbl_status.setText("%s %s  %.1fs" % (f, self._busy_step, dt))

    def _stop_busy_anim(self):
        t = getattr(self, "_busy_timer", None)
        if t is not None:
            t.stop()
        try:
            self._busy_elapsed = time.perf_counter() - getattr(self, "_busy_t0", time.perf_counter())
        except Exception:
            self._busy_elapsed = 0.0
        self.bar.setRange(0, 100)             # 交还给评分条，具体值由调用方设置
        self.lbl_status.setText("就绪")

    def _set_busy(self, busy, status=None):
        for b in (self.btn_scan, self.btn_apply, self.btn_restore, self.btn_export,
                  self.btn_apply_one, self.btn_ai, self.btn_settings, self.cb_delay):
            b.setEnabled(not busy)
        self.btn_log.setEnabled(True)
        if status is not None:
            self.statusBar().showMessage(status)
        if busy:
            self._start_busy_anim(status)
        else:
            self._stop_busy_anim()
        self._refresh_apply_state()

    def _update_admin_badge(self):
        if bc.is_admin():
            self.lbl_admin.setText("管理员")
            self.lbl_admin.setObjectName("adminOk")
            self.btn_elevate.hide()
        else:
            self.lbl_admin.setText("普通权限")
            self.lbl_admin.setObjectName("adminNo")
            self.btn_elevate.show()
        self.lbl_admin.style().unpolish(self.lbl_admin)
        self.lbl_admin.style().polish(self.lbl_admin)
        self._refresh_backup_badge()

    def _refresh_backup_badge(self):
        try:
            n = len(bc.list_backups())
        except Exception:
            n = 0
        self.lbl_bk.setText("备份 %d 个" % n if n else "无备份")

    def _show_welcome(self):
        self.app_head.setVisible(False)
        self._cur_app = {}
        p = PAL
        self.detail.setHtml(
            "<div style='font-family:\"Microsoft YaHei UI\";font-size:13px;color:%(text)s'>"
            "<div style='font-size:15px;font-weight:600;margin-bottom:6px'>怎么用</div>"
            "<table cellspacing='0' cellpadding='4' style='font-size:12px;color:%(text)s'>"
            "<tr><td style='color:%(accent)s;font-weight:600;width:76px'>1 体检</td>"
            "<td>扫描开机耗时、快速启动、自启项、服务残留、开机报错。</td></tr>"
            "<tr><td style='color:%(accent)s;font-weight:600'>2 处理</td>"
            "<td>每行就是一个开机启动对象，「应用」列告诉你它属于哪个软件，「签名」列告诉你"
            "这个程序有没有被改过。选中行后在底部选「延迟启动 / 禁止启动 / 彻底删除」，"
            "或按住 Ctrl 多选、勾选多行后一次改完。</td></tr>"
            "<tr><td style='color:%(accent)s;font-weight:600'>3 执行</td>"
            "<td>点「智能优化」执行勾选项，执行前自动备份，随时可「还原」。</td></tr>"
            "<tr><td style='color:%(accent)s;font-weight:600'>4 拿不准</td>"
            "<td>点「AI 判断」，逐项说明这是什么程序、开机要不要留。接口在「设置 → AI 接口」。</td></tr>"
            "</table>"
            "<div style='margin-top:12px;color:%(muted)s;font-size:11px'>"
            "所有修复只改系统启动配置（服务启动类型、自启标记、计划任务），"
            "不删除任何软件与文件，全部可还原。</div></div>"
            % p)

    # ---------------- 扫描 ----------------
    @guard
    def on_scan(self):
        self.start_scan()

    @guard
    def on_delay_changed(self, _idx):
        sec = self.cb_delay.currentData()
        if not sec:
            return
        bc.set_delay_seconds(int(sec))
        txt = bc.delay_text()
        self._log("延迟时长改为 %s" % txt)
        self.lbl_status.setText("延迟 %s" % txt)
        self.statusBar().showMessage("延迟时长已设为 %s（下次创建 / 修改延迟任务时生效）" % txt, 6000)
        if self._raw is None:
            return
        keep = set(f.get("id") for f in self._checked_findings() if f.get("id"))
        try:
            self.result = bc.analyze(self._raw)
            self._fill_tree(self.result, keep=keep)
        except Exception:
            self._log("重算失败：%s" % traceback.format_exc().strip().splitlines()[-1])

    def start_scan(self):
        if self.scan_worker and self.scan_worker.isRunning():
            return
        self._set_busy(True, "正在体检 …")
        self._log("开始体检")
        self.scan_worker = ScanWorker(self)
        self.scan_worker.sig_progress.connect(self.on_progress)
        self.scan_worker.sig_done.connect(self.on_scan_done)
        self.scan_worker.sig_fail.connect(self.on_worker_fail)
        self.scan_worker.start()

    def _scan_busy(self):
        return bool(self.scan_worker and self.scan_worker.isRunning())

    @guard
    def _show_cached_then_scan(self):
        """打开程序：先把上次的体检结果摆出来（毫秒级），再在后台重新体检。"""
        shown = False
        if bc.get_setting("show_last_scan", True):
            shown = self._load_cached()
        QTimer.singleShot(80 if shown else 400, self.start_scan)

    def _load_cached(self):
        raw, saved = bc.load_last_scan()
        if not raw:
            return False
        try:
            res = bc.analyze(raw)            # 用当前版本的规则重新分析，不会显示过时的判断
        except Exception:
            bc.log_line("cached analyze failed:\n" + traceback.format_exc())
            return False
        self.on_scan_done(raw, res, cached=max(1.0, time.time() - saved))
        return True

    @guard
    def on_progress(self, text):
        # 去掉尾巴的省略号，交给动画统一加「转圈 + 已用时」
        self._busy_step = (text or "").replace("…", "").replace("...", "").strip() or "处理中"
        self.lbl_status.setText(self._busy_step)
        self.statusBar().showMessage(text)

    @guard
    def on_scan_done(self, raw, res, cached=0.0):
        """cached>0：这是上次的缓存结果（值是已过去的秒数），先显示，后台还在刷新。"""
        keep = None
        if self._stale and not cached and self.result:
            # 缓存 → 新结果：保留用户已经勾的项；新出现的、默认该勾的也勾上
            old_ids = {f.get("id") for f in self.result.get("findings", [])}
            keep = {f.get("id") for f in self._checked_findings() if f.get("id")}
            keep |= {f.get("id") for f in res.get("findings", [])
                     if f.get("default") and f.get("id") not in old_ids}
        self._raw = raw
        self.result = res
        self._fill_tree(res, keep=keep)
        met = res.get("metrics", {})
        score = res.get("score")
        self.lbl_score.setText(str(score))
        gc = {"优秀": PAL["ok"], "良好": PAL["info"],
              "一般": PAL["warn"], "较差": PAL["err"]}.get(res.get("grade"), PAL["text"])
        self.lbl_score.setStyleSheet("color:%s;" % gc)
        self.lbl_grade.setText(res.get("grade") or "")
        self.lbl_grade.setStyleSheet("color:%s;" % gc)
        if cached:
            self._stale = True
            self.lbl_status.setText("上次体检 %s" % bc.age_text(cached))
            self.statusBar().showMessage("显示的是上次体检的结果（%s），正在后台刷新 …" % bc.age_text(cached))
        else:
            self._stale = False
            # 先退出忙碌态（把进度条范围还给评分条），再填分数，否则会被重置成 0
            self._set_busy(False, "体检完成 %s" % res.get("meta", {}).get("scanned_at", ""))
            took = getattr(self, "_busy_elapsed", 0.0)
            self.lbl_status.setText("体检完成 %.1fs" % took if took else "体检完成")
            bc.save_last_scan(raw)
        self.bar.setValue(int(score or 0))
        self.bar.setStyleSheet("QProgressBar::chunk{background:%s;}" % gc)
        # 摘要要说清「勾了没有」：否则按钮是“智能优化（0）”，看着像坏了
        n_chk = len(self._checked_findings())
        summary = res.get("summary", "")
        if n_chk:
            summary += "；已默认勾选 %d 项，可直接执行" % n_chk
        else:
            summary += "；当前未勾选，选中行后在底部选择处理方式"
        if cached:
            summary = "（上次体检结果，刷新中）" + summary
        self.lbl_summary.setText(summary)
        parts = []
        if met.get("last_boot_s") is not None:
            parts.append("上次开机 %s 秒" % met["last_boot_s"])
        parts.append("快速启动 %s" % ("已开" if met.get("fast_startup_on") else "未开"))
        parts.append("自启项 %s" % met.get("startup_enabled"))
        parts.append("自动服务 %s" % met.get("svc_auto"))
        self.lbl_meta.setText("　·　".join(str(x) for x in parts))
        self._log(("显示上次体检结果（%s）：%s" % (bc.age_text(cached), res.get("summary", ""))) if cached
                  else "体检完成：%s" % res.get("summary", ""))
        self._sync_nav_badges()
        for f in res.get("findings", []):
            self._log("  [%s] %s" % (bc.SEV_CN.get(f["sev"], "?"), f["title"]))

    @guard
    def on_worker_fail(self, err):
        self._set_busy(False, "出错了")
        bc.log_line("worker failed:\n" + err)
        QMessageBox.critical(self, "出错了", err[-1600:])

    # ---------------- 结果树 ----------------
    def _fill_tree(self, res, keep=None):
        """keep=None 用默认勾选；传 set 时按其中的 finding id 恢复勾选。"""
        self._filling = True
        try:
            self.tree.clear()
            cats = {}
            for f in res.get("findings", []):
                cats.setdefault(f["cat"], []).append(f)
            for cat in bc.CAT_ORDER:
                if cat not in cats:
                    continue
                parent = QTreeWidgetItem(["%s（%d）" % (cat, len(cats[cat])), "", "", "", "", ""])
                fnt = parent.font(0)
                fnt.setBold(True)
                parent.setFont(0, fnt)
                parent.setForeground(0, QColor(PAL["muted"]))
                for _c in range(self.tree.columnCount()):
                    parent.setBackground(_c, QColor(PAL["head"]))
                self.tree.addTopLevelItem(parent)
                for f in cats[cat]:
                    if f.get("opts"):
                        bc.apply_op(f, self._ops.get(f.get("id"), f.get("op")))
                    app = f.get("app") or {}
                    label = bc.app_label(app)
                    ai = f.get("ai") or {}
                    if ai:
                        status = "AI %s · %s" % (
                            bc.AI_VERDICT_CN.get(ai.get("verdict"), "").replace("建议", ""),
                            ai.get("reason") or "")
                    else:
                        status = f.get("short") or ""
                    sig = self._sig_of(app) if app else {"label": ""}
                    it = QTreeWidgetItem([f["title"], bc.SEV_CN.get(f["sev"], "?"), label,
                                          status, app.get("company") or "",
                                          sig.get("label") or ""])
                    it.setData(0, Qt.UserRole, f.get("idx"))
                    it.setToolTip(0, f.get("title", ""))
                    if label:
                        tip = bc.app_detail_text(app)
                        if sig.get("detail"):
                            tip += "\n签名：%s\n%s" % (sig.get("label"), sig.get("detail"))
                        it.setToolTip(2, tip)
                        if app.get("exists"):
                            ic = self._app_icon(app.get("path"))
                            if ic is not None:
                                it.setIcon(2, ic)
                        else:
                            it.setForeground(2, QColor(PAL["err"]))
                    if f.get("src"):
                        it.setToolTip(5, "来源：%s" % f.get("src"))
                    it.setToolTip(3, f.get("short") or "")
                    if ai:
                        it.setForeground(3, QColor(bc.AI_VERDICT_COLOR.get(ai.get("verdict"),
                                                                          PAL["text"])))
                        it.setToolTip(3, "%s\n%s" % (ai.get("reason") or "", f.get("short") or ""))
                    it.setForeground(1, QColor(sev_color(f["sev"])))
                    if f["sev"] == "high":
                        it.setIcon(1, self._dot_icon(sev_color("high")))
                    it.setForeground(4, QColor(PAL["muted"]))
                    if sig.get("label"):
                        it.setForeground(5, QColor({"valid": PAL["ok"], "catalog": PAL["info"],
                                                    "invalid": PAL["err"],
                                                    "missing": PAL["err"]}.get(
                                                        sig.get("state"), PAL["faint"])))
                    if f.get("fix"):
                        it.setFlags(it.flags() | Qt.ItemIsUserCheckable)
                        if keep is None:
                            checked = bool(f.get("default"))
                        else:
                            checked = f.get("id") in keep
                        it.setCheckState(0, Qt.Checked if checked else Qt.Unchecked)
                    parent.addChild(it)
                parent.setExpanded(True)
        finally:
            self._filling = False
        if self._sort_col >= 0:
            self._sort_tree(self._sort_col, self._sort_desc, remember=False)
        self._apply_view()
        self._refresh_apply_state()
        QTimer.singleShot(0, self._fit_columns)
        # 滚动条出现/消失会改变视口宽度，稍后再校准一次
        QTimer.singleShot(120, self._fit_columns)

    # ---------------- 过滤 / 排序 ----------------
    def _row_matches(self, ch, f, kw, cat, third):
        if kw:
            hay = " ".join([ch.text(0), ch.text(2), ch.text(3), ch.text(4)]).lower()
            if kw not in hay:
                return False
        if cat == MODE_TODO:
            if (f or {}).get("sev") not in ("high", "mid"):
                return False
        elif cat not in (MODE_ALL, None, ""):
            if (f or {}).get("cat") != cat:
                return False
        if third:
            app = (f or {}).get("app") or {}
            if bc.is_microsoft(app):
                return False
        return True

    def _apply_view(self):
        if not hasattr(self, "tree"):
            return
        kw = self.ed_search.text().strip().lower()
        cat = self.cb_cat.currentData() or MODE_ALL
        third = self.chk_third.isChecked()
        shown_total = 0
        for i in range(self.tree.topLevelItemCount()):
            p = self.tree.topLevelItem(i)
            shown = 0
            for j in range(p.childCount()):
                ch = p.child(j)
                f = self._finding_of_item(ch)
                ok = self._row_matches(ch, f, kw, cat, third)
                ch.setHidden(not ok)
                if ok:
                    shown += 1
            total = p.childCount()
            head = p.text(0).split("（")[0]
            p.setText(0, "%s（%d）" % (head, total) if shown == total
                      else "%s（%d / %d）" % (head, shown, total))
            p.setHidden(shown == 0)
            if kw and shown:
                p.setExpanded(True)
            shown_total += shown
        filtering = bool(kw) or cat != MODE_ALL or third
        if hasattr(self, "lbl_count"):
            self.lbl_count.setText(("显示 %d 项" % shown_total) if filtering else "")

    @guard
    def focus_search(self):
        self.ed_search.setFocus()
        self.ed_search.selectAll()

    @guard
    def on_header_click(self, col):
        desc = (self._sort_col == col) and not self._sort_desc
        self._sort_tree(col, desc)

    def _sort_tree(self, col, desc=False, remember=True):
        if remember:
            self._sort_col, self._sort_desc = col, desc
        # 表格里显示的是中文等级（高/中/低/提示），排序要按严重度而不是拼音
        cn2rank = {cn: {"high": 0, "mid": 1, "low": 2, "info": 3}[k]
                   for k, cn in bc.SEV_CN.items()}
        sig_rank = {"签名无效": 0, "未签名": 1, "目录签名": 2, "已签名": 3}
        self._filling = True
        try:
            for i in range(self.tree.topLevelItemCount()):
                p = self.tree.topLevelItem(i)
                kids = [p.child(j) for j in range(p.childCount())]
                if col == 1:
                    kids.sort(key=lambda it: cn2rank.get(it.text(1), 9), reverse=desc)
                elif col == 5:
                    kids.sort(key=lambda it: sig_rank.get(it.text(5), 9), reverse=desc)
                else:
                    kids.sort(key=lambda it: (it.text(col) or "").lower(), reverse=desc)
                p.takeChildren()
                for it in kids:
                    p.addChild(it)
                p.setExpanded(True)
        finally:
            self._filling = False

    def _finding_by_idx(self, idx):
        if not self.result:
            return None
        for f in self.result.get("findings", []):
            if f.get("idx") == idx:
                return f
        return None

    def _checked_findings(self):
        out = []
        for i in range(self.tree.topLevelItemCount()):
            parent = self.tree.topLevelItem(i)
            for j in range(parent.childCount()):
                ch = parent.child(j)
                if ch.checkState(0) == Qt.Checked:
                    f = self._finding_by_idx(ch.data(0, Qt.UserRole))
                    if f and f.get("fix"):
                        out.append(f)
        return out

    @guard
    def on_item_changed(self, item, _col):
        if self._filling:
            return
        self._refresh_apply_state()
        self._sync_op_bar()

    def _refresh_apply_state(self):
        n = len(self._checked_findings())
        self.btn_apply.setText("智能优化（%d）" % n)
        busy = bool(self.scan_worker and self.scan_worker.isRunning()) or \
               bool(self.fix_worker and self.fix_worker.isRunning())
        self.btn_apply.setEnabled(n > 0 and not busy)

    def _cur_finding(self):
        return self._finding_of_item(self.tree.currentItem())

    # ---------------- 选中项（支持多选，一次性处理） ----------------
    def _sel_items(self):
        return [it for it in self.tree.selectedItems()
                if it.data(0, Qt.UserRole) is not None]

    def _sel_findings(self):
        out = []
        for it in self._sel_items():
            f = self._finding_by_idx(it.data(0, Qt.UserRole))
            if f:
                out.append(f)
        return out

    @staticmethod
    def _op_counts(fs):
        return {k: sum(1 for f in fs if (f.get("opts") or {}).get(k)) for k in bc.OP_ORDER}

    def _items_of_findings(self, fs):
        want = {f.get("idx") for f in fs}
        out = {}
        for i in range(self.tree.topLevelItemCount()):
            p = self.tree.topLevelItem(i)
            for j in range(p.childCount()):
                ch = p.child(j)
                k = ch.data(0, Qt.UserRole)
                if k in want:
                    out[k] = ch
        return out

    def _refresh_row(self, it, f):
        if it is None or not f:
            return
        it.setText(0, f["title"])
        it.setText(3, f.get("short") or "")
        it.setToolTip(0, f["title"])
        it.setToolTip(3, f.get("short") or "")

    @guard
    def on_sel_changed(self):
        self._sync_op_bar()

    def _op_targets(self):
        """优先级：多行选中 > 已勾选（当前行在其中）> 当前一行。"""
        sel = self._sel_findings()
        if len(sel) > 1:
            return sel, "sel"
        cur = self._cur_finding()
        checked = self._checked_findings()
        if cur is not None and len(checked) >= 2 and \
                any(f.get("id") == cur.get("id") for f in checked):
            return checked, "checked"
        if sel:
            return sel, "cur"
        return ([cur] if cur else []), "cur"

    def _sync_op_bar(self):
        fs, mode = self._op_targets()
        if not fs:
            self.op_bar.setVisible(False)
            return
        counts = self._op_counts(fs)
        fixable = [f for f in fs if f.get("fix")]
        multi = len(fs) > 1
        visible = any(counts.values()) or bool(fixable)
        self.op_bar.setVisible(visible)
        if not visible:
            return
        if multi:
            self.lbl_op.setText("处理方式（%s %d 项）"
                                % ("已勾选" if mode == "checked" else "已选", len(fs)))
        else:
            self.lbl_op.setText("处理方式")
        for k, rb in self.op_btns.items():
            n = counts[k]
            rb.setVisible(n > 0)
            rb.setEnabled(n > 0)
            rb.setText(("%s（%d）" % (bc.OP_LABELS[k], n)) if (multi and n) else bc.OP_LABELS[k])
        if multi:
            ops = {f.get("op") for f in fs if f.get("opts")}
            common = ops.pop() if len(ops) == 1 else None
        else:
            common = fs[0].get("op")
        self.op_group.setExclusive(False)
        for k, rb in self.op_btns.items():
            rb.setChecked(common == k and counts[k] > 0)
        self.op_group.setExclusive(True)
        if multi:
            self.lbl_op_hint.setText("点一下 = 应用到全部")
        else:
            self.lbl_op_hint.setText("当前：%s" % bc.OP_LABELS.get(common, "")
                                     if common else "该项只有一种处理方式")
        self.btn_apply_one.setVisible(bool(fixable))
        self.btn_apply_one.setEnabled(bool(fixable))
        self.btn_apply_one.setText(
            ("立即执行%s %d 项" % ("勾选的" if mode == "checked" else "选中的", len(fixable)))
            if multi else "立即执行此项")

    @guard
    def on_cur_changed(self, cur, _prev):
        f = self._finding_of_item(cur)
        self._update_app_head(f)
        self._sync_op_bar()
        if f:
            self.detail.setHtml(self._finding_html(f))
        elif cur is not None and cur.data(0, Qt.UserRole) is None:
            n = sum(1 for i in range(cur.childCount())
                    if cur.child(i).flags() & Qt.ItemIsUserCheckable)
            self.detail.setHtml(
                "<div style='font-family:\"Microsoft YaHei UI\";color:%(text)s'>"
                "<div style='font-size:14px;font-weight:600'>%(name)s</div>"
                "<div style='margin-top:8px;color:%(muted)s;font-size:12px;line-height:1.8'>"
                "共 %(n)d 项可处理。按住 <b>Ctrl</b> 点选或 <b>Shift</b> 连选多行，"
                "在底部选一次处理方式即可全部改掉；也可以直接勾选多行后点「智能优化」。</div></div>"
                % {"text": PAL["text"], "muted": PAL["muted"], "n": n,
                   "name": html.escape(cur.text(0))})

    @guard
    def on_op_clicked(self, btn):
        key = next((k for k, b in self.op_btns.items() if b is btn), None)
        if key:
            self._apply_op_to(self._op_targets()[0], key)

    @guard
    def _apply_op_to(self, fs, key):
        fs = [f for f in (fs or []) if f]
        if not fs or not key:
            return
        targets = [f for f in fs if (f.get("opts") or {}).get(key) and f.get("fix")]
        if not targets:
            return
        skipped = len(fs) - len(targets)
        items = self._items_of_findings(targets)
        self._filling = True
        try:
            for f in targets:
                bc.apply_op(f, key)
                self._ops[f.get("id")] = key
                it = items.get(f.get("idx"))
                self._refresh_row(it, f)
                if len(targets) > 1 and it is not None and (it.flags() & Qt.ItemIsUserCheckable):
                    it.setCheckState(0, Qt.Checked)
        finally:
            self._filling = False
        self._refresh_apply_state()
        self._sync_op_bar()
        f0 = self._cur_finding()
        if f0 in targets:
            self.detail.setHtml(self._finding_html(f0))
        if len(targets) == 1:
            self._log("处理方式 -> %s：%s" % (bc.OP_LABELS[key], targets[0].get("title")))
        else:
            self._log("处理方式 -> %s：%d 项（已自动勾选，可点「智能优化」执行）"
                      % (bc.OP_LABELS[key], len(targets)))
            for f in targets:
                self._log("    · %s" % f.get("title"))
        if skipped:
            self._log("    另有 %d 项不支持「%s」，已跳过" % (skipped, bc.OP_LABELS[key]))

    # ---------------- 右键菜单 ----------------
    def _finding_of_item(self, it):
        if it is None:
            return None
        idx = it.data(0, Qt.UserRole)
        if idx is None:
            return None
        return self._finding_by_idx(idx)

    @guard
    def on_tree_menu(self, pos):
        it = self.tree.itemAt(pos)
        if it is None:
            return
        f = self._finding_of_item(it)
        m = QMenu(self)
        if f is None:
            m.addAction("全部勾选", lambda: self._check_children(it, True))
            m.addAction("全部取消", lambda: self._check_children(it, False))
            m.addSeparator()
            m.addAction("选中该分类全部条目", lambda: self._select_children(it))
            m.exec_(self.tree.viewport().mapToGlobal(pos))
            return

        if it.isSelected():
            sel = self._sel_findings()
        else:
            sel = []
        if len(sel) > 1:
            counts = self._op_counts(sel)
            head = m.addMenu("选中的 %d 项一起设为" % len(sel))
            for k in bc.OP_ORDER:
                if not counts[k]:
                    continue
                act = head.addAction("%s（%d 项）" % (bc.OP_LABELS[k], counts[k]))
                act.triggered.connect(lambda _c=False, kk=k: self._apply_op_to(sel, kk))
            head.addSeparator()
            act = head.addAction("勾选这 %d 项（参与批量）" % len(sel))
            act.triggered.connect(lambda: self._check_items(self._sel_items(), True))
            act = head.addAction("取消勾选这 %d 项" % len(sel))
            act.triggered.connect(lambda: self._check_items(self._sel_items(), False))
            head.addSeparator()
            act = head.addAction("立即执行这 %d 项…" % len([x for x in sel if x.get("fix")]))
            act.triggered.connect(lambda: self._run_findings(sel))
            m.addSeparator()

        # 流氓软件 / 全家桶：把卸载入口放最前面，这是用户最想点的
        uninst = f.get("uninstall_cmd") or ""
        if uninst or f.get("adware_group"):
            m.addSeparator()
            if uninst:
                a_un = m.addAction("运行官方卸载程序…")
                a_un.triggered.connect(lambda: self.on_uninstall(f))
            a_sel = m.addAction("在「已安装程序」里定位…")
            a_sel.triggered.connect(lambda: self.on_show_installed(f))
            if f.get("adware_group"):
                a_grp = m.addAction("复制该软件全部组件名")
                a_grp.triggered.connect(lambda: self._copy_text(
                    "\n".join(f.get("adware_group") or []), "组件清单"))
            m.addSeparator()

        app = self._app_of(f)
        a_info = m.addAction("查看这是哪个应用…")
        a_info.triggered.connect(lambda: self.show_app_detail(f))
        a_info.setEnabled(bool(app))
        a_open = m.addAction("打开文件所在位置")
        a_open.triggered.connect(lambda: self._open_containing(app))
        a_open.setEnabled(bool(app.get("exists")))
        a_prop = m.addAction("文件属性…")
        a_prop.triggered.connect(lambda: self._show_file_props(app))
        a_prop.setEnabled(bool(app.get("exists")))
        a_sig = m.addAction("查看数字签名")
        a_sig.triggered.connect(lambda: self.show_signature(app))
        a_sig.setEnabled(bool(app.get("exists")))
        a_copy = m.addAction("复制文件路径")
        a_copy.triggered.connect(lambda: self._copy_text(app.get("path") or "", "文件路径"))
        a_copy.setEnabled(bool(app.get("path")))
        a_cmd = m.addAction("复制启动命令")
        a_cmd.triggered.connect(lambda: self._copy_text(app.get("cmd") or "", "启动命令"))
        a_cmd.setEnabled(bool(app.get("cmd")))
        a_row = m.addAction("复制整行（制表符分隔）")
        a_row.triggered.connect(lambda: self._copy_text(
            "\t".join(it.text(i) for i in range(self.tree.columnCount())), "整行"))
        a_ai = m.addAction("问 AI：这程序能关吗？")
        a_ai.triggered.connect(lambda: self._ai_one(f))
        a_ai.setEnabled(bool(app) or bool(f.get("fix")))

        opts = f.get("opts") or {}
        if opts or f.get("fix"):
            m.addSeparator()
        if opts:
            sub = m.addMenu("立即切换为")
            for k in bc.OP_ORDER:
                if k not in opts:
                    continue
                act = sub.addAction(("● " if f.get("op") == k else "　") + bc.OP_LABELS[k])
                act.triggered.connect(lambda _c=False, kk=k: self._run_single(f, kk))
            sub.setToolTipsVisible(True)
        else:
            act = m.addAction("立即执行本项")
            act.triggered.connect(lambda: self._run_single(f, None))

        if f.get("fix"):
            m.addSeparator()
            checked = it.checkState(0) == Qt.Checked
            act = m.addAction("取消勾选（不参与批量）" if checked else "勾选此项（参与批量）")
            act.triggered.connect(lambda: self._toggle_check(it))
        if it.parent() is not None:
            act = m.addAction("收起该分类")
            act.triggered.connect(lambda: self._toggle_parent(it))
        m.exec_(self.tree.viewport().mapToGlobal(pos))

    def _check_all(self, on):
        self._filling = True
        try:
            for i in range(self.tree.topLevelItemCount()):
                p = self.tree.topLevelItem(i)
                for j in range(p.childCount()):
                    ch = p.child(j)
                    if ch.flags() & Qt.ItemIsUserCheckable:
                        ch.setCheckState(0, Qt.Checked if on else Qt.Unchecked)
        finally:
            self._filling = False
        self._refresh_apply_state()
        self._sync_op_bar()

    def _check_children(self, parent, on):
        self._filling = True
        try:
            for i in range(parent.childCount()):
                ch = parent.child(i)
                if ch.flags() & Qt.ItemIsUserCheckable:
                    ch.setCheckState(0, Qt.Checked if on else Qt.Unchecked)
        finally:
            self._filling = False
        self._refresh_apply_state()
        self._sync_op_bar()

    def _check_items(self, items, on):
        self._filling = True
        try:
            for it in items or []:
                if it.flags() & Qt.ItemIsUserCheckable:
                    it.setCheckState(0, Qt.Checked if on else Qt.Unchecked)
        finally:
            self._filling = False
        self._refresh_apply_state()
        self._sync_op_bar()

    def _select_children(self, parent):
        if parent.childCount():
            self.tree.setCurrentItem(parent.child(0))
        self.tree.clearSelection()
        for i in range(parent.childCount()):
            parent.child(i).setSelected(True)

    def _toggle_check(self, it):
        if not (it.flags() & Qt.ItemIsUserCheckable):
            return
        it.setCheckState(0, Qt.Unchecked if it.checkState(0) == Qt.Checked else Qt.Checked)

    def _toggle_parent(self, it):
        p = it.parent() or it
        p.setExpanded(not p.isExpanded())

    @guard
    def on_tree_dblclick(self, it, col):
        if col == 2:
            f = self._finding_of_item(it)
            if f:
                self.show_app_detail(f)

    @guard
    def _open_containing(self, app):
        p = (app or {}).get("path") or ""
        if not p or not os.path.isfile(p):
            QMessageBox.information(self, "打开位置", "文件不存在，无法定位。\n%s" % p)
            return
        p = os.path.normpath(p)
        try:
            subprocess.Popen(["explorer.exe", "/select,", p])
        except Exception as e:
            QMessageBox.warning(self, "打开位置", str(e))

    @guard
    def _show_file_props(self, app):
        p = (app or {}).get("path") or ""
        if not p or not os.path.isfile(p):
            return
        p = os.path.normpath(p)
        try:
            ctypes.windll.shell32.ShellExecuteW(
                None, "properties", p, None, os.path.dirname(p), 1)
        except Exception as e:
            QMessageBox.warning(self, "文件属性", str(e))

    def _copy_text(self, text, what):
        if not text:
            return
        QApplication.clipboard().setText(text)
        self.statusBar().showMessage("已复制%s" % what, 4000)

    # ---------------- 流氓软件：卸载 ----------------
    @guard
    def on_uninstall(self, f):
        """运行官方卸载程序。不自己删任何东西，把控制权交给系统卸载器。"""
        cmd = f.get("uninstall_cmd") or ""
        if not cmd:
            QMessageBox.information(self, "没有卸载入口",
                                    "这一项没找到对应的卸载程序。\n"
                                    "可能是绿色版 / 已被卸载残留，可以直接禁止启动。")
            return
        names = [n for n in (f.get("adware_group") or []) if n]
        body = "即将启动官方卸载程序：\n\n%s\n\n" % cmd
        if names:
            body += "涉及的组件：\n" + "\n".join("  · " + n for n in names[:8])
            if len(names) > 8:
                body += "\n  … 共 %d 个" % len(names)
            body += "\n\n"
        body += ("卸载过程由软件自己的卸载器负责，本工具不参与删除。\n"
                 "卸载完建议回来重新体检，清理残留的启动项与服务。")
        r = QMessageBox.question(self, "确认运行卸载程序", body,
                                 QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if r != QMessageBox.Yes:
            return
        try:
            # 用 ShellExecute 走系统关联，UAC 提权由系统处理
            os.startfile(cmd)
            self._log("启动卸载程序：%s" % cmd)
            self.statusBar().showMessage("已启动卸载程序，请按提示操作", 8000)
        except Exception:
            # startfile 处理不了带参数的命令行（msiexec /x {GUID}、带 /S 的安装器）。
            # 这里自己拆成 argv 直接起进程，不能用 shell=True —— UninstallString 是
            # 第三方软件写的字符串，交给 cmd.exe 解析就是白送一个注入面。
            try:
                argv = bc.cmd_argv(cmd)
                if not argv:
                    raise ValueError("无法解析卸载命令：%s" % cmd)
                subprocess.Popen(argv, close_fds=True)
                self._log("启动卸载程序(argv)：%s" % (argv,))
                self.statusBar().showMessage("已启动卸载程序，请按提示操作", 8000)
            except Exception as e:
                QMessageBox.warning(self, "启动失败",
                                    "无法启动卸载程序：\n%s\n\n"
                                    "可以手动到「设置 → 应用」里卸载。" % e)

    @guard
    def on_show_installed(self, f):
        """列出该软件在「已安装程序」里的条目，方便用户去系统设置里卸载。"""
        names = set(n.lower() for n in (f.get("adware_group") or []) if n)
        try:
            rows = bc._enum_uninstall()
        except Exception:
            rows = []
        hit = []
        for disp, pub, uninst, loc in rows:
            d = (disp or "").lower()
            if d in names or any(n and (n in d or d in n) for n in names):
                hit.append((disp, pub, uninst))
        if not hit:
            QMessageBox.information(self, "未找到",
                                    "「已安装程序」里没有匹配的条目，可能是绿色版。")
            return
        lines = []
        for disp, pub, uninst in hit:
            lines.append("· %s" % disp)
            if pub:
                lines.append("    发布者：%s" % pub)
            if uninst:
                lines.append("    卸载：%s" % uninst[:110])
        QMessageBox.information(
            self, "已安装程序",
            "在系统里找到这些条目：\n\n%s\n\n"
            "推荐走「设置 → 应用 → 已安装的应用」卸载，比直接跑卸载器更干净。"
            % "\n".join(lines))

    def show_signature(self, app):
        sig = self._sig_of(app)
        if not sig or not sig.get("label"):
            QMessageBox.information(self, "数字签名", "这一项没有可校验的可执行文件。")
            return
        QMessageBox.information(self, "数字签名 · %s" % bc.app_label(app),
                                "%s\n\n%s\n\n文件：\n%s"
                                % (sig.get("label"), sig.get("detail") or "",
                                   app.get("path") or ""))

    @guard
    def show_app_detail(self, f):
        app = self._app_of(f)
        if not app:
            QMessageBox.information(self, "应用详情",
                                    "这一项没有可识别的可执行文件（通常是汇总提示项）。")
            return
        dlg = QDialog(self)
        dlg.setWindowTitle("这是哪个应用")
        dlg.resize(720, 460)
        v = QVBoxLayout(dlg)
        v.setContentsMargins(16, 14, 16, 12)
        v.setSpacing(10)

        head = QHBoxLayout()
        head.setSpacing(12)
        ic = self._app_icon(app.get("path") if app.get("exists") else "")
        pic = QLabel()
        if ic is not None:
            pic.setPixmap(ic.pixmap(44, 44))
        else:
            pic.setFixedSize(44, 44)
        head.addWidget(pic, 0, Qt.AlignTop)
        col = QVBoxLayout()
        col.setSpacing(2)
        lbl_name = QLabel(bc.app_label(app))
        lbl_name.setStyleSheet("font-size:15px;font-weight:600;")
        lbl_name.setWordWrap(True)
        col.addWidget(lbl_name)
        sig = self._sig_of(app)
        meta = "　·　".join(x for x in (app.get("company") or "未知公司",
                                       app.get("version") or "",
                                       sig.get("label") or "") if x)
        lbl_meta = QLabel(meta)
        lbl_meta.setStyleSheet("color:%s;font-size:11px;" % PAL["faint"])
        lbl_meta.setWordWrap(True)
        col.addWidget(lbl_meta)
        head.addLayout(col, 1)
        v.addLayout(head)

        def row(k, val):
            if not val:
                return ""
            return ("<tr><td style='color:%s;padding:4px 14px 4px 0;"
                    "white-space:nowrap;vertical-align:top'>%s</td>"
                    "<td style='padding:4px 0;word-break:break-all'>%s</td></tr>"
                    % (PAL["faint"], html.escape(k), html.escape(val)))

        rows = "".join([
            row("文件路径", app.get("path")),
            row("启动命令", app.get("cmd")),
            row("启动参数", app.get("args")),
            row("文件说明", app.get("desc")),
            row("公司", app.get("company")),
            row("产品", app.get("product")),
            row("版本", app.get("version")),
            row("数字签名", sig.get("label")),
            row("签名说明", (sig.get("detail") or "").replace("\n", " ")),
        ])
        note = ""
        if not app.get("exists"):
            sib = app.get("siblings") or []
            note = ("<div style='margin-top:10px;background:%s;border:1px solid %s;"
                    "padding:8px 10px;color:%s;font-size:12px;line-height:1.7'>"
                    "找不到这个文件，多半是软件已卸载、或升级后改了文件名（自启条目成了残留）。<br>"
                    "这种项建议「禁止启动」或「彻底删除」，删了不影响任何在用的软件。"
                    % (PAL["err_bg"], PAL["border"], PAL["err"])
                    + (("<br>同目录下现在有：%s" % html.escape("、".join(sib[:5]))) if sib else "")
                    + "</div>")
        body = QTextBrowser()
        body.setFrameShape(QFrame.NoFrame)
        body.setFont(QFont("Microsoft YaHei UI", 9))
        body.setHtml("<table style='font-size:12px'>%s</table>%s" % (rows, note))
        v.addWidget(body, 1)

        bb = QHBoxLayout()
        b_open = QPushButton("打开位置")
        b_open.clicked.connect(lambda: self._open_containing(app))
        b_open.setEnabled(bool(app.get("exists")))
        bb.addWidget(b_open)
        b_sig = QPushButton("数字签名")
        b_sig.clicked.connect(lambda: self.show_signature(app))
        bb.addWidget(b_sig)
        b_copy = QPushButton("复制路径")
        b_copy.clicked.connect(lambda: self._copy_text(app.get("path") or "", "文件路径"))
        bb.addWidget(b_copy)
        bb.addStretch(1)
        b_close = QPushButton("关闭")
        b_close.setObjectName("primary")
        b_close.clicked.connect(dlg.accept)
        bb.addWidget(b_close)
        v.addLayout(bb)
        dlg.exec_()

    @guard
    def on_apply_one(self):
        self._run_findings(self._op_targets()[0])

    @guard
    def _run_single(self, f, op_key=None):
        self._run_findings([f] if f else [], op_key)

    @guard
    def _run_findings(self, fs, op_key=None):
        if self._scan_busy():
            self.statusBar().showMessage("正在体检，等刷新完成后再执行")
            return
        fs = [f for f in (fs or []) if f and f.get("fix")]
        if not fs:
            QMessageBox.information(self, "立即执行",
                                    "选中的项没有可自动处理的操作（只是提示项）。")
            return
        if not bc.is_admin():
            r = QMessageBox.question(
                self, "需要管理员权限",
                "立即执行需要管理员权限。\n是否现在以管理员身份重启本程序？",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
            if r == QMessageBox.Yes:
                self.on_elevate()
            return
        for f in fs:
            if op_key and (f.get("opts") or {}).get(op_key):
                bc.apply_op(f, op_key)
                self._ops[f.get("id")] = op_key
        tags, lines = [], []
        for f in fs:
            tag = bc.OP_LABELS.get(f.get("op"), "")
            tags.append(tag)
            lines.append("· %s%s" % (("[%s] " % tag) if tag else "", f.get("title", "")))
        box = QMessageBox(self)
        box.setWindowTitle("立即执行")
        box.setIcon(QMessageBox.Question)
        if len(fs) == 1:
            f = fs[0]
            box.setText("即将立即执行：\n\n· %s%s\n\n执行前会自动备份，可用「还原」撤回。"
                        % ("[%s] " % tags[0] if tags[0] else "", f.get("title", "")))
            app = self._app_of(f)
            if app:
                box.setInformativeText("应用：%s\n路径：%s"
                                       % (bc.app_label(app), app.get("path") or ""))
        else:
            box.setText("即将立即执行选中的 %d 项：\n\n执行前会自动备份，可用「还原」撤回。"
                        % len(fs))
            box.setDetailedText("\n".join(lines))
        box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        box.button(QMessageBox.Yes).setText("执 行")
        box.button(QMessageBox.No).setText("取消")
        if box.exec_() != QMessageBox.Yes:
            return
        self._set_busy(True, "正在执行 …")
        for f in fs:
            self._log("立即执行：%s %s"
                      % (bc.OP_LABELS.get(f.get("op"), ""), f.get("title", "")))
        self.fix_worker = FixWorker(fs, self)
        self.fix_worker.sig_progress.connect(self.on_progress)
        self.fix_worker.sig_done.connect(self.on_fix_done)
        self.fix_worker.sig_fail.connect(self.on_worker_fail)
        self.fix_worker.start()

    # ---------------- 详情面板 HTML ----------------
    def _finding_html(self, f):
        p = PAL
        sev = f.get("sev", "info")
        color, tint = sev_color(sev), sev_tint(sev)
        app = f.get("app") or {}
        sig = self._sig_of(app) if app else {"label": ""}

        def row(k, val, vcolor=None):
            if not val:
                return ""
            return ("<tr><td style='color:%s;padding:3px 12px 3px 0;white-space:nowrap;"
                    "vertical-align:top;font-size:12px'>%s</td>"
                    "<td style='padding:3px 0;font-size:12px;word-break:break-all;color:%s'>%s</td></tr>"
                    % (p["faint"], html.escape(k), vcolor or p["text"], html.escape(str(val))))

        h = ["<div style='font-family:\"Microsoft YaHei UI\";color:%s'>" % p["text"]]
        h.append("<div style='font-size:14px;font-weight:600'>%s</div>"
                 % html.escape(f.get("title", "")))
        h.append("<div style='font-size:11px;color:%s;margin:2px 0 8px 0'>"
                 "<span style='color:%s;font-weight:600'>%s</span>&nbsp;&nbsp;%s</div>"
                 % (p["faint"], color, bc.SEV_CN.get(sev, "?"), html.escape(f.get("short", ""))))

        rows = [row("分类", f.get("cat")),
                row("来源", f.get("src") or f.get("cat")),
                row("应用", bc.app_label(app) if app else ""),
                row("发布者", app.get("company")),
                row("签名", sig.get("label"),
                    {"valid": p["ok"], "catalog": p["info"],
                     "invalid": p["err"], "missing": p["err"]}.get(sig.get("state"))),
                row("路径", app.get("path")),
                row("处理方式", bc.OP_LABELS.get(f.get("op"), ""))]
        rows = "".join(r for r in rows if r)
        if rows:
            h.append("<table cellspacing='0' cellpadding='0' "
                     "style='margin-bottom:10px'>%s</table>" % rows)

        raw_detail = f.get("detail", "")
        cut = raw_detail.find("\n\n应用名称：")
        if cut > 0:
            raw_detail = raw_detail[:cut]
        detail = html.escape(raw_detail).replace("\n", "<br>")
        h.append("<div style='line-height:1.75;font-size:12px;color:%s;"
                 "border-top:1px solid %s;padding-top:8px'>%s</div>"
                 % (p["muted"], p["border_soft"], detail))

        fix = f.get("fix")
        if fix:
            risk = fix.get("risk", "safe")
            rk = ("<span style='color:%s'>安全操作（执行前自动备份）</span>" % p["ok"]
                  if risk == "safe" else
                  "<span style='color:%s'>建议确认后再执行</span>" % p["warn"])
            h.append("<div style='margin-top:10px;background:%s;border:1px solid %s;"
                     "padding:8px 10px;font-size:12px'>"
                     "<b>修复方式：</b>%s<br>%s</div>"
                     % (p["head"], p["border"], html.escape(
                         bc.FIX_DESC.get(fix.get("type"), fix.get("type", ""))), rk))
            items = fix.get("items")
            if isinstance(items, dict) and items:
                rows = "".join("<br>· %s → %s" % (html.escape(str(k)), {
                    2: "自动", 3: "手动", 4: "禁用"}.get(int(v), v))
                    for k, v in list(items.items())[:25])
                h.append("<div style='margin-top:6px;color:%s;font-size:11px'>"
                         "受影响项目：%s%s</div>"
                         % (p["muted"], rows, "<br>…" if len(items) > 25 else ""))
            elif isinstance(items, list) and items:
                names = []
                for x in items[:25]:
                    if isinstance(x, dict):
                        names.append(x.get("name") or x.get("task") or x.get("exe") or str(x))
                    else:
                        names.append(str(x))
                h.append("<div style='margin-top:6px;color:%s;font-size:11px'>"
                         "受影响项目：<br>· %s%s</div>"
                         % (p["muted"], "<br>· ".join(html.escape(n) for n in names),
                            "<br>…" if len(items) > 25 else ""))
        else:
            h.append("<div style='margin-top:10px;color:%s;font-size:12px'>"
                     "本项仅提示，不自动处理。</div>" % p["faint"])
        h.append("</div>")
        return "".join(h)

    # ---------------- 执行修复 ----------------
    @guard
    def on_apply(self):
        findings = self._checked_findings()
        if not findings:
            return
        if self._scan_busy():                      # 正在刷新：别对着旧结果执行
            self.statusBar().showMessage("正在体检，等刷新完成后再执行")
            return
        if not bc.is_admin():
            r = QMessageBox.question(
                self, "需要管理员权限",
                "修复系统设置需要管理员权限。\n是否现在以管理员身份重启本程序？",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
            if r == QMessageBox.Yes:
                self.on_elevate()
            return
        safe = [f for f in findings if f["fix"].get("risk") == "safe"]
        conf = [f for f in findings if f["fix"].get("risk") == "confirm"]
        lines, n_del = [], 0
        for f in findings:
            tag = ("〔%s〕" % bc.OP_LABELS[f["op"]]) if f.get("op") in bc.OP_LABELS else ""
            lines.append("· %s%s" % (tag, f["title"]))
            if f.get("op") == "delete":
                n_del += 1
        box = QMessageBox(self)
        box.setWindowTitle("智能优化")
        box.setIcon(QMessageBox.Question)
        text = ("即将执行 %d 项修复（安全 %d / 需确认 %d）。\n执行前会先自动备份，可随时还原。"
                % (len(findings), len(safe), len(conf)))
        if n_del:
            text += "\n\n其中 %d 项是「彻底删除」：会移除自启条目或注销计划任务。" % n_del
        box.setText(text)
        box.setDetailedText("将执行：\n" + "\n".join(lines))
        box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        b_yes, b_no = box.button(QMessageBox.Yes), box.button(QMessageBox.No)
        if b_yes:
            b_yes.setText("开始优化")
        if b_no:
            b_no.setText("取消")
        if box.exec_() != QMessageBox.Yes:
            return
        self._set_busy(True, "正在执行修复 …")
        self.fix_worker = FixWorker(findings, self)
        self.fix_worker.sig_progress.connect(self.on_progress)
        self.fix_worker.sig_done.connect(self.on_fix_done)
        self.fix_worker.sig_fail.connect(self.on_worker_fail)
        self.fix_worker.start()

    @guard
    def on_fix_done(self, results, bdir):
        ok = sum(1 for r in results if r.get("ok"))
        fail = len(results) - ok
        reboot = any(r.get("reboot") for r in results)
        lines = []
        for r in results:
            lines.append("[%s] %s" % ("成功" if r.get("ok") else "失败", r.get("title", "")))
            for msg in r.get("msgs", [])[:4]:
                lines.append("    %s" % msg)
        for msg in lines:
            self._log(msg)
        text = "优化完成：成功 %d 项，失败 %d 项。" % (ok, fail)
        if fail:
            text += "\n\n失败的项通常是软件自保护所致，重启电脑后再执行一次即可。"
        if reboot:
            text += "\n\n部分修改在下次开机时生效，建议重启后再次体检对比效果。"
        box = QMessageBox(self)
        box.setWindowTitle("智能优化")
        box.setIcon(QMessageBox.Information)
        box.setText(text)
        box.setDetailedText("\n".join(lines))
        box.exec_()
        self._log("备份目录：%s" % bdir)
        self._refresh_restore_state()
        self._refresh_backup_badge()
        if bc.get_setting("autorefresh", True):
            self.start_scan()

    # ---------------- AI ----------------
    @guard
    def on_settings(self):
        dlg = SettingsDialog(self)
        if dlg.exec_() != QDialog.Accepted:
            return
        d = dlg.values()
        base = str(d.get("ai_base") or "")
        # 自启项清单会发到这个地址。默认是本机网关；改成公网/别人机器时必须让用户知道
        if base and not bc.is_local_ai(base):
            r = QMessageBox.question(
                self, "AI 地址不是本机",
                "AI 接口地址：\n%s\n\n这不是本机回环地址。启用「AI 辅助判断」时，"
                "会把自启项名称、软件公司名和「末两级路径」发送到该地址"
                "（不发完整路径、不发文件）。\n\n确认这是你自己信任的服务吗？"
                % base, QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if r != QMessageBox.Yes:
                return
        self.apply_settings(d)

    @guard
    def on_ai_config(self, pos=None):
        """旧入口（AI 按钮右键）：直接打开设置里的 AI 页。"""
        self.on_settings()

    def apply_settings(self, d):
        old_theme = bc.get_setting("theme", "light")
        for k, v in d.items():
            bc.set_setting(k, v)
        base, model = bc.get_ai_cfg()
        enabled = bool(d.get("ai_enabled", True))
        self._refresh_ai_button()
        if d.get("theme") and d["theme"] != old_theme:
            self.set_theme(d["theme"])
        self.statusBar().showMessage("设置已保存", 4000)
        self._log("设置已保存：AI %s（%s / %s）" % ("开" if enabled else "关", base, model))

    def set_theme(self, theme):
        use_theme(theme)
        retint_glass(self, theme)
        QApplication.instance().setStyleSheet(build_qss())
        bc.set_setting("theme", theme)
        if self.result:
            keep = set(f.get("id") for f in self._checked_findings() if f.get("id"))
            self._fill_tree(self.result, keep=keep)
            # 没有选中行时右侧停在欢迎页，那段 HTML 的内联色是旧主题的，必须按新主题重画
            if not self._cur_app:
                self._show_welcome()
        else:
            self._show_welcome()
        self._tree_palette()
        self._cap_icons()
        self._update_admin_badge()
        np_ = self._page_built.get("notify")
        if np_ is not None:
            np_._fill()                    # 行文字颜色是按主题写死的，换主题要重填

    def _ai_targets(self):
        out = []
        for f in (self.result or {}).get("findings", []):
            if f.get("cat") != "延迟启动":
                continue
            if not (f.get("app") or f.get("fix")):
                continue
            out.append(f)
        return out[:40]

    @guard
    def on_adware_only(self):
        """只看流氓软件：切分类到「流氓软件」并重新体检一次（若还没数据）。"""
        idx = self.cb_cat.findData("流氓软件")
        if idx >= 0:
            self.cb_cat.setCurrentIndex(idx)
        if not self.result:
            self.start_scan()
            return
        n = sum(1 for f in (self.result.get("findings") or [])
                if f.get("cat") == "流氓软件")
        if n:
            self.statusBar().showMessage(
                "发现 %d 类流氓软件 / 全家桶，右键可运行官方卸载程序" % n, 8000)
        else:
            st = bc.adware_db_stats()
            QMessageBox.information(
                self, "没发现流氓软件",
                "特征库里没有命中项。\n\n"
                "注意：这里只比对已知的国产捆绑软件特征（%d 个目录 + %d 个签名主体 "
                "+ %d 个厂商家族，更新于 %s）。不认识的软件不会误报，"
                "但也不代表它一定干净。"
                % (st["dirs"], st["pubs"], st["families"], st["updated"]))

    @guard
    def on_popup_dialog(self):
        """弹窗定位 + 拦截规则 + 后台守护开关（现在是左侧的一页）。"""
        self.show_page("popup")
        self._popup_dlg = self.page_widget("popup")

    @guard
    def on_update_db(self):
        """在线同步上游特征库（只读公开黑名单文本，不动系统）。"""
        w = getattr(self, "_dbw", None)
        if w is not None and w.isRunning():
            self.statusBar().showMessage("特征库正在更新，请稍候…", 4000)
            return
        st = bc.adware_db_stats()
        r = QMessageBox.question(
            self, "更新流氓软件特征库",
            "当前特征库：v%d，更新于 %s\n"
            "%d 个目录 + %d 个签名主体 + %d 个厂商家族\n\n"
            "将从上游（Gitee 官方数据，失败自动换 GitHub 镜像）拉取最新黑名单。\n"
            "只下载公开文本文件，不下载任何程序，也不会改动系统设置。\n"
            "更新前自动备份当前库，可随时回滚。\n\n现在更新吗？"
            % (st["version"], st["updated"], st["dirs"], st["pubs"], st["families"]),
            QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
        if r != QMessageBox.Yes:
            return
        self.statusBar().showMessage("正在连接特征库源…")
        self._dbw = DbUpdateWorker(self)
        self._dbw.sig_progress.connect(
            lambda t: self.statusBar().showMessage(t, 6000))
        self._dbw.sig_done.connect(self._on_db_updated)
        self._dbw.sig_fail.connect(self._on_db_failed)
        self._dbw.start()

    def _on_db_failed(self, txt):
        self.statusBar().showMessage("特征库更新失败，本地库未改动", 8000)
        t = (txt or "").strip()
        if len(t) > 700:
            t = t[:700] + " …"
        QMessageBox.warning(
            self, "特征库更新失败",
            "没能从上游取到特征库，本地库没有改动。\n\n%s\n\n"
            "常见原因：没联网、公司代理拦了 Gitee / GitHub。\n"
            "也可以手动下载 folder.txt、sign.txt，然后运行：\n"
            "python _db_update.py --offline <文件夹>" % t)

    def _sync_db_btn(self):
        """工具栏「特征库」按钮显示当前版本，免得用户不知道库有多旧。"""
        try:
            st = bc.adware_db_stats()
            self.btn_db.setText("特征库 v%s" % st["version"])
            self.btn_db.setToolTip(
                "流氓软件特征库：%d 个目录 + %d 个签名主体 + %d 个家族\n"
                "更新于 %s\n点击从上游在线更新"
                % (st["dirs"], st["pubs"], st["families"], st["updated"]))
        except Exception:
            self.btn_db.setText("特征库")

    def _on_db_updated(self, rep):
        if not rep or not rep.get("ok"):
            self._on_db_failed((rep or {}).get("error") or "未知错误")
            return
        if rep.get("up_to_date"):
            self.statusBar().showMessage(
                "特征库已是最新（v%s）" % rep["version"], 8000)
            st = bc.adware_db_stats()
            QMessageBox.information(
                self, "特征库已是最新",
                "上游没有新条目，本地库未改动。\n\n"
                "当前：v%d，更新于 %s\n%d 个目录 + %d 个签名主体 + %d 个厂商家族"
                % (rep["version"], rep["updated"], st["dirs"], st["pubs"], st["families"]))
            return
        self._sync_db_btn()
        self.statusBar().showMessage(
            "特征库已更新到 v%d（%s）" % (rep["version"], rep["updated"]), 8000)
        lines = [
            "已更新到 v%d（%s）" % (rep["version"], rep["updated"]),
            "来源：%s" % rep.get("source", ""),
            "",
            "目录 %d 条：新增 %d，移除 %d，另有 %d 条改为带路径形式"
            % (rep["dirs"], rep["added_dirs"], rep["removed_dirs"], rep["moved_dirs"]),
            "签名 %d 条：新增 %d，移除 %d"
            % (rep["pubs"], rep["added_pubs"], rep["removed_pubs"]),
        ]
        if rep.get("samples_added"):
            lines += ["", "新增样例：" + "、".join(rep["samples_added"][:8])]
        if rep.get("backup"):
            lines += ["", "旧库已备份到：%s" % rep["backup"]]
        if not (rep["added_dirs"] or rep["removed_dirs"] or rep["moved_dirs"]
                or rep["added_pubs"] or rep["removed_pubs"]):
            lines += ["", "本地已经是最新的，没有差异。"]
        lines += ["", "现在重新体检一次，用新特征库扫一遍吗？"]
        r = QMessageBox.question(self, "特征库更新完成", "\n".join(lines),
                                 QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
        if r == QMessageBox.Yes:
            self.start_scan()

    @guard
    def on_ai(self):
        if not bc.get_setting("ai_enabled", True):
            QMessageBox.information(self, "AI 已关闭",
                                    "AI 判断已在设置里关闭。\n打开「设置 → AI 接口」勾选"
                                    "「启用 AI 辅助判断」后即可使用。")
            return
        targets = self._ai_targets()
        if not targets:
            QMessageBox.information(self, "AI 帮我判断",
                                    "请先点「体检」，等清单出来后我再分析。")
            return
        if self.ai_worker and self.ai_worker.isRunning():
            return
        self._set_busy(True, "AI 正在分析 %d 项 …" % len(targets))
        self._log("AI 分析开始：%d 项" % len(targets))
        self.ai_worker = AiWorker("batch", targets, self)
        self.ai_worker.sig_progress.connect(self.on_progress)
        self.ai_worker.sig_done.connect(self.on_ai_done)
        self.ai_worker.sig_fail.connect(self.on_worker_fail)
        self.ai_worker.start()

    @guard
    def _ai_one(self, f):
        if not f:
            return
        if not bc.get_setting("ai_enabled", True):
            self.on_ai()
            return
        if self.ai_worker and self.ai_worker.isRunning():
            return
        self._set_busy(True, "AI 正在看「%s」…" % (f.get("name") or f.get("title") or ""))
        self.ai_worker = AiWorker("one", [f], self)
        self.ai_worker.sig_progress.connect(self.on_progress)
        self.ai_worker.sig_done.connect(self.on_ai_done)
        self.ai_worker.sig_fail.connect(self.on_worker_fail)
        self.ai_worker.start()

    @guard
    def on_ai_done(self, mode, payload):
        self._set_busy(False, "就绪")
        data, err = payload
        if err:
            QMessageBox.warning(self, "AI 帮我判断", err)
            self._log("AI 失败：%s" % err)
            return
        if mode == "batch":
            for f in self._ai_targets():
                a = data.get(f.get("id"))
                if a:
                    f["ai"] = a
            keep = set(x.get("id") for x in self._checked_findings() if x.get("id"))
            self._fill_tree(self.result, keep=keep)
            self._log("AI 给出 %d 条建议" % len(data))
            self.show_ai_suggestions()
        else:
            self.show_ai_text(data)

    def show_ai_suggestions(self):
        finds = [f for f in self._ai_targets() if f.get("ai")]
        if not finds:
            QMessageBox.information(self, "AI 帮我判断", "AI 没有给出可用建议，稍后再试。")
            return
        order = {"disable": 0, "delay": 1, "keep": 2}
        finds.sort(key=lambda x: (order.get(x["ai"]["verdict"], 3), (x.get("name") or "").lower()))
        dlg = QDialog(self)
        dlg.setWindowTitle("AI 建议（%d 项）" % len(finds))
        dlg.resize(920, 580)
        v = QVBoxLayout(dlg)
        v.setContentsMargins(14, 12, 14, 12)
        v.setSpacing(8)
        tip = QLabel("AI 按「这程序是什么 + 开机是否必须」给建议。勾选的项在点「采纳勾选项」后"
                     "会替换成对应处理方式（禁止 / 延迟），最终仍由你点「智能优化」执行，"
                     "执行前自动备份。")
        tip.setObjectName("meta")
        tip.setWordWrap(True)
        v.addWidget(tip)
        t = QTreeWidget()
        t.setColumnCount(4)
        t.setHeaderLabels(["项目", "应用", "AI 建议", "理由"])
        t.setColumnWidth(0, 220)
        t.setColumnWidth(1, 260)
        t.setColumnWidth(2, 84)
        t.header().setStretchLastSection(True)
        t.setRootIsDecorated(False)
        t.setAlternatingRowColors(True)
        for f in finds:
            a = f["ai"]
            it = QTreeWidgetItem([f.get("name") or "", bc.app_label(f.get("app") or {}),
                                  bc.AI_VERDICT_CN.get(a["verdict"], "?"),
                                  a.get("reason") or ""])
            it.setForeground(2, QColor(bc.AI_VERDICT_COLOR.get(a["verdict"], PAL["muted"])))
            it.setToolTip(1, bc.app_detail_text(f.get("app") or {}))
            it.setToolTip(3, a.get("reason") or "")
            it.setData(0, Qt.UserRole, f.get("id"))
            it.setFlags(it.flags() | Qt.ItemIsUserCheckable)
            it.setCheckState(0, Qt.Checked if a["verdict"] != "keep" else Qt.Unchecked)
            t.addTopLevelItem(it)
        v.addWidget(t, 1)
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.button(QDialogButtonBox.Ok).setText("采纳勾选项")
        bb.button(QDialogButtonBox.Ok).setObjectName("primary")
        bb.button(QDialogButtonBox.Cancel).setText("只看建议")
        bb.accepted.connect(dlg.accept)
        bb.rejected.connect(dlg.reject)
        v.addWidget(bb)
        if dlg.exec_() != QDialog.Accepted:
            return
        chosen, n_keep = set(), 0
        for i in range(t.topLevelItemCount()):
            it = t.topLevelItem(i)
            fid = it.data(0, Qt.UserRole)
            if it.checkState(0) != Qt.Checked:
                continue
            f = next((x for x in finds if x.get("id") == fid), None)
            if not f:
                continue
            op = {"disable": "block", "delay": "delay"}.get(f["ai"]["verdict"])
            if op and f.get("opts") and op in f["opts"]:
                bc.apply_op(f, op)
                self._ops[fid] = op
                n_keep += 1
            chosen.add(fid)
        keep = set(x.get("id") for x in self._checked_findings() if x.get("id")) | chosen
        self._fill_tree(self.result, keep=keep)
        self.statusBar().showMessage(
            "已采纳 AI 建议 %d 项（其中 %d 项改成了禁止/延迟），点「智能优化」执行"
            % (len(chosen), n_keep), 9000)

    def show_ai_text(self, text):
        dlg = QDialog(self)
        dlg.setWindowTitle("AI 怎么看这个程序")
        dlg.resize(660, 480)
        v = QVBoxLayout(dlg)
        v.setContentsMargins(14, 12, 14, 12)
        v.setSpacing(8)
        body = QTextBrowser()
        body.setFrameShape(QFrame.NoFrame)
        body.setFont(QFont("Microsoft YaHei UI", 9))
        body.setWordWrapMode(QTextOption.WrapAtWordBoundaryOrAnywhere)
        body.setHtml("<div style='line-height:1.8;font-size:12px;color:%s'>%s</div>"
                     % (PAL["text"], html.escape(text).replace("\n", "<br>")))
        v.addWidget(body, 1)
        bb = QDialogButtonBox(QDialogButtonBox.Close)
        bb.button(QDialogButtonBox.Close).setText("关闭")
        bb.rejected.connect(dlg.reject)
        bb.clicked.connect(dlg.accept)
        v.addWidget(bb)
        dlg.exec_()

    # ---------------- 趋势 / 还原 / 导出 ----------------
    @guard
    def on_boot_trend(self):
        boots = ((self._raw or {}).get("events") or {}).get("boots") or []
        if not boots:
            QMessageBox.information(self, "开机耗时趋势",
                                    "还没有开机性能记录。先点「体检」采集一次。")
            return
        BootTrendDialog(self, self._raw).exec_()

    def _refresh_restore_state(self):
        has = bool(bc.list_backups())
        if self.btn_restore:
            self.btn_restore.setEnabled(has)
        if hasattr(self, "lbl_bk"):
            self._refresh_backup_badge()
        self._sync_nav_badges()

    @guard
    def open_backup_dir(self):
        d = bc.BACKUP_DIR
        if not os.path.isdir(d):
            QMessageBox.information(self, "备份目录", "还没有备份。\n会创建在：%s" % d)
            return
        subprocess.Popen(["explorer.exe", os.path.normpath(d)])

    @guard
    def on_restore(self):
        """还原入口统一到「备份还原」页：能看到每个备份改了什么再决定。"""
        if not bc.list_backups():
            QMessageBox.information(self, "还原", "还没有任何备份。")
            return
        self.show_page("backup")

    def restore_dir(self, bdir):
        if not bdir:
            return
        if QMessageBox.question(self, "确认还原",
                                "确定要还原所选备份吗？\n%s" % bdir,
                                QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
            return
        self._set_busy(True, "正在还原 …")
        self.restore_worker = RestoreWorker(bdir, self)
        self.restore_worker.sig_progress.connect(self.on_progress)
        self.restore_worker.sig_done.connect(self.on_restore_done)
        self.restore_worker.sig_fail.connect(self.on_worker_fail)
        self.restore_worker.start()

    @guard
    def on_restore_done(self, results):
        ok = sum(1 for r in results if r.get("ok"))
        fail = len(results) - ok
        msg = "还原完成：成功 %d 项，失败 %d 项。" % (ok, fail)
        if fail:
            msg += "\n失败的项可能受软件保护，重启后再试一次。"
        QMessageBox.information(self, "还原", msg)
        for r in results:
            self._log("[还原%s] %s" % ("成功" if r.get("ok") else "失败", r.get("kind", "")))
        bp = self._page_built.get("backup")
        if bp is not None:
            bp.refresh()
        self.start_scan()

    @guard
    def on_export(self):
        if not self.result:
            QMessageBox.information(self, "导出报告", "请先执行一次体检。")
            return
        default = os.path.join(os.path.expanduser("~"), "Desktop",
                               "开机体检报告_%s.md" % time.strftime("%Y%m%d_%H%M"))
        fn, _ = QFileDialog.getSaveFileName(self, "保存体检报告", default,
                                            "Markdown (*.md);;文本 (*.txt)")
        if not fn:
            return
        try:
            with open(fn, "w", encoding="utf-8") as f:
                f.write(bc.build_report(self.result))
            self._log("报告已保存：%s" % fn)
            self.statusBar().showMessage("报告已保存：%s" % fn, 6000)
        except OSError as e:
            QMessageBox.warning(self, "导出报告", "保存失败：%s" % e)

    @guard
    def on_export_html(self):
        """导出单文件 HTML 报告：带图表、可分享、可直接打印成 PDF。"""
        if not self.result:
            QMessageBox.information(self, "导出报告", "请先执行一次体检。")
            return
        default = os.path.join(
            os.path.expanduser("~"), "Desktop",
            "开机体检报告_%s.html" % time.strftime("%Y%m%d_%H%M"))
        fn, _ = QFileDialog.getSaveFileName(
            self, "导出 HTML 报告", default, "HTML (*.html)")
        if not fn:
            return
        try:
            bc.write_html_report(self.result, raw=self._raw, path=fn)
        except Exception as e:
            self._log("导出 HTML 失败：%r" % (e,))
            QMessageBox.warning(self, "导出失败", "写文件失败：\n%s" % e)
            return
        self._log("已导出 HTML 报告：%s" % fn)
        r = QMessageBox.question(
            self, "报告已导出",
            "已保存到：\n%s\n\n现在用浏览器打开看看？" % fn,
            QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
        if r == QMessageBox.Yes:
            try:
                os.startfile(fn)
            except Exception:
                pass

    @guard
    def on_export_csv(self):
        if not self.result:
            QMessageBox.information(self, "导出清单", "请先执行一次体检。")
            return
        default = os.path.join(os.path.expanduser("~"), "Desktop",
                               "开机清单_%s.csv" % time.strftime("%Y%m%d_%H%M"))
        fn, _ = QFileDialog.getSaveFileName(self, "导出清单 CSV", default, "CSV (*.csv)")
        if not fn:
            return
        try:
            with open(fn, "w", encoding="utf-8-sig", newline="") as fp:
                w = csv.writer(fp)
                w.writerow(["分类", "等级", "项目", "应用", "发布者", "签名",
                            "来源", "处理方式", "说明"])
                for f in self.result.get("findings", []):
                    app = f.get("app") or {}
                    sig = self._sig_of(app) if app else {"label": ""}
                    w.writerow([f.get("cat"), bc.SEV_CN.get(f.get("sev"), ""),
                                f.get("title"), bc.app_label(app), app.get("company") or "",
                                sig.get("label") or "", f.get("src") or "",
                                bc.OP_LABELS.get(f.get("op"), ""), f.get("short") or ""])
            self.statusBar().showMessage("清单已保存：%s" % fn, 6000)
            self._log("清单已导出：%s" % fn)
        except OSError as e:
            QMessageBox.warning(self, "导出清单", "保存失败：%s" % e)

    @guard
    def on_about(self):
        QMessageBox.about(self, "关于",
                          "%s %s\n\n开机链路体检 / 延迟启动 / 自启项管理。\n"
                          "配置：%s\n备份：%s\n\n所有修改前自动备份，随时可还原。"
                          % (bc.APP_NAME, bc.VERSION, bc.SETTINGS_PATH, bc.BACKUP_DIR))

    # ---------------- 其他 ----------------
    @guard
    def on_toggle_log(self):
        show = not self.log_edit.isVisible()
        self.log_edit.setVisible(show)
        self.btn_log.setText("隐藏日志" if show else "运行日志")

    @guard
    def on_elevate(self):
        # 以前不看 ShellExecuteW 的返回值：用户在 UAC 里点「否」，程序也照样退出了
        ok, err = relaunch_elevated()
        if ok:
            QApplication.quit()
        elif err:
            QMessageBox.warning(self, "提权失败", "无法以管理员身份重启：%s" % err)

    def closeEvent(self, event):
        event.accept()


def relaunch_elevated():
    """用 ShellExecute runas 以管理员身份重新拉起本程序。返回 (是否已拉起, 错误说明)。

    用户在 UAC 里点「否」返回 (False, "")：调用方继续以普通权限运行即可。
    """
    script = os.path.abspath(__file__)
    exe = sys.executable
    pwx = os.path.join(os.path.dirname(exe), "pythonw.exe")
    if os.path.exists(pwx):
        exe = pwx
    args = subprocess.list2cmdline([script, "--no-elevate"] +
                                   [a for a in sys.argv[1:] if a != "--no-elevate"])
    try:
        rc = int(ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, args,
                                                     os.path.dirname(script), 1))
    except Exception as e:
        return False, str(e)
    if rc > 32:
        return True, ""
    return False, "" if rc == 5 else "ShellExecute 返回 %d" % rc   # 5 = 用户拒绝 UAC


def main():
    # 提权放在程序里做：启动体检.bat 不再先起一个 PowerShell 去 Start-Process -Verb RunAs，
    # 少一个 PowerShell 冷启动；用户拒绝 UAC 时以普通权限继续（界面上有「以管理员身份重启」）
    if not bc.is_admin() and "--no-elevate" not in sys.argv \
            and not os.environ.get("BOOTDOC_NO_ELEVATE"):
        if relaunch_elevated()[0]:
            return
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    sys.excepthook = _excepthook
    app = QApplication(sys.argv)
    app.setStyle(GlassItemStyle("Fusion"))
    use_theme(bc.get_setting("theme", "light"))
    app.setFont(QFont("Microsoft YaHei UI", 9))
    app.setStyleSheet(build_qss())
    app._chrome_filter = DialogChrome(app)      # 保持引用，别被 GC
    app.installEventFilter(app._chrome_filter)
    win = MainWindow()
    win.show()
    for a in sys.argv[1:]:
        if a.startswith("--page="):           # 守护托盘提醒点进来时直接到对应页
            win.show_page(a.split("=", 1)[1])
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
