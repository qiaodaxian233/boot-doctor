# -*- coding: utf-8 -*-
"""弹窗拦截守护（后台托盘）

为什么不放进主程序：体检工具只在需要时打开，常驻一个窗口没道理。所以拦截单独跑，
主程序负责「指认是谁弹的 + 配规则 + 开关守护」，这个小进程只干一件事——盯着新窗口，
命中规则就发 WM_CLOSE。

安全边界（重要）：
  · 只发 WM_CLOSE（请求关闭），不 TerminateProcess，不注入 DLL，不挂钩子
  · 任务栏 / 桌面 / 开始菜单这类系统窗口无条件放过
  · 自动模式只关「命中流氓软件特征库 / 已知纯广告进程」的窗口
  · 标题关键词只用来提示可疑，不作为关闭依据（"推荐""精选"误伤太大）
  · 同一个窗口 30 秒内不重复发消息，避免和顽固程序死磕

启动：主程序「操作 → 弹窗拦截…」里点开始，或直接 python popup_guard.py
停止：托盘菜单退出，或由主程序写 _logs\\popup_guard.stop
"""
import ctypes
import ctypes.wintypes as wt
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import boot_core as bc  # noqa: E402
from PyQt5.QtCore import Qt, QTimer  # noqa: E402
from PyQt5.QtGui import QColor, QFont, QIcon, QPainter, QPixmap  # noqa: E402
from PyQt5.QtWidgets import (QAction, QApplication, QMenu, QMessageBox,  # noqa: E402
                             QSystemTrayIcon)

GL = os.path.join(bc.LOG_DIR, "popup_guard.log")
WM_CLOSE = 0x0010
ERROR_ACCESS_DENIED = 5
ERROR_ALREADY_EXISTS = 183

# 事件钩子：窗口一显示就收到通知，不用靠轮询碰运气。
# WINEVENT_OUTOFCONTEXT = 不注入任何进程，回调走本线程的消息循环（Qt 事件循环会泵它），
# 和「不注入、不挂全局钩子」的安全边界一致。
EVENT_OBJECT_SHOW = 0x8002
WINEVENT_OUTOFCONTEXT = 0x0000
WINEVENT_SKIPOWNPROCESS = 0x0002
OBJID_WINDOW = 0
CHILDID_SELF = 0
GA_ROOT = 2

# 单独的 WinDLL 实例 + use_last_error：GetLastError 才可靠，
# 也不会改到 boot_core 里共用的 ctypes.windll.user32 函数签名
_u32 = ctypes.WinDLL("user32", use_last_error=True)
_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
WinEventProc = ctypes.WINFUNCTYPE(None, wt.HANDLE, wt.DWORD, wt.HWND, wt.LONG,
                                  wt.LONG, wt.DWORD, wt.DWORD)
_u32.SetWinEventHook.restype = wt.HANDLE
_u32.SetWinEventHook.argtypes = [wt.UINT, wt.UINT, wt.HMODULE, WinEventProc,
                                 wt.DWORD, wt.DWORD, wt.UINT]
_u32.UnhookWinEvent.restype = wt.BOOL
_u32.UnhookWinEvent.argtypes = [wt.HANDLE]
_u32.GetAncestor.restype = wt.HWND
_u32.GetAncestor.argtypes = [wt.HWND, wt.UINT]
_u32.PostMessageW.restype = wt.BOOL
_u32.PostMessageW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
_u32.IsWindow.restype = wt.BOOL
_u32.IsWindow.argtypes = [wt.HWND]
_u32.IsWindowVisible.restype = wt.BOOL
_u32.IsWindowVisible.argtypes = [wt.HWND]
_k32.CreateMutexW.restype = wt.HANDLE
_k32.CreateMutexW.argtypes = [ctypes.c_void_p, wt.BOOL, wt.LPCWSTR]
SILENT = "--silent" in sys.argv        # 开机自启走的模式：不弹任何窗口 / 对话框


def glog(msg):
    try:
        os.makedirs(os.path.dirname(GL), exist_ok=True)
        with open(GL, "a", encoding="utf-8") as fp:
            fp.write("[%s] %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg))
    except Exception:
        pass


def make_icon(color="#2f6feb"):
    pm = QPixmap(64, 64)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    p.setBrush(QColor(color))
    p.setPen(Qt.NoPen)
    p.drawEllipse(4, 4, 56, 56)
    p.setPen(QColor(255, 255, 255))
    f = QFont("Microsoft YaHei UI", 26, QFont.Bold)
    p.setFont(f)
    p.drawText(pm.rect(), Qt.AlignCenter, "禁")
    p.end()
    return QIcon(pm)


class Guard(QApplication):
    def __init__(self, argv):
        super().__init__(argv)
        self.setQuitOnLastWindowClosed(False)
        self.closed = {}            # hwnd -> (time, count)
        self.seen = {}              # proc|title -> time（窗口记录去重用）
        self.blocked = 0
        self.failed = 0             # PostMessage 被拒（多为权限不足 / UIPI）
        self.skipped = 0
        self.paused = False
        self._pending = set()       # 事件钩子报上来、等待判定的 hwnd
        self._hook = None
        self._hook_proc = None      # 必须持有引用，否则回调被 GC 后进程直接崩
        self._rules_mtime = None
        self.rules = bc.load_popup_rules()
        self.paused = not bool(self.rules.get("enabled"))
        if self.paused and SILENT:
            # 开机自启模式下「总开关」是关的：直接退出，别留个灰图标占托盘
            glog("拦截已关闭（enabled=false），本次静默退出")
            raise SystemExit(0)

        # pid 文件第一时间写：主程序靠它判断「守护起来了没有」。以前写在自启监控初始化之后，
        # 慢一点的机器上主程序等不到就报「守护进程没起来」，其实它几秒后就起来了
        try:
            bc.write_guard_pid()
        except Exception:
            pass

        self.tray = QSystemTrayIcon(make_icon(), self)
        self.tray.setToolTip("弹窗拦截 · 守护中")
        self.menu = QMenu()
        self.act_state = QAction("状态：守护中", self)
        self.act_state.setEnabled(False)
        self.menu.addAction(self.act_state)
        self.menu.addSeparator()
        self.act_pause = QAction("暂停拦截", self)
        self.act_pause.triggered.connect(self.toggle_pause)
        self.menu.addAction(self.act_pause)
        self.act_scan = QAction("立即扫一遍", self)
        self.act_scan.triggered.connect(lambda: self.tick(force=True))
        self.menu.addAction(self.act_scan)
        self.act_log = QAction("打开拦截日志", self)
        self.act_log.triggered.connect(self.open_log)
        self.menu.addAction(self.act_log)
        self.act_open_app = QAction("打开开机体检大师", self)
        self.act_open_app.triggered.connect(lambda: self.open_main("popup"))
        self.menu.addAction(self.act_open_app)
        self.act_rules = QAction("打开规则文件", self)
        self.act_rules.triggered.connect(self.open_rules)
        self.menu.addAction(self.act_rules)
        self.menu.addSeparator()
        self.act_boot = QAction("开机自动拦截", self)
        self.act_boot.setCheckable(True)
        self.act_boot.setChecked(bc.guard_autostart()[0] != "off")
        self.act_boot.setToolTip("登录 Windows 后在后台静默启动，不开窗口、不弹提示")
        self.act_boot.toggled.connect(self.toggle_autostart)
        self.menu.addAction(self.act_boot)
        self.menu.addSeparator()
        self.act_quit = QAction("退出", self)
        self.act_quit.triggered.connect(self.quit_guard)
        self.menu.addAction(self.act_quit)
        self.tray.setContextMenu(self.menu)
        self.tray.show()
        if self.paused:
            self.act_pause.setText("恢复拦截")
            self.act_state.setText("状态：已暂停")
            self.tray.setIcon(make_icon("#8a8f98"))

        self.install_hook()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.tick)
        self.timer.start(self.poll_interval())
        # 停止标记单独用一个轻量定时器查：有钩子时全量扫描会放慢到 5 秒，
        # 不能让主程序的「停止」也跟着等 5 秒（它只等 3 秒就会走强杀）
        self.stop_timer = QTimer(self)
        self.stop_timer.timeout.connect(self.check_stop)
        self.stop_timer.start(500)
        self.aboutToQuit.connect(self.cleanup)   # 注销 / 关机时也会触发
        self.tray.messageClicked.connect(lambda: self.open_main("popup"))

        # 新增自启监控：和弹窗拦截共用这个常驻进程，不再多开一个
        self.as_watch = None
        self.as_snap = None
        self.as_timer = QTimer(self)
        self.as_timer.timeout.connect(self.check_autostart)
        self.as_full_at = 0.0
        if self.rules.get("watch_autostart", True):
            # 拦截先开始工作；自启监控要拍快照、挂一批变更通知，稍后再启动，别拖慢「开始拦截」
            QTimer.singleShot(400, self.start_autostart_watch)

        # 新进程提醒：每 1.5 秒对比一次进程列表（枚举 17 个进程约 10ms，几乎不占 CPU）
        self.proc_seen = {}         # (pid, ctime) -> 首次见到的时间
        self.proc_alerted = {}      # 路径 -> 上次提醒时间（同一个程序 10 分钟内只提醒一次，防刷屏）
        self.proc_baseline = False
        self.proc_alerts = 0
        self.proc_timer = QTimer(self)
        self.proc_timer.timeout.connect(self.check_processes)
        QTimer.singleShot(600, lambda: self.proc_timer.start(1500))

        self.update_tip()
        glog("守护启动 pid=%d 管理员=%s 事件钩子=%s 规则 block=%d allow=%d auto=%s"
             % (os.getpid(), bc.is_admin(), "on" if self._hook else "off(轮询)",
                len(self.rules.get("block") or []),
                len(self.rules.get("allow") or []), self.rules.get("auto_adware")))
        if not bc.is_admin():
            glog("提示：守护以普通权限运行，以管理员身份运行的程序弹出的窗口关不掉（UIPI 限制）")
        self.tick(force=True)

    # ---------------- 新增自启监控 ----------------
    def start_autostart_watch(self):
        try:
            self.as_snap = bc.autostart_snapshot()
            base = bc.load_autostart_baseline()
            if base is not None:
                # 守护没运行的这段时间（比如关机期间装了软件）发生的变化，补报一次
                self.report_autostart(bc.autostart_diff(base, self.as_snap), offline=True)
            bc.save_autostart_baseline(self.as_snap)
            self.as_watch = bc.AutostartWatcher(watch_tasks=bc.is_admin())
            self.as_watch.start()
            self.as_full_at = time.time()
            self.as_timer.start(1000)
            glog("自启监控已启动，盯住 %d 处：%s" % (len(self.as_watch.watching),
                                              "；".join(self.as_watch.watching)))
        except Exception as e:
            glog("自启监控启动失败：%r" % (e,))
            self.as_watch = None

    def check_autostart(self):
        w = self.as_watch
        if not w or self.as_snap is None:
            return
        now = time.time()
        # 安装程序往往连写好几个值：最后一次变化后静默 1.5 秒再对比，免得一次安装报好几回。
        # 另外每 10 分钟无条件对比一次，防止哪次通知漏了
        due = (w.dirty_at and now - w.dirty_at > 1.5) or now - self.as_full_at > 600
        if not due:
            return
        w.dirty_at = 0.0
        self.as_full_at = now
        try:
            new = bc.autostart_snapshot(with_tasks=bc.is_admin())
        except Exception as e:
            glog("自启快照失败：%r" % (e,))
            return
        rows = bc.autostart_diff(self.as_snap, new)
        self.as_snap = new
        bc.save_autostart_baseline(new)
        self.report_autostart(rows)

    def report_autostart(self, rows, offline=False):
        if not rows:
            return
        rows = [bc.describe_autostart_change(r) for r in rows]
        bc.append_autostart_watch(rows)
        for r in rows:
            glog("自启%s「%s」 来源=%s 命令=%s%s" % (
                bc.AUTOSTART_CHANGE_CN.get(r["change"], r["change"]), r.get("name"),
                r.get("source"), (r.get("cmd") or "")[:160],
                ("  特征库：" + r["adware"]) if r.get("adware") else ""))
        if len(rows) == 1:
            r = rows[0]
            title = "开机启动%s：%s" % (bc.AUTOSTART_CHANGE_CN.get(r["change"], ""), r.get("name"))
            msg = "%s\n%s" % (r.get("source") or "", (r.get("cmd") or "")[:120])
            if r.get("adware"):
                msg += "\n命中流氓软件特征库：%s" % r["adware"]
        else:
            title = "%s有 %d 项开机启动变化" % ("关机期间" if offline else "", len(rows))
            msg = "、".join((r.get("name") or "")[:20] for r in rows[:5])
            if len(rows) > 5:
                msg += " 等"
        msg += "\n点这里查看和处理"
        icon = QSystemTrayIcon.Warning if any(r.get("adware") for r in rows) \
            else QSystemTrayIcon.Information
        try:
            self.tray.showMessage(title, msg, icon, 10000)
        except Exception:
            pass

    def open_main(self, page="popup"):
        """拉起主程序并跳到某一页（主程序自己会请求管理员权限）。"""
        try:
            exe = bc._pythonw_path()
            subprocess.Popen([exe, os.path.join(HERE, "boot_doctor.py"), "--page=" + page],
                             cwd=HERE, creationflags=0x08000000)
        except Exception as e:
            glog("打开主程序失败：%r" % (e,))

    # ---------------- 新进程提醒 ----------------
    def check_processes(self):
        """对比进程列表：第一次只建基线（守护启动前就在跑的不报），之后出现的新进程逐个判定。"""
        self.reload_rules()          # 开关改了立即生效：规则文件没变时只是一次 stat，几乎没有开销
        if bc.adware_db_reload_if_changed():     # 主程序自动更新了特征库：守护不用重启就用上新库
            glog("特征库文件已更新，已重新加载")
        if self.paused or not self.rules.get("watch_process", True):
            return
        try:
            procs = bc.enum_processes()
        except Exception as e:
            glog("枚举进程失败：%r" % (e,))
            return
        now = time.time()
        alive = {(p["pid"], p["ctime"]) for p in procs}
        if not self.proc_baseline:
            self.proc_seen = {k: now for k in alive}
            self.proc_baseline = True
            glog("新进程监控已启动，基线 %d 个进程（之前就在运行的不提醒）" % len(alive))
            return
        strict = bool(self.rules.get("watch_strict"))
        rows = []
        for p in procs:
            key = (p["pid"], p["ctime"])
            if key in self.proc_seen:
                continue
            self.proc_seen[key] = now
            try:
                v = bc.judge_new_process(p, strict=strict)
            except Exception as e:
                glog("判定进程失败 %s：%r" % (p.get("name"), e))
                continue
            if v:
                rows.append(self.handle_new_process(v, now))
        self.proc_seen = {k: t for k, t in self.proc_seen.items() if k in alive}   # 只留还活着的
        for pth in [k for k, t in self.proc_alerted.items() if now - t > 3600]:
            self.proc_alerted.pop(pth, None)
        rows = [r for r in rows if r]
        if rows:
            bc.append_proc_watch(rows)

    def handle_new_process(self, v, now):
        """一个新进程命中了：记日志，必要时自动结束，托盘提醒。返回要写进记录的行。"""
        path = v["path"]
        action = "提醒"
        if (v["level"] == "adware" and self.rules.get("auto_kill_adware")
                and bc.proc_kill_allowed(v["name"], path, int(v["pid"]))):
            ok, msg = bc.kill_process(int(v["pid"]), int(v["ctime"]), path)
            action = "已结束" if ok and "已结束" in msg else "结束失败"
            glog("新进程「%s」命中特征库，自动结束：%s" % (v["name"], msg))
        else:
            glog("新进程「%s」%s：%s  %s" % (v["name"], bc.PROC_LEVEL_CN.get(v["level"], v["level"]),
                                          v["why"], path))
        row = {"t": time.strftime("%Y-%m-%d %H:%M:%S"), "level": v["level"], "sev": v["sev"],
               "label": v.get("label") or "", "name": v["name"], "path": path, "why": v["why"],
               "action": action}
        self.proc_alerts += 1
        if now - self.proc_alerted.get(path.lower(), 0) > 600:      # 同一个程序 10 分钟内只弹一次
            self.proc_alerted[path.lower()] = now
            title = "新启动的程序：%s" % v["name"]
            if action == "已结束":
                title = "已结束流氓软件进程：%s" % v["name"]
            msg = "%s\n%s\n%s\n点这里查看" % (v.get("label") or bc.PROC_LEVEL_CN.get(v["level"], ""),
                                            v["why"][:80], path[-70:])
            try:
                self.tray.showMessage(title, msg, QSystemTrayIcon.Warning, 10000)
            except Exception:
                pass
        return row

    # ---------------- 事件钩子 ----------------
    def install_hook(self):
        try:
            self._hook_proc = WinEventProc(self.on_win_event)
            self._hook = _u32.SetWinEventHook(
                EVENT_OBJECT_SHOW, EVENT_OBJECT_SHOW, None, self._hook_proc, 0, 0,
                WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS)
        except Exception as e:
            glog("安装事件钩子失败，退回纯轮询：%r" % (e,))
            self._hook = None
        if not self._hook:
            self._hook_proc = None

    def poll_interval(self):
        base = max(600, int(self.rules.get("poll_ms") or 1200))
        # 有钩子时轮询只是兜底（补漏 + 写窗口记录），放慢到 5 秒省 CPU
        return max(base, 5000) if self._hook else base

    def on_win_event(self, _hook, _event, hwnd, id_object, id_child, _tid, _ms):
        """EVENT_OBJECT_SHOW 回调。这里只做最便宜的过滤，判定延后到 Qt 定时器里。

        ctypes 回调里抛异常不会传出去，只会打印到（不存在的）控制台，所以整段兜住。
        """
        try:
            if self.paused or not hwnd:
                return
            if id_object != OBJID_WINDOW or id_child != CHILDID_SELF:
                return                              # 子控件 / 光标 / 插入符，占事件的绝大多数
            if _u32.GetAncestor(hwnd, GA_ROOT) != hwnd:
                return                              # 只看顶层窗口
            h = int(hwnd)
            if h in self._pending:
                return
            self._pending.add(h)
            # 稍等一下再判定：不少弹窗先 Show 再设标题 / 挪位置
            QTimer.singleShot(150, lambda h=h: self.check_one(h))
        except Exception:
            pass

    def check_one(self, hwnd):
        self._pending.discard(hwnd)
        if self.paused:
            return
        self.reload_rules()
        try:
            w = bc._win_item(hwnd, include_hidden=False)
        except Exception:
            w = None
        if not w:
            return
        rows = []
        self.handle(w, time.time(), rows)
        try:
            bc.append_popup_watch(rows)
        except Exception:
            pass

    def reload_rules(self):
        """规则文件没改就不重读（以前每轮都 json.load 一次）。"""
        try:
            mt = os.path.getmtime(bc.POPUP_RULES_PATH)
        except OSError:
            mt = None
        if mt != self._rules_mtime:
            self._rules_mtime = mt
            self.rules = bc.load_popup_rules()

    # ---------------- 托盘动作 ----------------
    def toggle_pause(self):
        self.paused = not self.paused
        self.act_pause.setText("恢复拦截" if self.paused else "暂停拦截")
        self.act_state.setText("状态：已暂停" if self.paused else "状态：守护中")
        self.tray.setIcon(make_icon("#8a8f98" if self.paused else "#2f6feb"))
        self.update_tip()
        glog("暂停" if self.paused else "恢复")

    def update_tip(self):
        tip = "弹窗拦截 · %s · 已拦 %d 个" % ("已暂停" if self.paused else "守护中", self.blocked)
        if self.failed:
            tip += " · %d 个关不掉（见日志）" % self.failed
        self.tray.setToolTip(tip)

    def open_log(self):
        try:
            os.startfile(GL)
        except Exception:
            pass

    def open_rules(self):
        try:
            os.startfile(bc.POPUP_RULES_PATH)
        except Exception:
            pass

    def toggle_autostart(self, on):
        ok, msg = bc.set_guard_autostart(bool(on))
        if not ok:
            self.act_boot.blockSignals(True)
            self.act_boot.setChecked(not on)
            self.act_boot.blockSignals(False)
        glog("开机自启 -> %s（%s）" % ("开" if on else "关", msg))
        try:
            self.tray.showMessage("弹窗拦截", msg, QSystemTrayIcon.Information, 3000)
        except Exception:
            pass

    def quit_guard(self):
        glog("守护退出（手动），累计拦截 %d" % self.blocked)
        # 手动退出 = 不想拦了：把总开关关掉，避免下次登录被自启又拉起来
        bc.set_popup_enabled(False)
        self.cleanup()
        self.tray.hide()
        self.quit()

    def cleanup(self):
        if getattr(self, "as_watch", None):
            try:
                self.as_watch.stop()
            except Exception:
                pass
            self.as_watch = None
        if self._hook:
            try:
                _u32.UnhookWinEvent(self._hook)
            except Exception:
                pass
            self._hook = None
        # 只删属于自己的 pid 文件：新守护可能已经覆盖写过了
        if bc.guard_pid() in (0, os.getpid()):
            try:
                os.remove(bc.GUARD_PID_PATH)
            except Exception:
                pass

    # ---------------- 主循环 ----------------
    def check_stop(self):
        """主程序要求停止（写了 stop 标记）。"""
        if not os.path.exists(bc.GUARD_STOP_PATH):
            return
        try:
            os.remove(bc.GUARD_STOP_PATH)
        except Exception:
            pass
        glog("收到停止标记，退出")
        self.cleanup()
        self.quit()

    def tick(self, force=False):
        """全量扫一遍：有事件钩子时是兜底，没有钩子时就是主力。"""
        if self.paused and not force:
            return
        self.reload_rules()                  # 规则可能被主程序改过
        if bc.adware_db_reload_if_changed():
            glog("特征库文件已更新，已重新加载")
        want = self.poll_interval()
        if self.timer.interval() != want:
            self.timer.setInterval(want)
        try:
            wins = bc.enum_popups(include_hidden=False, limit=300)
        except Exception as e:
            glog("枚举窗口失败：%r" % (e,))
            return
        now = time.time()
        rows = []
        for w in wins:
            self.handle(w, now, rows)
        # 清理过期记录，避免字典无限增长
        if len(self.closed) > 500:
            self.closed = {k: v for k, v in self.closed.items() if now - v[0] < 600}
        if len(self.seen) > 800:
            self.seen = {k: v for k, v in self.seen.items() if now - v < 3600}
        try:
            bc.append_popup_watch(rows)
        except Exception:
            pass

    def handle(self, w, now, rows):
        """单个窗口：先记一笔窗口记录，再判定要不要关。轮询和事件钩子共用这一段。"""
        # 窗口记录（火绒同款）：把见过的窗口留一笔，事后能回溯"刚才是谁弹的"
        try:
            t = (w.get("title") or "").strip()
            if t:
                key = ((w.get("proc") or "") + "|" + t)[:200]
                if now - self.seen.get(key, 0) > 600:
                    self.seen[key] = now
                    if len(rows) < 20:
                        rows.append({
                            "t": time.strftime("%m-%d %H:%M:%S"),
                            "title": t[:80], "proc": w.get("proc") or "",
                            "cls": w.get("cls") or "", "judge": w.get("judge") or "",
                            "path": (w.get("path") or "")[:200],
                        })
        except Exception:
            pass
        try:
            ok, why = bc.should_close_popup(w, self.rules)
        except Exception:
            return
        if not ok:
            return
        hwnd = int(w.get("hwnd") or 0)
        if not hwnd:
            return
        last = self.closed.get(hwnd)
        if last and now - last[0] < 30:
            return
        self.closed[hwnd] = (now, (last[1] + 1) if last else 1)
        title = (w.get("title") or "")[:60]
        if not _u32.PostMessageW(hwnd, WM_CLOSE, 0, 0):
            # 以前这里不看返回值，发失败了也算「已拦」，统计和日志都是虚的
            err = ctypes.get_last_error()
            self.failed += 1
            reason = ("权限不足：对方以管理员身份运行，守护是普通权限（UIPI）"
                      if err == ERROR_ACCESS_DENIED else "错误码 %d" % err)
            glog("关闭失败「%s」 proc=%s pid=%s %s" % (title, w.get("proc"), w.get("pid"), reason))
            self.update_tip()
            return
        self.blocked += 1
        glog("拦截「%s」 proc=%s pid=%s 原因=%s" % (title, w.get("proc"), w.get("pid"), why))
        self.update_tip()
        # PostMessage 成功只代表消息进了队列；1.5 秒后看窗口是不是真没了
        QTimer.singleShot(1500, lambda h=hwnd, t=title, p=w.get("proc"): self.verify_closed(h, t, p))

    def verify_closed(self, hwnd, title, proc):
        try:
            if _u32.IsWindow(hwnd) and _u32.IsWindowVisible(hwnd):
                glog("已发送关闭但窗口还在「%s」 proc=%s：对方忽略了 WM_CLOSE，"
                     "建议直接禁用它的启动项或卸载" % (title, proc))
        except Exception:
            pass


_MUTEX = None


def single_instance():
    """同名互斥体，防止点两次开两个守护互相打架。"""
    global _MUTEX
    try:
        # use_last_error=True：ctypes 在调用返回的那一刻就把 LastError 存进线程私有副本，
        # 不会被解释器在两次外部调用之间的其他 API 改掉。比手动 SetLastError(0) 可靠
        ctypes.set_last_error(0)
        _MUTEX = _k32.CreateMutexW(None, False, "Local\\BootDoctorPopupGuard")
        return ctypes.get_last_error() != ERROR_ALREADY_EXISTS
    except Exception:
        return True


def main():
    if not single_instance():
        glog("已有守护在运行，本次退出")
        return 0
    try:
        app = Guard(sys.argv)
    except Exception:
        import traceback
        glog("启动失败：\n" + traceback.format_exc())
        try:
            QMessageBox.critical(None, "弹窗拦截", "守护启动失败，详情见 %s" % GL)
        except Exception:
            pass
        return 1
    return app.exec_()


if __name__ == "__main__":
    sys.exit(main())
