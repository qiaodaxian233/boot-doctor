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
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import boot_core as bc  # noqa: E402
from PyQt5.QtCore import Qt, QTimer  # noqa: E402
from PyQt5.QtGui import QColor, QFont, QIcon, QPainter, QPixmap  # noqa: E402
from PyQt5.QtWidgets import (QAction, QApplication, QMenu, QMessageBox,  # noqa: E402
                             QSystemTrayIcon)

GL = os.path.join(HERE, "_logs", "popup_guard.log")
WM_CLOSE = 0x0010
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
        self.skipped = 0
        self.paused = False
        self.rules = bc.load_popup_rules()
        self.paused = not bool(self.rules.get("enabled"))
        if self.paused and SILENT:
            # 开机自启模式下「总开关」是关的：直接退出，别留个灰图标占托盘
            glog("拦截已关闭（enabled=false），本次静默退出")
            raise SystemExit(0)

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

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.tick)
        self.timer.start(max(600, int(self.rules.get("poll_ms") or 1200)))

        try:
            os.makedirs(os.path.dirname(bc.GUARD_PID_PATH), exist_ok=True)
            with open(bc.GUARD_PID_PATH, "w", encoding="utf-8") as fp:
                fp.write(str(os.getpid()))
        except Exception:
            pass
        self.update_tip()
        glog("守护启动 pid=%d 规则 block=%d allow=%d auto=%s"
             % (os.getpid(), len(self.rules.get("block") or []),
                len(self.rules.get("allow") or []), self.rules.get("auto_adware")))
        self.tick(force=True)

    # ---------------- 托盘动作 ----------------
    def toggle_pause(self):
        self.paused = not self.paused
        self.act_pause.setText("恢复拦截" if self.paused else "暂停拦截")
        self.act_state.setText("状态：已暂停" if self.paused else "状态：守护中")
        self.tray.setIcon(make_icon("#8a8f98" if self.paused else "#2f6feb"))
        self.update_tip()
        glog("暂停" if self.paused else "恢复")

    def update_tip(self):
        self.tray.setToolTip("弹窗拦截 · %s · 已拦 %d 个"
                             % ("已暂停" if self.paused else "守护中", self.blocked))

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
        try:
            os.remove(bc.GUARD_PID_PATH)
        except Exception:
            pass

    # ---------------- 主循环 ----------------
    def tick(self, force=False):
        # 主程序要求停止
        if os.path.exists(bc.GUARD_STOP_PATH):
            try:
                os.remove(bc.GUARD_STOP_PATH)
            except Exception:
                pass
            glog("收到停止标记，退出")
            self.cleanup()
            self.quit()
            return
        if self.paused and not force:
            return
        # 规则可能被主程序改过，每轮重读（文件很小）
        self.rules = bc.load_popup_rules()
        if self.timer.interval() != int(self.rules.get("poll_ms") or 1200):
            self.timer.setInterval(max(600, int(self.rules.get("poll_ms") or 1200)))
        try:
            wins = bc.enum_popups(include_hidden=False, limit=300)
        except Exception as e:
            glog("枚举窗口失败：%r" % (e,))
            return
        now = time.time()
        rows = []
        for w in wins:
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
                continue
            if not ok:
                continue
            hwnd = int(w.get("hwnd") or 0)
            if not hwnd:
                continue
            last = self.closed.get(hwnd)
            if last and now - last[0] < 30:
                continue
            self.closed[hwnd] = (now, (last[1] + 1) if last else 1)
            try:
                ctypes.windll.user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)
            except Exception as e:
                glog("关闭失败 hwnd=%s %r" % (hwnd, e))
                continue
            self.blocked += 1
            glog("拦截「%s」 proc=%s pid=%s 原因=%s"
                 % ((w.get("title") or "")[:60], w.get("proc"), w.get("pid"), why))
            self.update_tip()
        # 清理过期记录，避免字典无限增长
        if len(self.closed) > 500:
            self.closed = {k: v for k, v in self.closed.items() if now - v[0] < 600}
        if len(self.seen) > 800:
            self.seen = {k: v for k, v in self.seen.items() if now - v < 3600}
        try:
            bc.append_popup_watch(rows)
        except Exception:
            pass


_MUTEX = None


def single_instance():
    """同名互斥体，防止点两次开两个守护互相打架。"""
    global _MUTEX
    try:
        k32 = ctypes.windll.kernel32
        # CreateMutexW 成功时不会把 LastError 清零，线程里可能残留上一次的 183，
        # 不先清零会把「首次启动」误判成「已有实例」直接退出
        k32.SetLastError(0)
        _MUTEX = k32.CreateMutexW(None, False, "Local\\BootDoctorPopupGuard")
        return k32.GetLastError() != 183   # ERROR_ALREADY_EXISTS
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
