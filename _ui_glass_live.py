# -*- coding: utf-8 -*-
"""真机观感验证：开 DWM 亚克力，抓真实屏幕（能看到窗外模糊），浅深各一张。"""
import json
import os
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)

import boot_core as bc  # noqa: E402
import boot_doctor as bd  # noqa: E402
from PyQt5.QtCore import QTimer  # noqa: E402
from PyQt5.QtGui import QFont  # noqa: E402
from PyQt5.QtWidgets import QApplication  # noqa: E402

with open(os.path.join(BASE, "_ui_shot_cache.json"), "r", encoding="utf-8") as fp:
    RAW = json.load(fp)
RES = bc.analyze(RAW)

app = QApplication(sys.argv)
app.setStyle(bd.GlassItemStyle("Fusion"))
bd.use_theme("dark")
app.setFont(QFont("Microsoft YaHei UI", 9))
app.setStyleSheet(bd.build_qss())
win = bd.MainWindow(autoscan=False)
win.resize(1180, 780)
win.move(60, 40)
win.show()
win.on_scan_done(RAW, RES)
win.raise_()
win.activateWindow()
print("acrylic =", getattr(win, "_glass", None), "| _ACRYLIC_ON =", bd._ACRYLIC_ON)
print("enabled:", "scan", win.btn_scan.isEnabled(), "ai", win.btn_ai.isEnabled(),
      "apply", win.btn_apply.isEnabled(), "active", win.isActiveWindow())


def grab(tag):
    scr = app.primaryScreen()
    g = win.frameGeometry()
    dpr = scr.grabWindow(0).width() / float(scr.size().width())
    pm = scr.grabWindow(0, int(g.x() * dpr), int(g.y() * dpr),
                        int(g.width() * dpr), int(g.height() * dpr))
    pm.save(os.path.join(BASE, "_ui_glass_%s.png" % tag))
    print("saved", tag, pm.width(), pm.height())


def step2():
    grab("dark")
    win.set_theme("light")
    win.repaint()
    app.processEvents()
    QTimer.singleShot(900, step3)


def step3():
    grab("light")
    app.quit()


QTimer.singleShot(1800, step2)
app.exec_()
