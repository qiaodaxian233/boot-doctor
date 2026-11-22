# -*- coding: utf-8 -*-
"""每一页各截一张（浅色 + 深色），CI 里用真实采集数据跑，结果放 _ci_shots/。

本机也能跑：python _ui_pages_shot.py   （不改任何系统设置，跑完把主题设置恢复原样）
"""
import os
import sys
import time

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)
os.environ.setdefault("BOOTDOC_NOSCAN", "1")

import boot_core as bc  # noqa: E402
import boot_doctor as bd  # noqa: E402
from PyQt5.QtCore import Qt  # noqa: E402
from PyQt5.QtGui import QFont  # noqa: E402
from PyQt5.QtWidgets import QApplication  # noqa: E402

OUT = os.path.join(BASE, "_ci_shots")
bd.USE_ACRYLIC = False          # 亚克力是窗外模糊，截图抓不到，固定走伪毛玻璃档


def pump(app, sec=0.3):
    end = time.time() + sec
    while time.time() < end:
        app.processEvents()
        time.sleep(0.02)


def main():
    os.makedirs(OUT, exist_ok=True)
    old_theme = bc.get_setting("theme", "light")
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    app = QApplication(sys.argv)
    app.setStyle(bd.GlassItemStyle("Fusion"))
    bd.use_theme("light")
    app.setFont(QFont("Microsoft YaHei UI", 9))
    app.setStyleSheet(bd.build_qss())
    t = time.time()
    raw = bc.collect()
    res = bc.analyze(raw)
    print("collect+analyze %.2fs, findings=%d" % (time.time() - t, len(res.get("findings") or [])))
    win = bd.MainWindow(autoscan=False)
    win.resize(1360, 860)
    win.show()
    win.on_scan_done(raw, res)
    try:
        for theme in ("light", "dark"):
            if theme == "dark":
                win.set_theme("dark")
            for key in ("scan", "popup", "notify", "backup"):
                win.show_page(key)
                pump(app)
                p = os.path.join(OUT, "%s_%s.png" % (theme, key))
                win.grab().save(p)
                print("saved", p)
    finally:
        bc.set_setting("theme", old_theme)
        win.close()


if __name__ == "__main__":
    main()
