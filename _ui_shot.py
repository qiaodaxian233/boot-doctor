# -*- coding: utf-8 -*-
"""真实窗口截图（真实字体）：短命窗口，抓完即退。"""
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

CACHE = os.path.join(BASE, "_ui_shot_cache.json")

# 截图固定走"伪毛玻璃"档：DWM 亚克力是窗外模糊，抓图抓不到，而且离屏平台拿不到真句柄。
# 真机观感另用 _ui_glass_live.py 抓屏验证。
bd.USE_ACRYLIC = False


def main():
    with open(CACHE, "r", encoding="utf-8") as fp:
        raw = json.load(fp)
    res = bc.analyze(raw)

    app = QApplication(sys.argv)
    app.setStyle(bd.GlassItemStyle("Fusion"))
    bd.use_theme("light")
    app.setFont(QFont("Microsoft YaHei UI", 9))
    app.setStyleSheet(bd.build_qss())
    win = bd.MainWindow(autoscan=False)
    win.show()
    win.on_scan_done(raw, res)

    def pick():
        for i in range(win.tree.topLevelItemCount()):
            p = win.tree.topLevelItem(i)
            for j in range(p.childCount()):
                ch = p.child(j)
                f = win._finding_of_item(ch)
                if f and f.get("app", {}).get("exists") and f.get("cat") == "延迟启动":
                    win.tree.setCurrentItem(ch)
                    return

    def shoot():
        pick()
        app.processEvents()
        win.grab().save(os.path.join(BASE, "_ui_live_light.png"))
        win.set_theme("dark")
        pick()
        win.repaint()
        app.processEvents()
        QTimer.singleShot(600, shoot_dark)

    orig_theme = "light"   # 本脚本固定先渲染浅色，跑完把设置恢复成浅色，别污染用户配置

    def shoot_dark():
        win.repaint()
        app.processEvents()
        win.grab().save(os.path.join(BASE, "_ui_live_dark.png"))
        from PyQt5.QtCore import QTimer as _T
        d = bd.BootTrendDialog(win, win._raw)
        d.show()
        d.grab().save(os.path.join(BASE, "_ui_live_trend.png"))
        d.close()
        dlg = bd.SettingsDialog(win)
        dlg.resize(560, 400)
        dlg.show()
        QTimer.singleShot(300, lambda: (dlg.grab().save(
            os.path.join(BASE, "_ui_live_settings.png")), dlg.close(),
            bc.set_setting("theme", orig_theme), app.quit()))

    QTimer.singleShot(1200, shoot)
    app.exec_()
    print("ok")


if __name__ == "__main__":
    main()
