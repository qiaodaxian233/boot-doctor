# -*- coding: utf-8 -*-
"""实测：体检耗时 + 等待动画是否真的在动。

抓「状态栏文字」在扫描期间的变化，验证：
  1. 有转圈帧（⠋⠙… 每 120ms 换一格）
  2. 有已用秒数在走
  3. 步骤文案跟着阶段变
  4. 结束后进度条交还给评分（range 回到 0..100，值为分数）
"""
import sys
import time

sys.path.insert(0, ".")
from PyQt5.QtWidgets import QApplication  # noqa: E402

import boot_core as bc  # noqa: E402
import boot_doctor as bd  # noqa: E402


def main():
    app = QApplication([])
    app.setStyle(bd.GlassItemStyle("Fusion"))
    bd.use_theme("light")
    app.setStyleSheet(bd.build_qss())
    win = bd.MainWindow(autoscan=False)
    win.show()
    app.processEvents()

    print("=== 开始体检（同时每 0.25s 采样一次状态栏）===")
    t0 = time.perf_counter()
    win.start_scan()
    samples = []
    while time.perf_counter() - t0 < 30:
        app.processEvents()
        samples.append((round(time.perf_counter() - t0, 2), win.lbl_status.text()))
        if win.scan_worker is not None and not win.scan_worker.isRunning():
            break
        time.sleep(0.25)
    app.processEvents()
    total = time.perf_counter() - t0

    print("总耗时 %.2fs" % total)
    print("状态栏采样（前 14 条）：")
    for t, s in samples[:14]:
        print("  %5.2fs  %s" % (t, s))
    print("状态栏采样（后 6 条）：")
    for t, s in samples[-6:]:
        print("  %5.2fs  %s" % (t, s))

    spin = set("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
    frames = {ch for _t, s in samples for ch in s if ch in spin}
    print("\n出现的转圈帧：%d 种 %s" % (len(frames), "".join(sorted(frames))))
    secs = [s.split()[-1] for _t, s in samples if s.split() and s.split()[-1].endswith("s")]
    print("出现的秒数：%s" % secs[:10])
    print("结束后：bar range=%s value=%s 分数=%s 状态=%s"
          % ((win.bar.minimum(), win.bar.maximum()), win.bar.value(),
             win.lbl_score.text(), win.lbl_status.text()))
    print("结果行数：%d  发现项：%d" % (win.tree.topLevelItemCount(),
                                       len((win.result or {}).get("findings") or [])))
    win.close()


if __name__ == "__main__":
    main()
