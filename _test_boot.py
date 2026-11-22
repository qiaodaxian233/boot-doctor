# -*- coding: utf-8 -*-
"""开机体检大师 · 离屏自测

覆盖：
  1) 规则引擎 + 计分（合成数据）
  2) 备份 / 试运行修复 / restore.reg 生成（全程不写真实系统设置）
  3) GUI 离屏 Smoke（真点击：勾选切换 -> 按钮计数更新、详情渲染）

运行：python _test_boot.py   （QT_QPA_PLATFORM=offscreen 自动设置）
"""
import ctypes
import json
import os
import shutil
import sys
import tempfile
import unittest

os.environ["QT_QPA_PLATFORM"] = "offscreen"
BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)


def _visible_windows(pid):
    """某个进程拥有的可见顶层窗口数量（用于断言"后台运行不带界面"）。"""
    u = ctypes.WinDLL("user32", use_last_error=True)
    u.GetWindowThreadProcessId.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
    u.IsWindowVisible.argtypes = [ctypes.c_void_p]
    n = []

    def cb(hwnd, _l):
        p = ctypes.c_ulong(0)
        u.GetWindowThreadProcessId(hwnd, ctypes.byref(p))
        if p.value == pid and u.IsWindowVisible(hwnd):
            n.append(hwnd)
        return True

    u.EnumWindows(ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p,
                                     ctypes.c_void_p)(cb), 0)
    return len(n)

import boot_core as bc  # noqa: E402


def fake_raw():
    return {
        "ts": "2026-10-15 12:00:00", "admin": True,
        "startup": [
            {"name": "QuarkUpdaterTaskUser1.0.0.11", "cmd": "updater.exe", "source": "用户 Run",
             "kind": "run", "hive": "HKCU", "subkey": None, "enabled": True},
            {"name": "MyApp", "cmd": "app.exe", "source": "用户 Run",
             "kind": "run", "hive": "HKCU", "subkey": None, "enabled": True},
        ],
        "services": [
            {"name": "360Box64", "start": 1, "type": 2,
             "image": "system32\\DRIVERS\\360Box64.sys", "disp": ""},
            {"name": "ESRV_SVC_QUEENCREEK", "start": 2, "type": 16, "image": "", "disp": ""},
            {"name": "Intel(R) Platform License Manager Service", "start": 2,
             "type": 16, "image": "", "disp": ""},
            {"name": "Razer Game Manager Service 3", "start": 2, "type": 16,
             "image": "C:\\Program Files (x86)\\Razer\\Razer Services\\GMS3\\GameManagerService3.exe",
             "disp": ""},
        ],
        "power": {"hiberboot": 0, "hibernate": 0, "enable_lua": 0, "hiberfil": False},
        "sys": {"osName": "TestOS", "build": "19045", "bootTime": "2026-10-15 11:00:00",
                "ramGB": 16, "svcAuto": 120, "svcAutoRun": 110, "svcAutoDown": [],
                "disks": [], "vols": [{"letter": "C", "free": 100, "total": 900}], "tasks": []},
        "events": {"boots": [{"time": "2026-10-15 11:00", "boot": 95, "main": 80, "post": 15,
                              "profile": 30, "explorer": 25, "apps": 20}],
                   "slow": [],
                   "scm": [{"id": 7009, "time": "10-15 11:00",
                            "msg": "等待 Intel(R) Platform License Manager Service "
                                   "服务的连接超时(120000 毫秒)。"}],
                   "c7005": 0, "c7005_7d": 0, "c7023": 0},
        "filters": [],
    }


def fake_raw_multi():
    """多选 / 批量用例专用：保证至少 3 条普通自启项。

    以前这两个用例靠本机已有的 BootDoctor-Delay 任务凑数，换一台干净机器（CI）就不够 3 条。
    """
    raw = fake_raw()
    for n in ("UnitTestToolA", "UnitTestToolB", "UnitTestToolC"):
        raw["startup"].append({"name": n, "cmd": n.lower() + ".exe", "source": "用户 Run",
                               "kind": "run", "hive": "HKCU", "subkey": None, "enabled": True})
    return raw


class TestAnalyze(unittest.TestCase):
    def test_rules_and_score(self):
        res = bc.analyze(fake_raw())
        ids = {f["id"] for f in res["findings"]}
        for expect in ("boot_slow", "login_phase", "fast_startup", "updater_startups",
                       "residue_360", "residue_intel_sur", "svc_intel_plm",
                       "delay_svc@Razer Game Manager Service 3"):
            self.assertIn(expect, ids)
        self.assertTrue(any(i.startswith("delay_item@MyApp") for i in ids))
        # 服务必须逐条可勾选（不能是"一键整批"）
        svc_rows = [f for f in res["findings"] if (f.get("fix") or {}).get("type") == "svc_delay"]
        self.assertGreaterEqual(len(svc_rows), 1)
        self.assertTrue(all(len(f["fix"]["items"]) == 1 for f in svc_rows))
        self.assertFalse(any(f["id"] == "delay_svc_batch" for f in res["findings"]))
        self.assertTrue(0 <= res["score"] <= 100)
        self.assertLess(res["score"], 100)
        for f in res["findings"]:
            if f.get("fix"):
                self.assertIn(f["fix"]["type"], bc.FIX_DESC)

    def test_updater_pattern(self):
        self.assertTrue(bc._is_updater_like({"name": "XQuarkUpdater", "cmd": ""}))
        self.assertTrue(bc._is_updater_like({"name": "app", "cmd": "auto-update.exe"}))
        self.assertFalse(bc._is_updater_like({"name": "MyApp", "cmd": "app.exe"}))

    def test_timeout_name_extract(self):
        out = bc._extract_timeout_names([
            {"id": 7009, "msg": "等待 Some Service 服务的连接超时(120000 毫秒)。"}])
        self.assertIn("Some Service", out)

    def test_7005_hist_vs_active(self):
        import datetime as _dt2
        raw = fake_raw()
        raw["events"]["c7005"] = 500
        raw["events"]["c7005_1h"] = 0
        raw["events"]["last7005"] = (_dt2.datetime.now()
                                     - _dt2.timedelta(minutes=40)).strftime("%Y-%m-%d %H:%M:%S")
        res = bc.analyze(raw)
        ids = {f["id"] for f in res["findings"]}
        self.assertIn("reg_corrupt_hist", ids)
        self.assertNotIn("reg_corrupt", ids)

        raw["events"]["last7005"] = (_dt2.datetime.now()
                                     - _dt2.timedelta(minutes=1)).strftime("%Y-%m-%d %H:%M:%S")
        raw["events"]["c7005_1h"] = 50
        res2 = bc.analyze(raw)
        ids2 = {f["id"] for f in res2["findings"]}
        self.assertIn("reg_corrupt", ids2)
        self.assertNotIn("reg_corrupt_hist", ids2)


class TestBackupDryRun(unittest.TestCase):
    def test_backup_and_dry_apply(self):
        with tempfile.TemporaryDirectory() as td:
            findings = [
                {"id": "t1", "title": "T1",
                 "fix": {"type": "svc_start", "risk": "safe", "items": {"luafv": 3}}},
                {"id": "t2", "title": "T2",
                 "fix": {"type": "startup_off", "risk": "safe",
                         "items": [{"hive": "HKCU", "kind": "run",
                                    "name": "UnitTest_NotExistItem"}]}},
                {"id": "t3", "title": "T3",
                 "fix": {"type": "svc_delay", "risk": "safe", "items": ["UnitTest_NotExistSvc"]}},
                {"id": "t4", "title": "T4",
                 "fix": {"type": "startup_delay", "risk": "confirm",
                         "items": [{"hive": "HKCU", "kind": "run", "name": "UnitTest_DelayItem",
                                    "cmd": r"C:\Windows\System32\notepad.exe"}]}},
                {"id": "t5", "title": "T5",
                 "fix": {"type": "delay_task_set", "risk": "safe",
                         "items": [{"task": "BootDoctor-Delay-UnitTest_NotExistTask",
                                    "exe": r"C:\Windows\System32\notepad.exe", "args": "",
                                    "old_delay": 60}]}},
            ]
            bdir = bc.make_backup(findings, backup_root=td, tag="test")
            self.assertTrue(os.path.isfile(os.path.join(bdir, "snapshot.json")))
            self.assertTrue(os.path.isfile(os.path.join(bdir, "restore-all.reg")))
            with open(os.path.join(bdir, "snapshot.json"), encoding="utf-8") as f:
                snap = json.load(f)
            self.assertEqual(len(snap["items"]), 5)
            svc = next(i for i in snap["items"] if i["kind"] == "service")
            self.assertIsInstance(svc["old"], int)
            self.assertTrue(any(i["kind"] == "svc_delay" for i in snap["items"]))
            sd = next(i for i in snap["items"] if i["kind"] == "startup_delay")
            self.assertEqual(sd["task"], "BootDoctor-Delay-UnitTest_DelayItem")
            dt = next(i for i in snap["items"] if i["kind"] == "delay_task")
            self.assertEqual(dt["old_delay"], 60)

            results = bc.apply_fixes(findings, bdir, dry_run=True)
            self.assertEqual(len(results), 5)
            self.assertTrue(all(r["ok"] for r in results))
            joined = "\n".join(m for r in results for m in r["msgs"])
            self.assertIn("[试运行]", joined)

            with open(os.path.join(bdir, "restore-all.reg"), encoding="utf-16") as f:
                reg = f.read()
            self.assertIn("HKEY_LOCAL_MACHINE", reg)
            self.assertIn('"Start"=dword', reg)
            self.assertIn('"DelayedAutoStart"=dword', reg)

            res2 = bc.restore_backup(bdir, dry_run=True)
            self.assertTrue(all(r["ok"] for r in res2))

    def test_list_backups_smoke(self):
        self.assertIsInstance(bc.list_backups(), list)


class TestResolvePaths(unittest.TestCase):
    def test_resolve_env_and_args(self):
        rp = bc.resolve_image_path(r"%SystemRoot%\system32\svchost.exe -k netsvcs -p")
        self.assertNotIn("%", rp)
        self.assertTrue(rp.lower().endswith(r"\system32\svchost.exe"), rp)
        rp2 = bc.resolve_image_path('"C:\\Program Files\\X\\a.exe" -k run')
        self.assertEqual(rp2.lower(), "c:\\program files\\x\\a.exe")
        rp3 = bc.resolve_image_path(r"\SystemRoot\System32\drivers\luafv.sys")
        self.assertTrue(rp3.lower().endswith(r"\drivers\luafv.sys"))
        rp4 = bc.resolve_image_path(r"\??\C:\Windows\temp\abc\x64.sys")
        self.assertTrue(rp4.lower().startswith("c:\\windows\\temp"), rp4)
        rp5 = bc.resolve_image_path(r"%SystemRoot%\SysWOW64\svchost -k douyin_performance_service")
        self.assertEqual(rp5.lower(), r"c:\windows\syswow64\svchost")
        self.assertTrue(bc.image_file_exists(r"C:\Windows\System32\svchost"))
        self.assertFalse(bc.image_file_exists(r"C:\not_exist_dir\not_exist.sys"))

    def test_split_cmdline(self):
        exe, args = bc.split_cmdline(r'"C:\Program Files\A B\app.exe" --minimized')
        self.assertEqual(exe.lower(), r"c:\program files\a b\app.exe")
        self.assertEqual(args, "--minimized")
        exe2, args2 = bc.split_cmdline(r"%SystemRoot%\System32\notepad.exe -x")
        self.assertTrue(exe2.lower().endswith("system32\\notepad.exe"))
        self.assertEqual(args2, "-x")
        exe3, args3 = bc.split_cmdline(r"C:\Nope\xx.exe -a")
        self.assertEqual(exe3, r"C:\Nope\xx.exe")
        self.assertEqual(args3, "-a")

    def test_task_name_sanitize(self):
        self.assertEqual(bc._task_name_for(r"a\b:c"), "BootDoctor-Delay-a_b_c")

    def test_exists_raw_protected(self):
        # C:\ 下必然存在的目录级枚举兜底：随便找个系统文件
        self.assertTrue(bc.path_exists_raw(r"C:\Windows\System32\svchost.exe"))
        self.assertFalse(bc.path_exists_raw(r"C:\Windows\System32\definitely_not_exists_xyz.sys"))

    def test_parse_json_array_and_object(self):
        # 回归：run_ps 可能返回顶层数组（如事件列表），_parse_json 必须支持
        self.assertEqual(bc._parse_json('[{"x":1},{"x":2}]'), [{"x": 1}, {"x": 2}])
        self.assertEqual(bc._parse_json('[1,2]'), [1, 2])
        self.assertEqual(bc._parse_json('{"y":3}'), {"y": 3})
        self.assertEqual(bc._parse_json(''), {})
        self.assertEqual(bc._parse_json('[]'), [])


class TestGuiOffscreen(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from PyQt5.QtWidgets import QApplication
        cls.app = QApplication.instance() or QApplication([])

    def test_main_window_flow(self):
        from PyQt5.QtCore import Qt
        import boot_doctor as bd

        res = bc.analyze(fake_raw())
        win = bd.MainWindow(autoscan=False)
        win.show()
        win.on_scan_done(fake_raw(), res)

        n_children = sum(win.tree.topLevelItem(i).childCount()
                         for i in range(win.tree.topLevelItemCount()))
        self.assertGreaterEqual(n_children, 5)

        checked = win._checked_findings()
        self.assertGreaterEqual(len(checked), 3)
        self.assertIn("智能优化（%d）" % len(checked), win.btn_apply.text())

        target = None
        for i in range(win.tree.topLevelItemCount()):
            p = win.tree.topLevelItem(i)
            for j in range(p.childCount()):
                c = p.child(j)
                if c.checkState(0) == Qt.Checked:
                    target = c
                    break
            if target:
                break
        self.assertIsNotNone(target)

        before = len(win._checked_findings())
        target.setCheckState(0, Qt.Unchecked)
        self.assertEqual(len(win._checked_findings()), before - 1)
        self.assertIn("智能优化（%d）" % (before - 1), win.btn_apply.text())

        target.setSelected(True)
        win.on_cur_changed(target, None)
        self.assertGreater(len(win.detail.toHtml()), 50)
        win.close()

    def test_popup_dialog(self):
        """弹窗拦截对话框能建起来、列够、按钮状态正确。"""
        import boot_doctor as bd

        dlg = bd.PopupDialog()
        self.assertEqual(dlg.tree.columnCount(), 5)
        self.assertEqual(dlg.watch.columnCount(), 5)
        self.assertEqual(dlg.tabs.count(), 4)            # 当前窗口 / 窗口记录 / 自启变动 / 新进程
        self.assertTrue(dlg.btn_guard.text() in ("开始后台拦截", "停止后台拦截"))
        self.assertIn("守护：", dlg.lbl_guard.text())
        self.assertIn("开机自启", dlg.lbl_guard.text())
        # 开机自启是用户自己勾的，默认跟着注册表走，不能偷偷打开
        self.assertTrue(hasattr(dlg, "chk_boot"))
        self.assertEqual(dlg.chk_boot.isChecked(), bc.guard_autostart()[0] != "off")
        self.assertGreaterEqual(dlg.tree.topLevelItemCount(), 0)
        dlg.close()

    def test_db_button_wired(self):
        """工具栏「特征库」按钮要显示真实版本，菜单里也要有更新入口。"""
        import boot_doctor as bd

        win = bd.MainWindow(autoscan=False)
        st = bc.adware_db_stats()
        win._sync_db_btn()
        self.assertIn("v%d" % st["version"], win.btn_db.text())
        self.assertIn("目录", win.btn_db.toolTip())
        acts = []
        for m in win.menuBar().actions():
            if m.menu():
                acts += [a.text() for a in m.menu().actions()]
        self.assertTrue(any("更新流氓软件特征库" in t for t in acts),
                        "菜单里没有特征库更新入口：%s" % acts)
        self.assertTrue(callable(getattr(win, "on_update_db", None)))
        win.close()

    def test_multi_select_apply_one_op(self):
        """多选多行后点一次处理方式，必须全部生效（不是只改当前这一行）。"""
        from PyQt5.QtCore import Qt
        from PyQt5.QtWidgets import QApplication
        import boot_doctor as bd

        raw = fake_raw_multi()
        res = bc.analyze(raw)
        win = bd.MainWindow(autoscan=False)
        win.show()
        win.on_scan_done(raw, res)
        rows = []
        for i in range(win.tree.topLevelItemCount()):
            p = win.tree.topLevelItem(i)
            for j in range(p.childCount()):
                ch = p.child(j)
                f = win._finding_of_item(ch)
                if f and (f.get("opts") or {}).get("block") and len(rows) < 3:
                    rows.append(ch)
        self.assertGreaterEqual(len(rows), 3, "样例数据里支持『禁止启动』的项不足 3 个")

        win.tree.clearSelection()
        win.tree.setCurrentItem(rows[0])   # 先定当前行：它会清空选中，必须在补选之前
        for ch in rows:
            ch.setSelected(True)
        QApplication.processEvents()
        self.assertTrue(win.op_bar.isVisible())
        self.assertIn("已选 3 项", win.lbl_op.text())
        self.assertIn("（3）", win.op_btns["block"].text())

        win.op_btns["block"].click()
        QApplication.processEvents()
        for ch in rows:
            f = win._finding_of_item(ch)
            self.assertEqual(f.get("op"), "block", "多选项没有全部改成禁止启动")
            self.assertEqual(ch.checkState(0), Qt.Checked, "多选改完没有自动纳入批量")
        self.assertIn("智能优化（%d）" % len(win._checked_findings()), win.btn_apply.text())
        self.assertGreaterEqual(len(win._checked_findings()), 3)
        self.assertIn("3 项", win.btn_apply_one.text())
        win.close()

    def test_checked_items_take_one_op(self):
        """只勾选（不选中多行）多项时，点一次处理方式也应作用到所有勾选项。"""
        from PyQt5.QtCore import Qt
        from PyQt5.QtWidgets import QApplication
        import boot_doctor as bd

        raw = fake_raw_multi()
        res = bc.analyze(raw)
        win = bd.MainWindow(autoscan=False)
        win.show()
        win.on_scan_done(raw, res)

        rows = []
        for i in range(win.tree.topLevelItemCount()):
            p = win.tree.topLevelItem(i)
            for j in range(p.childCount()):
                ch = p.child(j)
                f = win._finding_of_item(ch)
                if f and (f.get("opts") or {}).get("delete") and len(rows) < 3:
                    rows.append(ch)
        self.assertGreaterEqual(len(rows), 3)

        win._check_items(rows, True)          # 只勾选，不选中
        win.tree.setCurrentItem(rows[0])      # 当前行在其中
        QApplication.processEvents()
        self.assertIn("已勾选", win.lbl_op.text())

        win.op_btns["delete"].click()
        QApplication.processEvents()
        for ch in rows:
            f = win._finding_of_item(ch)
            self.assertEqual(f.get("op"), "delete", "勾选项没有被一起改掉")
        win.close()

    def test_apply_dialog_no_crash(self):
        """回归：『智能优化确认对话框』必须能正常构建（Qt5 无 setButtonText 的坑）。"""
        from PyQt5.QtWidgets import QMessageBox
        import boot_doctor as bd

        res = bc.analyze(fake_raw())
        win = bd.MainWindow(autoscan=False)
        win.on_scan_done(fake_raw(), res)
        captured = {}
        orig_exec = QMessageBox.exec_
        orig_admin = bc.is_admin

        def fake_exec(self):
            byes = self.button(QMessageBox.Yes)
            captured["yes_text"] = byes.text() if byes else ""
            captured["detail"] = self.detailedText()
            return QMessageBox.No

        QMessageBox.exec_ = fake_exec
        bc.is_admin = lambda: True
        try:
            win.on_apply()
        finally:
            QMessageBox.exec_ = orig_exec
            bc.is_admin = orig_admin
            win.close()
        self.assertEqual(captured.get("yes_text"), "开始优化")
        self.assertTrue(captured.get("detail"))


class TestDelaySettings(unittest.TestCase):
    """延迟时长设置 + 已有延迟任务识别（★ 全部写临时目录，不碰真实 _settings.json）"""

    def setUp(self):
        self._orig = bc.SETTINGS_PATH
        self._td = tempfile.TemporaryDirectory()
        bc.SETTINGS_PATH = os.path.join(self._td.name, "_settings.json")

    def tearDown(self):
        bc.SETTINGS_PATH = self._orig
        self._td.cleanup()

    def test_get_set_roundtrip(self):
        self.assertEqual(bc.get_delay_seconds(), 60)
        self.assertTrue(bc.set_delay_seconds(120))
        self.assertEqual(bc.get_delay_seconds(), 120)
        self.assertEqual(bc.delay_text(), "2 分钟")
        bc.set_delay_seconds(30)
        self.assertEqual(bc.delay_text(), "30 秒")
        bc.set_delay_seconds(9999)          # 越界钳制
        self.assertEqual(bc.get_delay_seconds(), 600)
        bc.set_delay_seconds(1)
        self.assertEqual(bc.get_delay_seconds(), 5)
        self.assertEqual(bc.delay_text(0), "无延迟")

    def test_iso_parse(self):
        self.assertEqual(bc._iso_delay_to_sec("PT1M"), 60)
        self.assertEqual(bc._iso_delay_to_sec("PT30S"), 30)
        self.assertEqual(bc._iso_delay_to_sec("PT1M30S"), 90)
        self.assertEqual(bc._iso_delay_to_sec("PT2H"), 7200)
        self.assertEqual(bc._iso_delay_to_sec(""), 0)
        self.assertEqual(bc._iso_delay_to_sec("bogus"), 0)

    def test_existing_tasks_shape(self):
        tasks = bc.existing_delay_tasks()
        self.assertIsInstance(tasks, list)
        for t in tasks:
            for k in ("task", "name", "exe", "args", "delay", "enabled"):
                self.assertIn(k, t)
            self.assertTrue(t["task"].startswith(bc.DELAY_TASK_PREFIX))
            self.assertIsInstance(t["delay"], int)

    def test_gui_delay_combo_keeps_checks(self):
        from PyQt5.QtWidgets import QApplication
        import boot_doctor as bd
        app = QApplication.instance() or QApplication([])
        win = bd.MainWindow(autoscan=False)
        win.on_scan_done(fake_raw(), bc.analyze(fake_raw()))
        self.assertEqual(win.cb_delay.count(), len(bc.DELAY_CHOICES))
        checked0 = set(f["id"] for f in win._checked_findings())
        self.assertTrue(checked0)
        win.cb_delay.setCurrentIndex(win.cb_delay.findData(120))
        app.processEvents()
        self.assertEqual(bc.get_delay_seconds(), 120)
        self.assertEqual(set(f["id"] for f in win._checked_findings()), checked0)
        self.assertIn("2 分钟", win.lbl_status.text())
        win.close()


class TestOps(unittest.TestCase):
    """每种自启对象的「延迟 / 禁止 / 删除」三选一（★ 只写临时目录，不碰真实系统）"""

    def test_apply_op_switch(self):
        f = {"id": "t", "title": "T", "short": "s", "detail": "d", "fix": {"type": "A"},
             "opts": {k: {"fix": {"type": v}, "title": k, "short": k + "s",
                          "impact": k + "i", "detail": k + "d"}
                      for k, v in (("delay", "A"), ("block", "B"), ("delete", "C"))}}
        bc.apply_op(f, "block")
        self.assertEqual((f["op"], f["fix"]["type"], f["title"], f["impact"]),
                         ("block", "B", "block", "blocki"))
        bc.apply_op(f, "delete")
        self.assertEqual((f["fix"]["type"], f["title"]), ("C", "delete"))
        bc.apply_op(f, "delay")
        self.assertEqual((f["fix"]["type"], f["title"], f["detail"]), ("A", "delay", "delayd"))
        bc.apply_op(f, "bogus")
        self.assertIn(f["op"], ("delay", "block", "delete"))
        g = {"title": "x", "fix": {"type": "Z"}}
        bc.apply_op(g, "delete")
        self.assertEqual(g["fix"]["type"], "Z")
        self.assertNotIn("op", g)

    def test_analyze_supplies_ops(self):
        r = bc.analyze(fake_raw())
        found = [f for f in r["findings"] if f.get("opts")]
        self.assertTrue(found, "没有找到任何带处理方式的项目")
        for f in found:
            self.assertIn(f["op"], f["opts"])
            self.assertEqual(f["fix"], f["opts"][f["op"]]["fix"])
            if f["id"].startswith("delay_svc@"):
                self.assertEqual(set(f["opts"]), {"delay", "block"},
                                 "服务只提供延迟 / 禁止，不给删除")
            elif f["id"].startswith("delay_task@"):
                self.assertEqual(set(f["opts"]), {"delay", "now", "block", "delete"},
                                 "已延迟的任务要能改回立即启动")
            else:
                self.assertEqual(set(f["opts"]), {"delay", "block", "delete"})

    def test_task_enabled_parse(self):
        """Disable-ScheduledTask 写的是 Settings/Enabled=false，不能只看 Triggers。"""
        td = tempfile.mkdtemp()
        old = bc.TASKS_DIR
        bc.TASKS_DIR = td
        try:
            body = ('<?xml version="1.0" encoding="UTF-16"?><Task><Triggers>'
                    '<LogonTrigger>%s<Delay>PT1M</Delay></LogonTrigger></Triggers>'
                    '<Settings><Enabled>%s</Enabled></Settings></Task>')
            for name, trig, setting, want in (
                    ("BootDoctor-Delay-On", "<Enabled>true</Enabled>", "true", True),
                    ("BootDoctor-Delay-Off", "", "false", False),
                    ("BootDoctor-Delay-NoSet", "", None, True)):
                xml = body % (trig, setting if setting else "true")
                with open(os.path.join(td, name), "wb") as fp:
                    fp.write(b"\xff\xfe" + xml.encode("utf-16-le"))
            got = {t["task"]: t["enabled"] for t in bc.existing_delay_tasks()}
            self.assertTrue(got.get("BootDoctor-Delay-On"))
            self.assertFalse(got.get("BootDoctor-Delay-Off"), got)
            self.assertTrue(got.get("BootDoctor-Delay-NoSet"))
        finally:
            bc.TASKS_DIR = old
            shutil.rmtree(td, ignore_errors=True)

    def test_backup_and_dry_run(self):
        td = tempfile.mkdtemp()
        old = bc.TASKS_DIR
        bc.TASKS_DIR = os.path.join(td, "Tasks")
        os.makedirs(bc.TASKS_DIR)
        try:
            sf = os.path.join(td, "Startup")
            os.makedirs(sf)
            lnk = os.path.join(sf, "T.lnk")
            with open(lnk, "wb") as fp:
                fp.write(b"X")
            task = "BootDoctor-Delay-T"
            with open(os.path.join(bc.TASKS_DIR, task), "wb") as fp:
                fp.write(b"\xff\xfe" + "<Task><Triggers/></Task>".encode("utf-16-le"))
            fs = [
                {"id": "d1", "title": "删文件", "fix": {
                    "type": "startup_delete", "risk": "confirm",
                    "items": [{"hive": "HKCU", "kind": "folder", "name": "T.lnk",
                               "cmd": lnk}]}},
                {"id": "d2", "title": "删Run", "fix": {
                    "type": "startup_delete", "risk": "confirm",
                    "items": [{"hive": "HKCU", "kind": "run", "name": "NoSuchValue__T",
                               "cmd": "x", "subkey": r"Software\Microsoft\Windows\CurrentVersion\Run"}]}},
                {"id": "d3", "title": "禁任务", "fix": {
                    "type": "delay_task_block", "risk": "safe",
                    "items": [{"task": task, "enabled": True}]}},
                {"id": "d4", "title": "删任务", "fix": {
                    "type": "delay_task_del", "risk": "confirm",
                    "items": [{"task": task, "exe": "x", "args": "", "delay": 60}]}},
            ]
            bdir = bc.make_backup(fs, backup_root=os.path.join(td, "bak"), tag="t")
            with open(os.path.join(bdir, "snapshot.json"), encoding="utf-8") as fp:
                snap = json.load(fp)
            kinds = [i["kind"] for i in snap["items"]]
            self.assertIn("startup_delete", kinds)
            self.assertIn("delay_task_block", kinds)
            self.assertIn("delay_task_del", kinds)
            fold = [i for i in snap["items"] if i["kind"] == "startup_delete"
                    and i.get("kindx") == "folder"][0]
            self.assertTrue(os.path.isfile(os.path.join(bdir, fold["backup_file"])))
            blk = [i for i in snap["items"] if i["kind"] == "delay_task_block"][0]
            self.assertTrue(blk["old_enabled"])
            dl = [i for i in snap["items"] if i["kind"] == "delay_task_del"][0]
            self.assertTrue(os.path.isfile(os.path.join(bdir, dl["xml_file"])))
            res = bc.apply_fixes(fs, bdir, dry_run=True)
            self.assertEqual(len(res), 4)
            self.assertTrue(all(r["ok"] for r in res), [r for r in res if not r["ok"]])
            self.assertTrue(os.path.isfile(lnk), "dry-run 不该真删文件")
            res2 = bc.restore_backup(bdir, dry_run=True)
            self.assertTrue(all(r["ok"] for r in res2), [r for r in res2 if not r["ok"]])
        finally:
            bc.TASKS_DIR = old
            shutil.rmtree(td, ignore_errors=True)

    def test_gui_op_switch(self):
        from PyQt5.QtWidgets import QApplication
        from PyQt5.QtCore import Qt
        import boot_doctor as bd
        app = QApplication.instance() or QApplication([])
        # ★ 铁律：测试绝不写真实 _settings.json（改延迟时长会持久化）
        _orig_cfg = bc.SETTINGS_PATH
        _td = tempfile.TemporaryDirectory()
        bc.SETTINGS_PATH = os.path.join(_td.name, "_settings.json")
        try:
            raw = fake_raw()
            win = bd.MainWindow(autoscan=False)
            win.on_scan_done(raw, bc.analyze(raw))
            target = None
            for i in range(win.tree.topLevelItemCount()):
                p = win.tree.topLevelItem(i)
                for j in range(p.childCount()):
                    if p.child(j).text(0).startswith("自启项："):
                        target = p.child(j)
                        break
                if target:
                    break
            self.assertIsNotNone(target, "没有可切换处理方式的自启项")
            win.tree.setCurrentItem(target)
            app.processEvents()
            self.assertTrue(win.op_bar.isVisible() or win.op_bar.isVisibleTo(win))
            win.op_btns["delete"].click()
            app.processEvents()
            f = win._finding_by_idx(target.data(0, Qt.UserRole))
            self.assertEqual(f["fix"]["type"], "startup_delete")
            self.assertIn("删除", target.text(3))
            # 改延迟时长会重建清单，选择必须保留
            win.cb_delay.setCurrentIndex(win.cb_delay.findData(180))
            app.processEvents()
            kept = [f2 for f2 in win.result["findings"] if f2.get("id") == f.get("id")]
            self.assertTrue(kept and kept[0].get("op") == "delete", "重建后选择丢了")
            win.close()
        finally:
            bc.SETTINGS_PATH = _orig_cfg
            _td.cleanup()


class TestSignatureAndMeta(unittest.TestCase):
    """签名列 / 来源列 / 设置项（v1.6.0 新增能力）"""

    def test_signature_states(self):
        info = bc.describe_app(r"C://Windows//System32//notepad.exe")
        if not info.get("exists"):
            self.skipTest("本机没有 notepad.exe")
        sig = bc.app_signature(info)
        self.assertIn(sig["state"], ("valid", "catalog"),
                      "系统自带程序应当有内嵌或目录签名，实际：%r" % sig)
        miss = bc.app_signature({"path": r"C://__no_such_dir__//nope.exe", "exists": False})
        self.assertEqual(miss["state"], "missing")
        blank = bc.app_signature({})
        self.assertEqual(blank["state"], "unknown")

    def test_signature_cache(self):
        info = bc.describe_app(r"C://Windows//System32//notepad.exe")
        if not info.get("exists"):
            self.skipTest("本机没有 notepad.exe")
        a = bc.app_signature(info)
        b = bc.app_signature(dict(info))
        self.assertEqual(a, b)

    def test_delay_findings_carry_source(self):
        res = bc.analyze(fake_raw())
        ds = [f for f in res["findings"] if f["cat"] == "延迟启动"]
        self.assertTrue(ds, "样例数据应当产出延迟启动项")
        for f in ds:
            self.assertTrue(f.get("src"), "延迟项缺少来源字段：%s" % f.get("id"))

    def test_is_microsoft(self):
        self.assertTrue(bc.is_microsoft({"company": "Microsoft Corporation"}))
        self.assertFalse(bc.is_microsoft({"company": "AdGuard Software Limited"}))
        win_root = os.environ.get("SystemRoot", r"C://Windows")
        self.assertFalse(bc.is_microsoft({"company": "Razer Inc.",
                                          "path": win_root + r"\System32\x.exe"}))


class TestSettingsAndView(unittest.TestCase):
    """设置项读写 / 主题切换 / 过滤与搜索（离屏，不写真实配置）"""

    def setUp(self):
        self._orig = bc.SETTINGS_PATH
        self._td = tempfile.TemporaryDirectory()
        bc.SETTINGS_PATH = os.path.join(self._td.name, "_settings.json")

    def tearDown(self):
        bc.SETTINGS_PATH = self._orig
        self._td.cleanup()

    def test_setting_roundtrip(self):
        self.assertEqual(bc.get_setting("ai_enabled", True), True)
        bc.set_setting("ai_enabled", False)
        bc.set_setting("theme", "dark")
        bc.set_setting("ai_timeout", 45)
        self.assertEqual(bc.get_setting("ai_enabled", True), False)
        self.assertEqual(bc.get_setting("theme", "light"), "dark")
        self.assertEqual(bc.get_setting("ai_timeout", 60), 45)
        # 延迟时长与其它设置共用同一个文件
        bc.set_delay_seconds(120)
        self.assertEqual(bc.get_delay_seconds(), 120)
        self.assertEqual(bc.get_setting("theme", "light"), "dark")

    def test_settings_dialog_values(self):
        from PyQt5.QtWidgets import QApplication
        import boot_doctor as bd
        app = QApplication.instance() or QApplication([])
        bc.set_setting("ai_enabled", False)
        bc.set_setting("theme", "dark")
        dlg = bd.SettingsDialog()
        v = dlg.values()
        self.assertFalse(v["ai_enabled"])
        self.assertEqual(v["theme"], "dark")
        self.assertTrue(v["ai_base"].startswith("http"))
        dlg.close()

    def test_theme_switch_keeps_rows(self):
        from PyQt5.QtWidgets import QApplication
        import boot_doctor as bd
        app = QApplication.instance() or QApplication([])
        raw = fake_raw()
        win = bd.MainWindow(autoscan=False)
        win.on_scan_done(raw, bc.analyze(raw))
        before = sum(win.tree.topLevelItem(i).childCount()
                     for i in range(win.tree.topLevelItemCount()))
        light_bg = bd.PAL["bg"]
        win.set_theme("dark")
        app.processEvents()
        after = sum(win.tree.topLevelItem(i).childCount()
                    for i in range(win.tree.topLevelItemCount()))
        self.assertEqual(before, after, "切主题后清单条数变了")
        self.assertNotEqual(light_bg, bd.PAL["bg"])
        self.assertEqual(bc.get_setting("theme", "light"), "dark")
        win.set_theme("light")
        app.processEvents()
        win.close()

    def test_search_and_category_filter(self):
        from PyQt5.QtWidgets import QApplication
        import boot_doctor as bd
        app = QApplication.instance() or QApplication([])
        raw = fake_raw()
        win = bd.MainWindow(autoscan=False)
        win.on_scan_done(raw, bc.analyze(raw))

        def visible():
            n = 0
            for i in range(win.tree.topLevelItemCount()):
                p = win.tree.topLevelItem(i)
                for j in range(p.childCount()):
                    if not p.child(j).isHidden():
                        n += 1
            return n

        total = visible()
        self.assertGreater(total, 5)
        win.ed_search.setText("Service")
        app.processEvents()
        hit = visible()
        self.assertLess(hit, total, "搜索没有过滤掉任何行")
        self.assertGreater(hit, 0, "搜索 Service 应当还能命中几条")
        self.assertIn("显示", win.lbl_count.text())

        win.ed_search.clear()
        app.processEvents()
        self.assertEqual(visible(), total, "清空搜索后应当全部恢复")

        win.cb_cat.setCurrentIndex(win.cb_cat.findData("服务与残留"))
        app.processEvents()
        for i in range(win.tree.topLevelItemCount()):
            p = win.tree.topLevelItem(i)
            if p.isHidden():
                continue
            self.assertIn("服务与残留", p.text(0), "分类过滤漏了别的分类")
        win.cb_cat.setCurrentIndex(0)
        app.processEvents()
        self.assertEqual(visible(), total)
        win.close()

    def test_sort_by_header(self):
        from PyQt5.QtWidgets import QApplication
        import boot_doctor as bd
        app = QApplication.instance() or QApplication([])
        raw = fake_raw()
        win = bd.MainWindow(autoscan=False)
        win.on_scan_done(raw, bc.analyze(raw))
        win.on_header_click(1)       # 按等级排序
        app.processEvents()
        ranks = {"高": 0, "中": 1, "低": 2, "提示": 3}
        for i in range(win.tree.topLevelItemCount()):
            p = win.tree.topLevelItem(i)
            seq = [ranks.get(p.child(j).text(1), 9) for j in range(p.childCount())]
            self.assertEqual(seq, sorted(seq), "等级列没有按严重度排好")
        win.close()


class TestAdware(unittest.TestCase):
    """流氓软件 / 全家桶识别（v1.8.0）"""

    def test_db_loaded(self):
        db = bc.adware_db()
        self.assertGreater(len(db.get("dirs") or {}), 500, "特征库目录数太少")
        self.assertGreater(len(db.get("pubs") or []), 100, "签名黑名单太少")
        self.assertGreaterEqual(len(db.get("_fam") or []), 5, "厂商家族规则缺失")

    def test_family_match(self):
        cases = [
            (r"C://Program Files (x86)//360//360Safe//360tray.exe", "360安全卫士", "360"),
            (r"C://Program Files (x86)//2345Soft//2345Explorer//2345Explorer.exe", "2345浏览器", "2345"),
            (r"C://Program Files//LuDaShi//LdsGameBox.exe", "鲁大师游戏盒子", "ludashi"),
        ]
        for path, name, want in cases:
            r = bc.adware_check(path=path, name=name)
            self.assertTrue(r.get("hit"), "没识别出 %s" % name)
            self.assertEqual(r.get("family"), want, "%s 家族判断错误" % name)

    def test_no_false_positive(self):
        """大厂 / 系统组件不能误报 —— 误判一次用户就不信这个工具了。"""
        safe = [
            (r"C://Windows//System32//notepad.exe", "记事本", "Microsoft Corporation"),
            (r"C://Program Files//WinRAR//WinRAR.exe", "WinRAR", "win.rar GmbH"),
            (r"C://Program Files//NVIDIA Corporation//x.exe", "NVIDIA", "NVIDIA Corporation"),
            (r"C://Program Files//Intel//oneAPI//x.exe", "oneAPI", "Intel Corporation"),
            (r"C://Program Files//3DMark//3DMark.exe", "3DMark", "UL"),
        ]
        for path, name, comp in safe:
            r = bc.adware_check(path=path, name=name, company=comp)
            self.assertFalse(r.get("hit"), "误报了：%s（%s）-> %s"
                             % (name, comp, r.get("why")))

    def test_generic_dir_excluded(self):
        """downloads / update / temp 这类通用目录名必须排除，否则满屏误报。"""
        db = bc.adware_db()
        for d in ("downloads", "update", "temp", "data"):
            self.assertNotIn(d, db["_dir_lower"], "通用目录 %s 没被排除" % d)

    def test_scan_structure(self):
        """adware_scan 会真扫本机已安装程序，所以只验结构、不假定结果为空。"""
        raw = fake_raw()
        raw["extra"] = []
        res = bc.adware_scan(raw)
        self.assertIsInstance(res.get("items"), list)
        self.assertIsInstance(res.get("families"), dict)
        self.assertEqual(res.get("count"), len(res["items"]))
        for it in res["items"]:
            for k in ("name", "source", "label", "sev", "why"):
                self.assertIn(k, it, "命中项缺字段 %s" % k)
            self.assertIn(it["sev"], ("high", "mid", "low"))


class TestExtraAutostarts(unittest.TestCase):
    """隐蔽启动点枚举（IFEO / Winlogon / AppInit / LSP）"""

    def test_returns_list(self):
        items = bc.enum_extra_autostarts()
        self.assertIsInstance(items, list)
        for it in items:
            self.assertIn("name", it)
            self.assertIn("loc", it)
            self.assertIn("danger", it)

    def test_multi_sz_parsed(self):
        """REG_MULTI_SZ 不能读成 "['xxx']" 这种字符串。"""
        v = bc._reg_str(bc.HKLM, r"SYSTEM\CurrentControlSet\Control\Lsa",
                        "Authentication Packages")
        self.assertNotIn("[", v, "多字符串被 str(list) 拼坏了：%r" % v)
        self.assertNotIn("'", v)


class TestHtmlReport(unittest.TestCase):
    """HTML 报告"""

    def test_build(self):
        raw = fake_raw()
        raw["adware"] = {"items": [], "families": {}, "count": 0}
        res = bc.analyze(raw)
        html = bc.build_html_report(res, raw=raw)
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("开机体检报告", html)
        self.assertIn("</html>", html)
        # 单文件：不能引用外部 css / js
        self.assertNotIn("<link", html)
        self.assertNotIn("<script src", html)

    def test_write_file(self):
        import tempfile
        raw = fake_raw()
        raw["adware"] = {"items": [], "families": {}, "count": 0}
        res = bc.analyze(raw)
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "r.html")
            out = bc.write_html_report(res, raw=raw, path=p)
            self.assertTrue(os.path.isfile(out))
            self.assertGreater(os.path.getsize(out), 2000)

    def test_escape(self):
        """标题里的尖括号必须转义，否则会破坏页面结构。"""
        html = bc.build_html_report({"findings": [{
            "cat": "测试", "sev": "high", "title": "<script>x</script>",
            "detail": "a < b", "short": ""}], "score": 50, "grade": "差",
            "metrics": {}, "meta": {}})
        self.assertNotIn("<script>x</script>", html)
        self.assertIn("&lt;script&gt;", html)


class TestAdwareDbUpdate(unittest.TestCase):
    """特征库在线更新 / 多级路径匹配（v1.8.2）"""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._old_path = bc.ADWARE_DB_PATH
        self._old_adb = dict(bc._ADB)
        # 别把测试数据写进真实的 _backups / _logs
        self._old_dirs = (bc.BACKUP_DIR, bc.LOG_DIR)
        bc.BACKUP_DIR = os.path.join(self._tmp, "_backups")
        bc.LOG_DIR = os.path.join(self._tmp, "_logs")

    def tearDown(self):
        bc.BACKUP_DIR, bc.LOG_DIR = self._old_dirs
        bc.ADWARE_DB_PATH = self._old_path
        bc._ADB.clear()
        bc._ADB.update(self._old_adb)
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _use_db(self, dirs, pubs=(), white=(), families=()):
        p = os.path.join(self._tmp, "db.json")
        with open(p, "w", encoding="utf-8") as fp:
            json.dump({"version": 1, "dirs": dict(dirs), "pubs": list(pubs),
                       "white": list(white), "families": list(families)},
                      fp, ensure_ascii=False)
        bc.ADWARE_DB_PATH = p
        bc._ADB.clear()
        return p

    def test_parse_utf16_bom(self):
        """上游文件夹是 UTF-16 LE 带 BOM，解错就是满屏乱码，必须能认。"""
        txt = "\\123coco\\\r\n\\Local\\finder\\\r\n\\Program Files (x86)\\Calendar\\\r\n"
        p = bc.parse_adware_txt(txt.encode("utf-16"),
                                "Some Vendor Ltd\r\nAnother Vendor\r\n".encode("utf-16"),
                                "\\mysqld.exe\r\n".encode("utf-16"))
        self.assertEqual(len(p["dirs"]), 3)
        self.assertIn("local\\finder", p["dirs"], "多级路径没解析出来")
        self.assertIn("program files (x86)\\calendar", p["dirs"])
        self.assertNotIn("\\", list(p["dirs"])[0], "键里不该留反斜杠")
        self.assertEqual(p["pubs"][1], "Another Vendor")
        self.assertIn("mysqld.exe", p["white"])

    def test_parse_utf8_and_dedupe(self):
        p = bc.parse_adware_txt("\\某软件\\\n\\某软件\\\n".encode("utf-8"),
                                b"VendorX\nvendorx\n")
        self.assertEqual(list(p["dirs"]), ["某软件"])
        self.assertEqual(p["pubs"], ["VendorX"], "大小写不同的重复签名没去掉")

    def test_merge_inherits_cn_name(self):
        """上游把 finder 改写成 Local\\finder 时，中文名不能丢。"""
        old = {"version": 3,
               "dirs": {"finder": "光速搜索", "oldone": "老条目"},
               "pubs": ["A Corp"],
               "families": [{"id": "x", "name": "X 系", "pats": ["x"]}]}
        parsed = {"dirs": {"local\\finder": "finder", "newone": "newone"},
                  "pubs": ["A Corp"], "white": []}
        db, diff = bc.merge_adware_db(old, parsed)
        self.assertEqual(db["dirs"]["local\\finder"], "光速搜索")
        self.assertEqual(db["version"], 4, "版本号没自增")
        self.assertEqual(db["families"][0]["id"], "x", "厂商家族规则被覆盖了")
        self.assertEqual(diff["moved_dirs"], ["local\\finder"],
                         "路径前缀变化应算改名，不是删除")
        self.assertNotIn("finder", diff["removed_dirs"])
        self.assertNotIn("local\\finder", diff["added_dirs"], "改名不该被算成新增条目")

    def test_deep_key_needs_prefix(self):
        """多级键必须按连续路径段匹配：Local\\finder 不能命中 D:\\Tools\\finder。"""
        self._use_db({"local\\finder": "光速搜索"})
        hit = bc.adware_check(path=r"C:\Users\me\AppData\Local\finder\finder.exe",
                              name="finder")
        self.assertTrue(hit.get("hit"), "多级键没匹配上")
        miss = bc.adware_check(path=r"D:\Tools\finder\finder.exe", name="finder")
        self.assertFalse(miss.get("hit"), "没有 Local 前缀也命中了，会误报")

    def test_whitepath_skipped(self):
        """上游 whitepath 里的文件名是已知误报，不能被目录规则带出来。"""
        self._use_db({"某流氓目录": "某流氓"}, white=["mysqld.exe"])
        r = bc.adware_check(path=r"C:\某流氓目录\mysqld.exe", name="mysqld")
        self.assertFalse(r.get("hit"), "白名单没生效")

    def test_public_documents_not_flagged(self):
        """公共文档 / 图片这类系统容器目录不能当成流氓目录，否则绿色软件全中枪。"""
        for p in (r"C:\Users\Public\Documents\PortableApp\app.exe",
                  r"C:\Users\Public\Pictures\壁纸程序\wp.exe",
                  r"C:\Users\me\AppData\Roaming\config\app.exe"):
            r = bc.adware_check(path=p, name="app")
            self.assertFalse(r.get("hit"), "公共目录误报：%s -> %s" % (p, r.get("why")))

    def test_update_from_local_source(self):
        """离线源更新：写入成功、版本自增、旧库有备份。"""
        src = os.path.join(self._tmp, "src")
        os.makedirs(src)
        dirs = "".join("\\fakedir%03d\\\r\n" % i for i in range(220))
        pubs = "\r\n".join("Fake Vendor %02d Ltd" % i for i in range(60))
        for name, txt in (("folder.txt", dirs), ("sign.txt", pubs),
                          ("whitepath.txt", "\\a.exe\r\n")):
            with open(os.path.join(src, name), "wb") as fp:
                fp.write(txt.encode("utf-16"))
        dbp = self._use_db({"oldonly": "旧条目"}, pubs=["Old Vendor Ltd"])
        rep = bc.update_adware_db(sources=[src], path=dbp)
        self.assertTrue(rep["ok"], rep.get("error"))
        self.assertEqual(rep["dirs"], 220)
        self.assertEqual(rep["pubs"], 60)
        self.assertEqual(rep["version"], 2)
        self.assertTrue(rep["backup"] and os.path.isfile(rep["backup"]))
        with open(dbp, encoding="utf-8") as fp:
            db = json.load(fp)
        self.assertIn("stats", db)
        self.assertEqual(db["stats"]["dirs"], 220)
        if rep["backup"]:
            os.remove(rep["backup"])

    def test_dry_run_keeps_file(self):
        src = os.path.join(self._tmp, "src2")
        os.makedirs(src)
        with open(os.path.join(src, "folder.txt"), "wb") as fp:
            fp.write("".join("\\d%03d\\\r\n" % i for i in range(220)).encode("utf-16"))
        with open(os.path.join(src, "sign.txt"), "wb") as fp:
            fp.write("\r\n".join("V%d Ltd" % i for i in range(60)).encode("utf-16"))
        dbp = self._use_db({"oldonly": "旧条目"})
        with open(dbp, "rb") as fp:
            before = fp.read()
        rep = bc.update_adware_db(dry_run=True, sources=[src], path=dbp)
        self.assertTrue(rep["ok"])
        self.assertEqual(rep["dirs"], 220)
        with open(dbp, "rb") as fp:
            self.assertEqual(fp.read(), before, "--dry-run 不该写文件")

    def test_second_update_is_noop(self):
        """重复更新不能每次都把版本号 +1、留一堆重复备份。"""
        src = os.path.join(self._tmp, "src3")
        os.makedirs(src)
        with open(os.path.join(src, "folder.txt"), "wb") as fp:
            fp.write("".join("\\d%03d\\\r\n" % i for i in range(220)).encode("utf-16"))
        with open(os.path.join(src, "sign.txt"), "wb") as fp:
            fp.write("\r\n".join("V%d Ltd" % i for i in range(60)).encode("utf-16"))
        dbp = self._use_db({"oldonly": "旧条目"})
        r1 = bc.update_adware_db(sources=[src], path=dbp)
        self.assertTrue(r1["ok"])
        self.assertFalse(r1.get("up_to_date"))
        v1 = r1["version"]
        r2 = bc.update_adware_db(sources=[src], path=dbp)
        self.assertTrue(r2["ok"])
        self.assertTrue(r2.get("up_to_date"), "第二次更新没被识别成「已是最新」")
        self.assertEqual(r2["version"], v1, "没有变化却把版本号加了")
        self.assertFalse(r2.get("backup"), "没有变化不该产生新备份")
        if r1.get("backup"):
            os.remove(r1["backup"])

    def test_bad_source_rejected(self):
        """拿到错误页（几十字节的 HTML）不能把本地库覆盖成空库。"""
        src = os.path.join(self._tmp, "bad")
        os.makedirs(src)
        with open(os.path.join(src, "folder.txt"), "w", encoding="utf-8") as fp:
            fp.write("<html>404</html>")
        with open(os.path.join(src, "sign.txt"), "w", encoding="utf-8") as fp:
            fp.write("nope")
        dbp = self._use_db({"keepme": "要保住"})
        rep = bc.update_adware_db(sources=[src], path=dbp)
        self.assertFalse(rep["ok"])
        with open(dbp, encoding="utf-8") as fp:
            self.assertIn("keepme", json.load(fp)["dirs"])


class TestPopupBlock(unittest.TestCase):
    """弹窗定位 / 拦截（v1.9.0）"""

    WIN = {"hwnd": 1, "proc": "AdPop.exe", "cls": "Chrome_WidgetWin_1",
           "title": "双11 限时特惠", "path": r"C:\Program Files\某流氓\adpop.exe",
           "company": "Some Ltd", "judge": "normal", "rect": [0, 0, 320, 200],
           "visible": True, "topmost": True}

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._old = bc.POPUP_RULES_PATH
        bc.POPUP_RULES_PATH = os.path.join(self._tmp, "_popup_rules.json")

    def tearDown(self):
        bc.POPUP_RULES_PATH = self._old
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _rules(self, **kw):
        d = {"enabled": True, "auto_adware": True, "poll_ms": 1200,
             "block": [], "allow": []}
        d.update(kw)
        return d

    def test_safe_class_never_closed(self):
        """任务栏 / 桌面这类系统窗口，即使用户写了规则也不能关。"""
        r = self._rules(block=[{"kind": "class", "pattern": "shell_traywnd"}])
        ok, why = bc.should_close_popup(
            {"cls": "Shell_TrayWnd", "proc": "explorer.exe", "judge": "normal"}, r)
        self.assertFalse(ok)
        self.assertEqual(why, "系统窗口")

    def test_rule_kinds(self):
        for rule in ({"kind": "proc", "pattern": "adpop.exe"},
                     {"kind": "proc_contains", "pattern": "adp"},
                     {"kind": "class", "pattern": "chrome_widgetwin_1"},
                     {"kind": "class_contains", "pattern": "widget"},
                     {"kind": "title", "pattern": "限时特惠"},
                     {"kind": "path", "pattern": "program files\\某流氓"}):
            ok, why = bc.should_close_popup(self.WIN, self._rules(block=[rule]))
            self.assertTrue(ok, "规则没命中：%s" % rule)

    def test_all_conditions(self):
        """组合条件必须全部满足才关，否则等于放宽了规则。"""
        r = self._rules(block=[{"all": [{"kind": "proc", "pattern": "adpop.exe"},
                                        {"kind": "title", "pattern": "广告"}]}])
        hit = dict(self.WIN, title="广告 - 今日推荐")
        self.assertTrue(bc.should_close_popup(hit, r)[0])
        self.assertFalse(bc.should_close_popup(self.WIN, r)[0], "只满足一条也关了")

    def test_allow_overrides_block(self):
        r = self._rules(block=[{"kind": "proc", "pattern": "adpop.exe"}],
                        allow=[{"kind": "title", "pattern": "限时特惠"}])
        self.assertFalse(bc.should_close_popup(self.WIN, r)[0])

    def test_disabled_does_nothing(self):
        r = self._rules(enabled=False, block=[{"kind": "proc", "pattern": "adpop.exe"}])
        ok, why = bc.should_close_popup(self.WIN, r)
        self.assertFalse(ok)
        self.assertEqual(why, "拦截未开启")

    def test_auto_adware(self):
        win = dict(self.WIN, judge="adware", proc="adpop.exe")
        self.assertTrue(bc.should_close_popup(win, self._rules())[0])
        # 系统进程即使被判 adware 也不动（防特征库误报把 explorer 关了）
        syswin = dict(win, proc="explorer.exe")
        self.assertFalse(bc.should_close_popup(syswin, self._rules())[0])

    def test_hint_known_ad_proc(self):
        w = dict(self.WIN, proc="flashcenter.exe", company="", title="")
        self.assertGreaterEqual(bc.popup_hint(w), 45)
        self.assertLessEqual(bc.popup_hint(w), 100)

    def test_import_community_rules(self):
        """能直接吃社区那种 conditions/action 格式（用户自己从网上下载的）。"""
        src = os.path.join(self._tmp, "rules.json")
        data = {"software": [{"name": "某播放器", "rules": [
            {"name": "右下角弹窗", "action": "Close",
             "conditions": [{"type": "ProcessNameEquals", "value": "adpop.exe"}]},
            {"name": "组合", "action": "Close",
             "conditions": [{"type": "ProcessPathContains", "value": "某流氓"},
                            {"type": "ClassNameContains", "value": "widget"}]},
            {"name": "放行主程序", "action": "Ignore",
             "conditions": [{"type": "ProcessNameEquals", "value": "player.exe"}]},
        ]}]}
        with open(src, "w", encoding="utf-8") as fp:
            json.dump(data, fp, ensure_ascii=False)
        ok, n, msg = bc.import_popup_rules(src, rules_path=bc.POPUP_RULES_PATH)
        self.assertTrue(ok, msg)
        self.assertEqual(n, 3)
        rules = bc.load_popup_rules(bc.POPUP_RULES_PATH)
        self.assertEqual(len(rules["block"]), 2)
        self.assertEqual(len(rules["allow"]), 1)
        ok, why = bc.should_close_popup(self.WIN, dict(rules, enabled=True))
        self.assertTrue(ok)

    def test_rules_roundtrip(self):
        r = self._rules(block=[{"kind": "title", "pattern": "迷你首页"}])
        self.assertTrue(bc.save_popup_rules(r))
        back = bc.load_popup_rules()
        self.assertEqual(back["block"][0]["pattern"], "迷你首页")

    def test_enum_popups_structure(self):
        items = bc.enum_popups(include_hidden=False, limit=50)
        self.assertIsInstance(items, list)
        for it in items[:10]:
            for k in ("hwnd", "title", "cls", "pid", "proc", "judge", "hint", "rect"):
                self.assertIn(k, it)
            self.assertNotEqual(it["pid"], os.getpid(), "把自己也枚举进来了")
            self.assertNotIn((it["cls"] or "").lower(), bc._POPUP_SAFE_CLASSES)
            self.assertIn(it["judge"], ("adware", "suspicious", "unsign", "normal"))

    def test_watch_log_roundtrip(self):
        """窗口记录要能写能读（火绒「窗口记录」同款，事后回溯用）。"""
        p = os.path.join(self._tmp, "watch.log")
        bc.append_popup_watch([
            {"t": "11-22 16:00:00", "title": "弹窗A", "proc": "a.exe",
             "cls": "X", "judge": "adware", "path": r"C:\a\a.exe"},
            {"t": "11-22 16:00:05", "title": "弹窗B", "proc": "b.exe",
             "cls": "Y", "judge": "normal", "path": r"C:\b\b.exe"},
        ], path=p)
        rows = bc.popup_watch_log(10, path=p)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["title"], "弹窗B", "应该按时间倒序（最新在前）")
        self.assertEqual(rows[1]["judge"], "adware")

    def test_pick_window_no_crash(self):
        """选取窗口在鼠标位置不确定时也必须安全返回。"""
        w = bc.popup_pick_window()
        self.assertTrue(w is None or "hwnd" in w)

    def test_pid_alive(self):
        self.assertTrue(bc._pid_alive(os.getpid()))
        self.assertFalse(bc._pid_alive(999999))

    def test_user_rule_cannot_close_system_proc(self):
        """用户规则也压不住系统进程：title=下载 不能把资源管理器里的「下载」文件夹关了。"""
        r = self._rules(block=[{"kind": "title", "pattern": "下载"}])
        win = {"proc": "explorer.exe", "cls": "CabinetWClass", "title": "下载",
               "judge": "normal"}
        ok, why = bc.should_close_popup(win, r)
        self.assertFalse(ok)
        self.assertEqual(why, "系统进程")

    def test_guard_pid_rejects_reused_pid(self):
        """pid 文件里的 PID 已被别的进程复用时不能认成守护，否则「停止」会误杀无关进程。"""
        p = os.path.join(self._tmp, "guard.pid")
        me = os.getpid()
        with open(p, "w", encoding="utf-8") as fp:
            fp.write("%d %d" % (me, 12345))              # PID 活着，但创建时间对不上
        self.assertEqual(bc.guard_pid(p), 0)
        bc.write_guard_pid(p)                             # 真实的 PID + 创建时间
        self.assertEqual(bc.guard_pid(p), me)
        with open(p, "w", encoding="utf-8") as fp:
            fp.write(str(me))                             # 旧格式只有 PID：至少得是 Python 进程
        self.assertEqual(bc.guard_pid(p), me)

    # ---------------- 后台运行 / 开机自启（v1.9.1） ----------------
    def test_autostart_roundtrip(self):
        """开机自启：写 Run 项 → 读回 → 删除；命令行必须是 pythonw + --silent。"""
        old = bc.guard_autostart()[0]
        try:
            ok, msg = bc.set_guard_autostart(True)
            self.assertTrue(ok, msg)
            st, val = bc.guard_autostart()
            self.assertEqual(st, "on")
            self.assertIn(bc.GUARD_SCRIPT.lower(), val.lower())
            self.assertIn("--silent", val.lower(), "自启必须静默，不能每次登录弹黑框")
            self.assertIn("pythonw", val.lower(), "自启要用 pythonw，否则会闪控制台")
            self.assertTrue(bc.guard_cmdline().startswith('"'), "路径要加引号，防空格截断")
            ok2, _ = bc.set_guard_autostart(False)
            self.assertTrue(ok2)
            self.assertEqual(bc.guard_autostart()[0], "off")
        finally:
            bc.set_guard_autostart(old != "off")

    def test_autostart_stale_detected(self):
        """项目目录被挪走：自启项指向旧路径时要能识别出来，而不是当成「已开启」。"""
        import winreg
        old = bc.guard_autostart()[0]
        try:
            with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, bc.GUARD_RUN_KEY, 0,
                                    winreg.KEY_SET_VALUE) as k:
                winreg.SetValueEx(k, bc.GUARD_RUN_NAME, 0, winreg.REG_SZ,
                                  '"C:\\old\\pythonw.exe" "D:\\moved\\popup_guard.py" --silent')
            self.assertEqual(bc.guard_autostart()[0], "stale")
        finally:
            bc.set_guard_autostart(old != "off")

    def test_master_switch(self):
        """总开关：守护开机静默启动时看它，关着就不驻留。"""
        bc.save_popup_rules(self._rules(enabled=True))
        self.assertTrue(bc.popup_enabled())
        self.assertTrue(bc.set_popup_enabled(False))
        self.assertFalse(bc.popup_enabled())
        self.assertTrue(bc.set_popup_enabled(True))
        self.assertTrue(bc.popup_enabled())

    def test_guard_launch_is_detached(self):
        """真跑一次「脱离父进程 + 无窗口」的启动方式，而不是断言源码里有某个字符串。

        pythonw + DETACHED_PROCESS 拉起一个会写 pid 的小脚本，父进程退出后它必须
        还活着，且没有可见顶层窗口 —— 这正是「关掉主程序后守护还在」的机制。
        """
        import subprocess
        import time as _t

        d = tempfile.mkdtemp()
        child = os.path.join(d, "child.py")
        launcher = os.path.join(d, "launch.py")
        pf = os.path.join(d, "child.pid")
        with open(child, "w", encoding="utf-8") as fp:
            fp.write("import os, time\n"
                     "open(r'%s','w').write(str(os.getpid()))\n"
                     "time.sleep(3)\n" % pf)
        # 中间层：拉起孙进程后自己立刻退出，模拟「主程序关掉」
        with open(launcher, "w", encoding="utf-8") as fp:
            fp.write("import subprocess, sys\n"
                     "subprocess.Popen([r'%s', r'%s'],\n"
                     "    creationflags=0x00000008 | 0x08000000,\n"
                     "    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
                     % (bc._pythonw_path(), child))
        subprocess.run([sys.executable, launcher], timeout=30, check=True)
        pid = 0
        try:
            for _ in range(60):
                _t.sleep(0.1)
                if os.path.exists(pf):
                    pid = int(open(pf).read().strip() or 0)
                    if pid:
                        break
            self.assertGreater(pid, 0, "孙进程没起来")
            self.assertTrue(bc._pid_alive(pid), "拉起它的进程退出后它跟着死了，没真正脱离")
            self.assertEqual(_visible_windows(pid), 0, "后台进程有可见窗口")
        finally:
            try:
                h = ctypes.windll.kernel32.OpenProcess(0x0001, False, pid)
                if h:
                    ctypes.windll.kernel32.TerminateProcess(h, 0)
                    ctypes.windll.kernel32.CloseHandle(h)
            except Exception:
                pass
            shutil.rmtree(d, ignore_errors=True)


class TestReviewFixes(unittest.TestCase):
    """代码评审（2026-11-22）提出的缺陷，逐条钉住，防回归。"""

    # ---- P0-1 快速启动备份了 hibernate 却只按 hiberboot 还原 ----
    def test_power_restore_uses_hibernate(self):
        # 原本休眠是关的、快速启动开着：必须 powercfg /h off，不能只写注册表
        self.assertEqual(bc._power_restore_plan({"hibernate": 0, "hiberboot": 1})[0],
                         "powercfg_off")
        # 休眠开着、快速启动关着：只写 HiberbootEnabled=0，别把休眠关掉
        self.assertEqual(bc._power_restore_plan({"hibernate": 1, "hiberboot": 0}),
                         ("reg", 0))
        # 两个都开着：还原成 1
        self.assertEqual(bc._power_restore_plan({"hibernate": 1, "hiberboot": 1}),
                         ("reg", 1))
        # 备份里没有该项（老备份）：不动系统
        self.assertEqual(bc._power_restore_plan({}), ("reg", None))

    # ---- P0-3 卸载命令不能走 shell=True ----
    def test_cmd_argv_splits_uninstall_string(self):
        a = bc.cmd_argv(r'"C:\Program Files\Foo\uninst.exe" /S /D=C:\Foo')
        self.assertEqual(a[0], r"C:\Program Files\Foo\uninst.exe")
        self.assertEqual(a[1:], ["/S", r"/D=C:\Foo"])
        b = bc.cmd_argv(r"C:\Windows\System32\msiexec.exe /x {1234-5678}")
        self.assertEqual(b[0].lower(), r"c:\windows\system32\msiexec.exe")
        self.assertEqual(b[1:], ["/x", "{1234-5678}"])
        self.assertEqual(bc.cmd_argv(""), [])
        # 关键：拆分结果里不能出现 shell 元字符被当成命令分隔的情况
        c = bc.cmd_argv(r'"C:\a\b.exe" & calc.exe')
        self.assertEqual(c[0], r"C:\a\b.exe")
        self.assertNotIn("calc.exe", c[0])

    # ---- P0-2 AI 结论按 id 对齐，不再被同名项覆盖 ----
    def test_ai_match_by_id(self):
        findings = [
            {"id": "f1", "name": "WeChat", "app": {"path": r"C:\a\WeChat.exe"}, "short": "启用"},
            {"id": "f2", "name": "WeChat", "app": {"path": r"C:\b\WeChat.exe"}, "short": "启用"},
        ]
        fake = ('[{"id":"f1","name":"WeChat","verdict":"keep","reason":"通讯","risk":"低"},'
                '{"id":"f2","name":"WeChat","verdict":"disable","reason":"冗余","risk":"低"}]')
        old = bc.ai_chat
        bc.ai_chat = lambda *a, **k: (fake, "")
        try:
            out, err = bc.ai_advise(findings)
        finally:
            bc.ai_chat = old
        self.assertEqual(err, "")
        self.assertEqual(out["f1"]["verdict"], "keep")
        self.assertEqual(out["f2"]["verdict"], "disable", "同名项串了结论")

    def test_ai_payload_masks_path(self):
        p = bc._ai_mask_path(r"C:\Users\zhangsan\AppData\Local\360bizhi\adpop.exe")
        self.assertTrue(p.endswith(r"360bizhi\adpop.exe"))
        self.assertNotIn("zhangsan", p, "完整路径不该发给 AI")
        self.assertEqual(bc._ai_mask_path(r"C:\a.exe"), r"C:\a.exe")

    def test_non_local_ai_detected(self):
        self.assertTrue(bc.is_local_ai("http://127.0.0.1:3425"))
        self.assertTrue(bc.is_local_ai("http://localhost:8080/v1"))
        self.assertFalse(bc.is_local_ai("http://api.example.com"))
        self.assertFalse(bc.is_local_ai("https://8.8.8.8"))

    # ---- P1-6 restore-all.reg 的覆盖范围要写清楚 ----
    def test_backup_readme_states_reg_limits(self):
        d = tempfile.mkdtemp()
        try:
            snap = {"created": "2026-11-22 12:00:00", "app": bc.APP_NAME, "items": [
                {"id": "a", "kind": "service", "name": "FooSvc", "old": 2},
                {"id": "b", "kind": "task", "name": "FooTask"},
                {"id": "c", "kind": "delay_task_del", "task": "FooDelay"},
            ]}
            bc._write_restore_reg(snap, os.path.join(d, "restore-all.reg"))
            # 直接跑 make_backup 太重，这里只验证说明文案的关键承诺
            txt = bc.make_backup_readme_text(snap)
            self.assertIn("只能还原注册表", txt)
            self.assertIn("计划任务", txt)
            self.assertIn("必须用第 1 种方式", txt)
        finally:
            shutil.rmtree(d, ignore_errors=True)


class TestUiPerf(unittest.TestCase):
    """界面性能与 DPI 相关（v1.8.1）

    这两条是回归防线：曾经因为「把原图 QIcon 直接塞表格」导致 28 行重绘 42ms，
    以及「WM_NCHITTEST 物理/逻辑坐标混用」导致鼠标在窗口中间变成缩放光标。
    """

    def test_icon_prerendered(self):
        """图标必须预缩放到目标尺寸，不能是 32px 以上的原图。"""
        from PyQt5.QtWidgets import QApplication
        import boot_doctor as bd
        app = QApplication.instance() or QApplication([])
        win = bd.MainWindow(autoscan=False)
        try:
            ic = win._app_icon(r"C://Windows//System32//notepad.exe")
            if ic is None:
                self.skipTest("本机取不到 notepad 图标")
            side = int(round(16 * win._dpr()))
            pm = ic.pixmap(side, side)
            self.assertFalse(pm.isNull(), "图标为空")
            # 允许 dpr 造成的偏差，但不能是原始大图
            self.assertLessEqual(max(pm.width(), pm.height()), side + 2,
                                 "图标没有预缩放，尺寸 %dx%d（目标 %d）"
                                 % (pm.width(), pm.height(), side))
        finally:
            win.close()

    def test_dot_icon_cached(self):
        """圆点图标按颜色缓存，重复取同一个对象。"""
        from PyQt5.QtWidgets import QApplication
        import boot_doctor as bd
        app = QApplication.instance() or QApplication([])
        win = bd.MainWindow(autoscan=False)
        try:
            a = win._dot_icon("#c23b31")
            b = win._dot_icon("#c23b31")
            self.assertIs(a, b, "圆点图标没走缓存")
            c = win._dot_icon("#157a4f")
            self.assertIsNot(a, c)
        finally:
            win.close()

    def test_brush_cached(self):
        """窗口渐变画刷按尺寸缓存，同一尺寸返回同一对象。"""
        import boot_doctor as bd
        bd.use_theme("light")
        a = bd.win_brush(1200, 800)
        b = bd.win_brush(1200, 800)
        self.assertIs(a, b, "渐变画刷没走缓存")

    def test_window_fits_screen(self):
        """窗口尺寸不能超出屏幕可用区，也不能小到挤在一起。"""
        from PyQt5.QtWidgets import QApplication
        import boot_doctor as bd
        app = QApplication.instance() or QApplication([])
        win = bd.MainWindow(autoscan=False)
        try:
            avail = app.primaryScreen().availableGeometry()
            self.assertLessEqual(win.width(), avail.width(),
                                 "窗口比屏幕还宽：%d > %d" % (win.width(), avail.width()))
            self.assertLessEqual(win.height(), avail.height(),
                                 "窗口比屏幕还高：%d > %d" % (win.height(), avail.height()))
            # 至少占屏 70%，否则内容挤成一团
            self.assertGreaterEqual(win.width(), int(avail.width() * 0.7))
        finally:
            win.close()



def _as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


class TestNativeSysInfo(unittest.TestCase):
    """原生采集（sys_info_native）必须和原来的 PS_SYS 结果一致：同一台机器上真跑两边对照。"""

    @classmethod
    def setUpClass(cls):
        cls.ps = bc._parse_json(bc.run_ps(bc.PS_SYS, timeout=180)) or {}
        cls.nat = bc.sys_info_native()

    def test_basic_fields(self):
        self.assertEqual(self.nat["build"], str(self.ps.get("build")))
        self.assertAlmostEqual(self.nat["ramGB"], float(self.ps.get("ramGB") or 0), delta=0.2)
        self.assertTrue(self.nat["osName"].startswith("Microsoft Windows"), self.nat["osName"])

    def test_boot_time(self):
        import datetime as _d
        fmt = "%Y-%m-%d %H:%M:%S"
        a = _d.datetime.strptime(self.nat["bootTime"], fmt)
        b = _d.datetime.strptime(self.ps["bootTime"], fmt)
        self.assertLessEqual(abs((a - b).total_seconds()), 120,
                             "原生 %s / WMI %s" % (self.nat["bootTime"], self.ps["bootTime"]))

    def test_services(self):
        self.assertLessEqual(abs(self.nat["svcAuto"] - int(self.ps.get("svcAuto") or 0)), 3,
                             "自动服务数 原生 %s / PS %s" % (self.nat["svcAuto"], self.ps.get("svcAuto")))
        diff = set(self.nat["svcAutoDown"]) ^ set(_as_list(self.ps.get("svcAutoDown")))
        self.assertLessEqual(len(diff), 3, "未运行的自动服务对不上：%s" % sorted(diff))

    def test_volumes(self):
        nat = {v["letter"]: v for v in self.nat["vols"]}
        self.assertIn("C", nat)
        for v in _as_list(self.ps.get("vols")):
            if v.get("total") and v["letter"] in nat:
                self.assertLessEqual(abs(nat[v["letter"]]["total"] - v["total"]), 1)

    def test_disks(self):
        key = lambda d: (d.get("name"), d.get("media"), d.get("health"))   # noqa: E731
        self.assertEqual(sorted(map(key, self.nat["disks"])),
                         sorted(map(key, _as_list(self.ps.get("disks")))))

    def test_tasks(self):
        if not bc.is_admin():
            self.skipTest("读 System32\\Tasks 需要管理员；普通权限下走 PowerShell 兜底")
        diff = set(self.nat["tasks"]) ^ set(_as_list(self.ps.get("tasks")))
        self.assertLessEqual(len(diff), 5, "开机/登录任务对不上：%s" % sorted(diff)[:10])


class TestEventsQuery(unittest.TestCase):
    """新版 PS_EVENTS（服务端过滤）必须和旧版结果一致。"""

    def test_new_matches_legacy(self):
        new = bc._parse_json(bc.run_ps(bc.PS_EVENTS, timeout=180)) or {}
        old = bc._parse_json(bc.run_ps(bc.PS_EVENTS_LEGACY, timeout=180)) or {}
        for k in ("c7005", "c7005_7d", "c7005_1h", "c7023"):
            self.assertEqual(int(new.get(k) or 0), int(old.get(k) or 0), k)
        self.assertEqual(new.get("last7005") or "", old.get("last7005") or "")
        # 旧版只在最近 800 条里找，新版直接按事件 ID 查，所以旧结果应是新结果的前缀
        ob = [b.get("time") for b in _as_list(old.get("boots"))]
        nb = [b.get("time") for b in _as_list(new.get("boots"))]
        self.assertEqual(nb[:len(ob)], ob)
        osl = [(x.get("id"), x.get("time"), x.get("name")) for x in _as_list(old.get("slow"))]
        nsl = [(x.get("id"), x.get("time"), x.get("name")) for x in _as_list(new.get("slow"))]
        self.assertEqual(nsl[:len(osl)], osl)
        self.assertEqual([x.get("msg") for x in _as_list(new.get("scm"))],
                         [x.get("msg") for x in _as_list(old.get("scm"))])


class TestNotify(unittest.TestCase):
    """通知管理：在一个临时注册表位置上真读真写，不碰真实的通知设置。"""
    ROOT = r"Software\BootDoctorUnitTest\Notifications\Settings"
    NESTED = r"{6D809377-6AF0-444B-8957-A3773F02200E}\UnitTestVendor\ut_app.exe"

    def setUp(self):
        import winreg
        self.wr = winreg
        bc._delete_key_tree(winreg.HKEY_CURRENT_USER, r"Software\BootDoctorUnitTest")
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, self.ROOT + r"\UnitTest.PlainApp") as k:
            winreg.SetValueEx(k, "LastNotificationAddedTime", 0, winreg.REG_QWORD,
                              133500000000000000)
        # 应用 ID 带反斜杠时，注册表里是多级子键，只有最里层有值
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, self.ROOT + "\\" + self.NESTED) as k:
            winreg.SetValueEx(k, "LastNotificationAddedTime", 0, winreg.REG_QWORD,
                              133600000000000000)

    def tearDown(self):
        bc._delete_key_tree(self.wr.HKEY_CURRENT_USER, r"Software\BootDoctorUnitTest")

    def _by_id(self):
        return {a["aumid"]: a for a in bc.list_notify_apps(self.ROOT)}

    def test_list_nested_and_plain(self):
        apps = self._by_id()
        self.assertEqual(set(apps), {"UnitTest.PlainApp", self.NESTED},
                         "多级子键没有拼回完整的应用 ID，或者把中间层当成了应用")
        nested = apps[self.NESTED]
        self.assertTrue(nested["path"].lower().endswith(r"unittestvendor\ut_app.exe"), nested["path"])
        self.assertTrue(nested["enabled"], "没写 Enabled 的应用默认是允许通知")
        self.assertTrue(nested["last"].startswith("20"), nested["last"])
        ids = [a["aumid"] for a in bc.list_notify_apps(self.ROOT)]
        self.assertEqual(ids[0], self.NESTED, "应按最近一次通知时间倒序")

    def test_toggle_roundtrip(self):
        ok, msg = bc.set_notify_enabled(self.NESTED, False, self.ROOT)
        self.assertTrue(ok, msg)
        self.assertFalse(self._by_id()[self.NESTED]["enabled"])
        self.assertTrue(self._by_id()["UnitTest.PlainApp"]["enabled"], "关一个不能影响别的")
        ok, msg = bc.set_notify_enabled(self.NESTED, True, self.ROOT)
        self.assertTrue(ok, msg)
        self.assertTrue(self._by_id()[self.NESTED]["enabled"])

    def test_bulk_off_adware_notifications(self):
        from PyQt5.QtWidgets import QApplication, QMessageBox
        import boot_doctor as bd
        app = QApplication.instance() or QApplication([])  # noqa: F841
        adware_id = r"{6D809377-6AF0-444B-8957-A3773F02200E}\LuDaShi\LdsGameBox.exe"
        with self.wr.CreateKeyEx(self.wr.HKEY_CURRENT_USER, self.ROOT + "\\" + adware_id) as k:
            self.wr.SetValueEx(k, "LastNotificationAddedTime", 0, self.wr.REG_QWORD, 133700000000000000)
        page = bd.NotifyPage(root_sub=self.ROOT)
        old_q = QMessageBox.question
        try:
            self.assertEqual(page.stats()["adware_on"], 1, "鲁大师路径应命中特征库：%r" % page.apps)
            self.assertFalse(page.btn_adware_off.isHidden())
            self.assertIn("（1）", page.btn_adware_off.text())
            QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.No)
            page.off_adware()
            self.assertEqual(page.stats()["adware_on"], 1, "点了「否」不该关")
            QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.Yes)
            page.off_adware()
            self.assertEqual(page.stats()["adware_on"], 0)
            self.assertTrue(page.btn_adware_off.isHidden(), "没有可关的了，按钮应隐藏")
            by = {a["aumid"]: a for a in page.apps}
            self.assertFalse(by[adware_id]["enabled"])
            self.assertTrue(by["UnitTest.PlainApp"]["enabled"], "只该关流氓软件的，别的不能动")
        finally:
            QMessageBox.question = old_q
            page.close()

    def test_page_toggles_selected(self):
        from PyQt5.QtWidgets import QApplication
        import boot_doctor as bd
        app = QApplication.instance() or QApplication([])  # noqa: F841
        page = bd.NotifyPage(root_sub=self.ROOT)
        self.assertEqual(page.tree.topLevelItemCount(), 2)
        page.tree.topLevelItem(0).setSelected(True)
        page.set_selected(False)
        self.assertEqual(page.stats()["on"], 1)
        page.close()


class TestNavPages(unittest.TestCase):
    """左侧导航：每页都能打开，弹窗页是嵌进来的（不是弹出窗口），过滤控件只在体检页显示。"""

    def test_pages(self):
        from PyQt5.QtWidgets import QApplication
        import boot_doctor as bd
        app = QApplication.instance() or QApplication([])
        win = bd.MainWindow(autoscan=False)
        win.show()
        try:
            self.assertEqual(win.nav.count(), 4)
            self.assertNotIn("popup", win._page_built, "弹窗页应在第一次打开时才建（启动不枚举窗口）")
            for key in ("popup", "notify", "backup", "scan"):
                win.show_page(key)
                app.processEvents()
                self.assertEqual(win.current_page(), key)
                self.assertIs(win.pages.currentWidget(), win.page_widget(key))
                for act in win._scan_only_acts:
                    self.assertEqual(act.isVisible(), key == "scan",
                                     "%s 页上体检过滤控件的显示状态不对" % key)
            pop = win.page_widget("popup")
            self.assertIsInstance(pop, bd.PopupDialog)
            self.assertFalse(pop.isWindow(), "弹窗拦截页应嵌在主窗口里，不是独立窗口")
            win.on_popup_dialog()              # 菜单入口：跳页，不再弹模态框
            self.assertEqual(win.current_page(), "popup")
        finally:
            win.close()

    def test_badges_after_scan(self):
        from PyQt5.QtWidgets import QApplication
        import boot_doctor as bd
        app = QApplication.instance() or QApplication([])  # noqa: F841
        win = bd.MainWindow(autoscan=False)
        try:
            raw = fake_raw()
            res = bc.analyze(raw)
            win.on_scan_done(raw, res)
            self.assertIn(str(res["score"]), win.nav.item(0).text())
        finally:
            win.close()

    def test_backup_page_lists(self):
        from PyQt5.QtWidgets import QApplication
        import boot_doctor as bd
        app = QApplication.instance() or QApplication([])  # noqa: F841
        old = bc.BACKUP_DIR
        with tempfile.TemporaryDirectory() as td:
            bc.BACKUP_DIR = td
            try:
                fs = [{"id": "t1", "title": "T1", "fix": {"type": "svc_start", "risk": "safe",
                                                         "items": {"luafv": 3}}}]
                bc.make_backup(fs, backup_root=td, tag="ut")
                win = bd.MainWindow(autoscan=False)
                try:
                    page = win.page_widget("backup")
                    self.assertEqual(page.tree.topLevelItemCount(), 1)
                    self.assertTrue(page.btn_restore.isEnabled())
                    self.assertIn("1", win.nav.item(3).text())
                finally:
                    win.close()
            finally:
                bc.BACKUP_DIR = old


class TestAutostartWatch(unittest.TestCase):
    """新增自启监控。测试写的 Run 值指向一个不存在的路径：万一测试中途崩了没删掉，登录时也只是静默失败。"""
    NAME = "BootDoctorUnitTestProbe"
    CMD = r'"C:\BootDoctorUnitTest\not_exist.exe" --probe'
    RUN = r"Software\Microsoft\Windows\CurrentVersion\Run"

    def _set(self, cmd):
        import winreg
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, self.RUN, 0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, self.NAME, 0, winreg.REG_SZ, cmd)

    def tearDown(self):
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.RUN, 0, winreg.KEY_SET_VALUE) as k:
                winreg.DeleteValue(k, self.NAME)
        except OSError:
            pass

    def test_diff_logic(self):
        old = {"a": {"name": "A", "cmd": "a.exe", "enabled": True, "kind": "run"},
               "b": {"name": "B", "cmd": "b.exe", "enabled": False, "kind": "run"},
               "c": {"name": "C", "cmd": "c.exe", "enabled": True, "kind": "run"}}
        new = {"a": {"name": "A", "cmd": "a.exe", "enabled": True, "kind": "run"},
               "b": {"name": "B", "cmd": "b.exe", "enabled": True, "kind": "run"},
               "c": {"name": "C", "cmd": "evil.exe", "enabled": True, "kind": "run"},
               "d": {"name": "D", "cmd": "d.exe", "enabled": True, "kind": "run"}}
        got = {r["key"]: r["change"] for r in bc.autostart_diff(old, new)}
        self.assertEqual(got, {"b": "reenabled", "c": "changed", "d": "added"})
        self.assertEqual(bc.autostart_diff(new, old) and
                         {r["key"] for r in bc.autostart_diff(new, old)}, {"c"},
                         "删除不报，只报命令变化")

    def test_own_entries_ignored(self):
        self.assertTrue(bc._OWN_AUTOSTART.search("BootDoctorPopupGuard"))
        self.assertTrue(bc._OWN_AUTOSTART.search(r"\BootDoctor-Delay-QQ"))
        self.assertFalse(bc._OWN_AUTOSTART.search("BootDoctorPopupGuardX"))

    def test_snapshot_and_diff_real_registry(self):
        before = bc.autostart_snapshot(with_tasks=False)
        self._set(self.CMD)
        after = bc.autostart_snapshot(with_tasks=False)
        rows = [r for r in bc.autostart_diff(before, after) if r["name"] == self.NAME]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["change"], "added")
        self._set(self.CMD + " --changed")
        again = bc.autostart_snapshot(with_tasks=False)
        rows = [r for r in bc.autostart_diff(after, again) if r["name"] == self.NAME]
        self.assertEqual([r["change"] for r in rows], ["changed"])

    def test_watcher_wakes_on_registry_change(self):
        import time as _t
        w = bc.AutostartWatcher(watch_tasks=False)
        self.assertTrue(w.start(), "一个位置都没盯上")
        try:
            self.assertTrue(any(x.endswith(self.RUN) for x in w.watching), w.watching)
            self.assertEqual(w.dirty_at, 0.0)
            self._set(self.CMD)
            end = _t.time() + 5
            while not w.dirty_at and _t.time() < end:
                _t.sleep(0.05)
            self.assertTrue(w.dirty_at, "写了 Run 键，监控线程 5 秒内没收到通知")
            # 通知是一次性的：要能连续收到第二次
            w.dirty_at = 0.0
            self._set(self.CMD + " --again")
            end = _t.time() + 5
            while not w.dirty_at and _t.time() < end:
                _t.sleep(0.05)
            self.assertTrue(w.dirty_at, "第二次变化没收到：触发后没重新挂通知")
        finally:
            w.stop()

    def test_describe_change(self):
        np = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "notepad.exe")
        r = bc.describe_autostart_change({"name": "x", "cmd": '"%s" a.txt' % np,
                                          "kind": "run", "change": "added"})
        self.assertEqual(os.path.normcase(r["path"]), os.path.normcase(np))
        self.assertIn("Microsoft", r["company"])
        self.assertEqual(r["adware"], "")
        self.assertTrue(r["t"].startswith("20"))

    def test_page_tab_and_jump(self):
        from PyQt5.QtWidgets import QApplication
        import boot_doctor as bd
        app = QApplication.instance() or QApplication([])  # noqa: F841
        old = bc.AUTOSTART_WATCH_LOG
        with tempfile.TemporaryDirectory() as td:
            bc.AUTOSTART_WATCH_LOG = os.path.join(td, "w.log")
            bc.append_autostart_watch([{"t": "2026-11-22 10:00:00", "change": "added",
                                        "name": "SomeUpdater", "source": "用户 Run",
                                        "cmd": "x.exe", "adware": "2345 全家桶"}])
            win = bd.MainWindow(autoscan=False)
            win.start_scan = lambda: None                 # 别真去体检
            try:
                win.show_page("popup")
                pg = win.page_widget("popup")
                pg.tabs.setCurrentIndex(2)
                self.assertEqual(pg.as_tree.topLevelItemCount(), 1)
                self.assertIn("(1)", pg.tabs.tabText(2))
                pg.as_tree.setCurrentItem(pg.as_tree.topLevelItem(0))
                pg.on_handle_autostart()
                self.assertEqual(win.current_page(), "scan")
                self.assertEqual(win.ed_search.text(), "SomeUpdater")
            finally:
                win.close()
                bc.AUTOSTART_WATCH_LOG = old


class TestThirdPartyTasks(unittest.TestCase):
    """第三方开机/登录计划任务：能列出、能禁止、能恢复。真注册一个测试任务（指向不存在的程序）。"""
    TP = "\\BootDoctorUnitTest\\"
    TN = "Probe"
    EXE = r"C:\BootDoctorUnitTest\not_exist.exe"

    def test_split_task_path(self):
        self.assertEqual(bc.split_task_path(r"\Vendor\Sub\Task"), ("\\Vendor\\Sub\\", "Task"))
        self.assertEqual(bc.split_task_path(r"\RootTask"), ("\\", "RootTask"))
        self.assertEqual(bc.split_task_path("BootDoctor-Delay-X"), ("\\", "BootDoctor-Delay-X"))

    def _ps(self, script):
        env = dict(os.environ, BD_TPATH=self.TP, BD_TASK=self.TN, BD_EXE=self.EXE)
        return bc.run_ps(script, timeout=90, env=env)

    def setUp(self):
        if not bc.is_admin():
            self.skipTest("读 System32\\Tasks 需要管理员")
        out = self._ps("Register-ScheduledTask -TaskName $env:BD_TASK -TaskPath $env:BD_TPATH "
                       "-Action (New-ScheduledTaskAction -Execute $env:BD_EXE -Argument '--probe') "
                       "-Trigger (New-ScheduledTaskTrigger -AtLogOn) -Force | Out-Null; 'OK'")
        self.assertIn("OK", out, "注册测试任务失败")

    def tearDown(self):
        self._ps("Unregister-ScheduledTask -TaskName $env:BD_TASK -TaskPath $env:BD_TPATH "
                 "-Confirm:$false -ErrorAction SilentlyContinue")

    def test_list_analyze_disable_enable(self):
        full = self.TP + self.TN
        self.assertIn(full, bc.boot_logon_tasks_from_xml())
        self.assertEqual(bc._task_command(full), self.EXE + " --probe")
        raw = fake_raw()
        raw["sys"]["tasks"] = [full, r"\Microsoft\Windows\Something\Ms"]
        res = bc.analyze(raw)
        f = next((x for x in res["findings"] if x["id"] == "task_item@" + full), None)
        self.assertIsNotNone(f, "第三方开机任务没出现在体检结果里")
        self.assertEqual(f["cat"], "开机自启")
        self.assertEqual(set(f["opts"]), {"block"})
        self.assertEqual(f["fix"], {"type": "task_off", "risk": "safe", "items": [full]})
        self.assertFalse(any(x["id"].startswith("task_item@\\Microsoft") for x in res["findings"]),
                         "微软自家任务不该列出来")

        ok, msg = bc._set_task_enabled(full, False)
        self.assertTrue(ok, msg)
        self.assertNotIn(full, bc.boot_logon_tasks_from_xml(), "禁止后还在开机任务列表里")
        ok, msg = bc._set_task_enabled(full, True)
        self.assertTrue(ok, msg)
        self.assertIn(full, bc.boot_logon_tasks_from_xml())

    def test_backup_restore_roundtrip(self):
        """走完整的 备份 → 执行 → 还原 流程，和界面上点「智能优化」「还原」一样。"""
        full = self.TP + self.TN
        f = {"id": "task_item@" + full, "title": "t",
             "fix": {"type": "task_off", "risk": "safe", "items": [full]}}
        with tempfile.TemporaryDirectory() as td:
            bdir = bc.make_backup([f], backup_root=td, tag="ut")
            res = bc.apply_fixes([f], bdir)
            self.assertTrue(all(r.get("ok", True) for r in (res if isinstance(res, list) else [res])),
                            res)
            self.assertNotIn(full, bc.boot_logon_tasks_from_xml())
            rr = bc.restore_backup(bdir)
            self.assertTrue(rr, "还原没有返回结果")
            self.assertIn(full, bc.boot_logon_tasks_from_xml(), "还原后任务没有重新启用")


class TestSigner(unittest.TestCase):
    """真实签名者：公司名是文件自己填的，不能当凭据；数字签名才是。"""
    SYS = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")

    def _system_exes(self, names=("cmd.exe", "svchost.exe", "notepad.exe", "find.exe", "hostname.exe")):
        out = [os.path.join(self.SYS, n) for n in names if os.path.isfile(os.path.join(self.SYS, n))]
        if not out:
            self.skipTest("找不到可用的系统程序")
        return out

    def test_system_files_signed_by_microsoft(self):
        """系统自带程序：签名有效（内嵌或目录），且能取到「Microsoft …」签名者。"""
        bad = []
        for exe in self._system_exes():
            sig = bc.app_signature(bc.describe_app(exe))
            if not bc.real_microsoft(sig):
                bad.append((os.path.basename(exe), {k: sig.get(k) for k in
                                                   ("state", "signer", "signer_ok", "rc")}))
        self.assertEqual(bad, [], "这些系统文件没认成「微软自己签的」")

    def test_non_microsoft_signer(self):
        sig = bc.app_signature(bc.describe_app(sys.executable))
        if sig["state"] != "valid":
            self.skipTest("这台机器上的 python.exe 没有内嵌签名：%s" % sig["state"])
        self.assertTrue(sig["signer"], "签名有效却没取到签名者")
        self.assertFalse(bc._ms_ish(sig["signer"]), sig["signer"])
        self.assertFalse(bc.real_microsoft(sig))

    def test_spoofed_company_is_not_microsoft(self):
        fake = dict(bc.describe_app(sys.executable), company="Microsoft Corporation")
        self.assertFalse(bc.is_microsoft(fake), "公司名写成 Microsoft 就被当成了微软组件")
        real = bc.describe_app(self._system_exes()[0])
        self.assertTrue(bc.is_microsoft(real), "真正的系统程序被当成了第三方")
        # 没有证据可反驳时沿用以前的行为（文件不在 / 没路径），不制造误判
        self.assertTrue(bc.is_microsoft({"company": "Microsoft Corporation"}))
        self.assertFalse(bc.is_microsoft({"company": "Some Ltd", "path": sys.executable}))

    def test_adware_exemption_needs_real_signature(self):
        name = "鲁大师游戏盒子"
        with tempfile.TemporaryDirectory() as td:
            d = os.path.join(td, "LuDaShi")
            os.makedirs(d)
            fake = os.path.join(d, "ldsgame.exe")
            shutil.copy(sys.executable, fake)
            genuine = os.path.join(d, "real.exe")
            shutil.copy(self._system_exes()[0], genuine)

            plain = bc.adware_check(path=fake, name=name, company="Some Ltd")
            self.assertTrue(plain.get("hit"), "路径里有 LuDaShi 应当命中家族规则")
            self.assertFalse(plain.get("spoof"))

            spoof = bc.adware_check(path=fake, name=name, company="Microsoft Corporation")
            self.assertTrue(spoof.get("hit"), "把公司名改成 Microsoft 就躲过了检测")
            self.assertTrue(spoof.get("spoof"))
            self.assertEqual(spoof["sev"], "high")
            self.assertIn("不是微软", spoof["why"] + "没有微软的数字签名")

            # 真正微软签名的文件即使放在黑名单目录里也放过（和以前一样，不误报系统组件）
            ok = bc.adware_check(path=genuine, name=name, company="Microsoft Corporation")
            self.assertFalse(ok.get("hit"), "真微软签名的文件被误报：%s" % ok.get("why"))

    def test_spoof_finding_in_analyze(self):
        orig = bc._file_version_info
        with tempfile.TemporaryDirectory() as td:
            fake = os.path.join(td, "WinHelperSvc.exe")
            shutil.copy(sys.executable, fake)
            real = self._system_exes()[0]

            def fvi(path):
                if path.lower() == fake.lower():
                    return {"CompanyName": "Microsoft Corporation",
                            "FileDescription": "Windows Helper"}
                return orig(path)

            bc._file_version_info = fvi
            bc._APP_CACHE.clear()
            try:
                raw = fake_raw()
                for nm, cmd in (("WinHelper", fake), ("RealOne", real)):
                    raw["startup"].append({"name": nm, "cmd": cmd, "source": "用户 Run",
                                           "kind": "run", "hive": "HKCU", "subkey": None,
                                           "enabled": True})
                res = bc.analyze(raw)
            finally:
                bc._file_version_info = orig
                bc._APP_CACHE.clear()
        spoofs = {f["id"]: f for f in res["findings"] if f["id"].startswith("ms_spoof@")}
        self.assertIn("ms_spoof@" + fake.lower(), spoofs, "冒充微软的文件没被报出来：%s" % list(spoofs))
        self.assertIn(spoofs["ms_spoof@" + fake.lower()]["sev"], ("high", "mid"))
        self.assertNotIn("ms_spoof@" + real.lower(), spoofs, "真正的系统程序被报成冒充")

    def test_warm_signatures_parallel(self):
        import time as _t
        infos = [bc.describe_app(p) for p in self._system_exes()]
        t0 = _t.perf_counter()
        n = bc.warm_signatures(infos)
        self.assertEqual(n, len(infos))
        self.assertLess(_t.perf_counter() - t0, 10)
        for a in infos:
            self.assertIn(a["path"].lower() in {x["path"].lower() for x in infos}, (True,))


class TestLauncher(unittest.TestCase):
    def test_bat_finds_python(self):
        """启动体检.bat 去掉了写死的路径兜底后，必须还能找到 pythonw（真跑一遍 bat 的查找逻辑）。"""
        import subprocess
        src = os.path.join(BASE, "启动体检.bat")
        with open(src, "rb") as fp:
            data = fp.read()
        # 把真正启动程序的那一行换成 echo，其余原样执行
        probe = [b"echo PY=[%PY%]" if ln.lstrip().lower().startswith(b"start ") else ln
                 for ln in data.split(b"\n")]
        with tempfile.TemporaryDirectory() as td:
            bat = os.path.join(td, "probe.bat")
            with open(bat, "wb") as fp:
                fp.write(b"\r\n".join(x.rstrip(b"\r") for x in probe))
            out = subprocess.run(["cmd", "/c", bat], capture_output=True, cwd=td,
                                 creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        txt = out.stdout.decode("gbk", "replace")
        m = [ln for ln in txt.splitlines() if ln.startswith("PY=[")]
        self.assertTrue(m, txt[-500:])
        self.assertRegex(m[0].lower(), r"pythonw?\.exe\]|pyw(\.exe)?\]", txt[-500:])


def _make_lnk(path, target, args="", workdir=""):
    """用 COM 造一个真的 .lnk（测试夹具）。"""
    env = dict(os.environ, BD_P=path, BD_T=target, BD_A=args, BD_W=workdir)
    out = bc.run_ps("$s=(New-Object -ComObject WScript.Shell).CreateShortcut($env:BD_P);"
                    "$s.TargetPath=$env:BD_T;$s.Arguments=$env:BD_A;"
                    "if($env:BD_W){$s.WorkingDirectory=$env:BD_W};$s.Save();'OK'", timeout=60, env=env)
    assert "OK" in out and os.path.isfile(path), "造 lnk 失败：%r（%s）" % (out, path)


def _com_read_lnk(path):
    env = dict(os.environ, BD_P=path)
    out = bc.run_ps("$s=(New-Object -ComObject WScript.Shell).CreateShortcut($env:BD_P);"
                    "Write-Output ($s.TargetPath+[char]9+$s.Arguments)", timeout=60, env=env)
    parts = out.strip("\r\n").split("\t")
    return parts[0], (parts[1] if len(parts) > 1 else "")


class TestLnkParser(unittest.TestCase):
    """原生 .lnk 解析必须和 COM（WScript.Shell）读出来的一致，否则体检里的应用识别会走偏。"""

    def test_matches_com(self):
        np = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "notepad.exe")
        cases = [(np, ""), (np, "a b"), (sys.executable, '--x "C:\\Temp\\y z" https://a.b/c?d=1')]
        with tempfile.TemporaryDirectory() as td:
            for i, (tgt, args) in enumerate(cases):
                lnk = os.path.join(td, "t%d.lnk" % i)
                _make_lnk(lnk, tgt, args)
                nat = bc.parse_lnk(lnk)
                self.assertIsNotNone(nat, "解析不出来：%s" % lnk)
                ct, ca = _com_read_lnk(lnk)
                self.assertEqual(os.path.normcase(nat["target"]), os.path.normcase(ct), lnk)
                self.assertEqual(nat["args"], ca)

    def test_unicode_name_and_bulk_without_powershell(self):
        """中文文件名 + 批量解析走原生：把 run_ps 换成会抛异常的，也必须解析成功。"""
        with tempfile.TemporaryDirectory() as td:
            # WScript.Shell 的 Save 在非中文代码页的系统上存不了中文路径（run_ps 会吞掉报错，
            # 照样输出 OK），所以先用英文名造，再改名成中文名——解析器读的是文件内容，和文件名无关
            tmp = os.path.join(td, "chrome_link.lnk")
            _make_lnk(tmp, sys.executable, "--profile-directory=Default")
            lnk = os.path.join(td, "谷歌浏览器.lnk")
            os.rename(tmp, lnk)
            self.assertTrue(os.path.isfile(lnk), "目录里是：%r" % (os.listdir(td),))
            old = bc.run_ps
            bc.run_ps = lambda *a, **k: (_ for _ in ()).throw(AssertionError("不该起 PowerShell"))
            bc._LNK_CACHE.pop(lnk, None)
            try:
                self.assertEqual(bc.resolve_shortcuts_bulk([lnk]), 1)
            finally:
                bc.run_ps = old
            tgt, args = bc._LNK_CACHE[lnk]
            self.assertEqual(os.path.normcase(tgt), os.path.normcase(sys.executable))
            self.assertEqual(args, "--profile-directory=Default")

    def test_garbage_is_none(self):
        self.assertIsNone(bc.parse_lnk_bytes(b""))
        self.assertIsNone(bc.parse_lnk_bytes(b"x" * 200))
        self.assertIsNone(bc.parse_lnk(os.path.join(tempfile.gettempdir(), "__no_such__.lnk")))


class TestBrowserHijack(unittest.TestCase):
    TESTKEY = r"Software\BootDoctorUnitTest\Hijack"

    def setUp(self):
        import winreg
        self.wr = winreg
        bc._delete_key_tree(winreg.HKEY_CURRENT_USER, r"Software\BootDoctorUnitTest")

    def tearDown(self):
        bc._delete_key_tree(self.wr.HKEY_CURRENT_USER, r"Software\BootDoctorUnitTest")

    def _collect(self, d):
        got = []
        bc._hijack_findings(d, lambda **kw: got.append(kw))
        return {f["id"]: f for f in got}

    # ---------------- 采集 ----------------
    def test_tcp_listeners_sees_my_socket(self):
        import socket
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        try:
            port = srv.getsockname()[1]
            ls = bc.tcp_listeners()
            self.assertIn(("127.0.0.1", port), ls)
            self.assertEqual(ls[("127.0.0.1", port)], os.getpid())
        finally:
            srv.close()

    def test_collect_hijack_real_machine(self):
        import time as _t
        t0 = _t.perf_counter()
        d = bc.collect_hijack()
        dt = _t.perf_counter() - t0
        for k in ("managed", "proxy", "policies", "ie", "hosts", "lnks"):
            self.assertIn(k, d)
        self.assertTrue(d["hosts"].get("exists"), "找不到 hosts 文件")
        self.assertLess(dt, 3.0, "采集太慢：%.2fs" % dt)
        print("  collect_hijack %.0f ms, lnks=%d policies=%d" % (dt * 1000, len(d["lnks"]), len(d["policies"])))

    def test_read_proxy_state_roundtrip(self):
        base = bc._INET
        old = bc.read_proxy_state()
        try:
            with self.wr.CreateKeyEx(self.wr.HKEY_CURRENT_USER, base, 0, self.wr.KEY_SET_VALUE) as k:
                self.wr.SetValueEx(k, "ProxyEnable", 0, self.wr.REG_DWORD, 1)
                self.wr.SetValueEx(k, "ProxyServer", 0, self.wr.REG_SZ, "127.0.0.1:1")
            st = bc.read_proxy_state()
            self.assertEqual((st["enable"], st["server"]), (1, "127.0.0.1:1"))
        finally:
            with self.wr.CreateKeyEx(self.wr.HKEY_CURRENT_USER, base, 0, self.wr.KEY_SET_VALUE) as k:
                self.wr.SetValueEx(k, "ProxyEnable", 0, self.wr.REG_DWORD, int(old.get("enable") or 0))
                if old.get("server"):
                    self.wr.SetValueEx(k, "ProxyServer", 0, self.wr.REG_SZ, old["server"])
                else:
                    try:
                        self.wr.DeleteValue(k, "ProxyServer")
                    except OSError:
                        pass

    # ---------------- 分析 ----------------
    def test_proxy_dead_vs_alive_vs_remote(self):
        base = {"managed": False, "policies": [], "ie": [], "hosts": {}, "lnks": []}
        dead = self._collect(dict(base, proxy={"enable": 1, "server": "127.0.0.1:7890"}, listeners=[]))
        self.assertIn("hij_proxy_dead", dead)
        self.assertEqual(dead["hij_proxy_dead"]["fix"]["items"][0]["name"], "ProxyEnable")
        alive = self._collect(dict(base, proxy={"enable": 1, "server": "127.0.0.1:7890"},
                                   listeners=[["0.0.0.0", 7890, os.getpid()]]))
        self.assertIn("hij_proxy_local", alive)
        self.assertNotIn("hij_proxy_dead", alive)
        self.assertEqual(alive["hij_proxy_local"]["sev"], "info")
        remote = self._collect(dict(base, proxy={"enable": 1, "server": "8.8.8.8:3128"}))
        self.assertEqual(remote["hij_proxy_remote"]["sev"], "mid")
        self.assertTrue(remote["hij_proxy_remote"]["fix"])
        managed = self._collect(dict(base, managed=True, proxy={"enable": 1, "server": "8.8.8.8:3128"}))
        self.assertEqual(managed["hij_proxy_remote"]["sev"], "info")
        self.assertIsNone(managed["hij_proxy_remote"]["fix"], "受管理的电脑不该建议改代理")
        off = self._collect(dict(base, proxy={"enable": 0, "server": "127.0.0.1:7890"}))
        self.assertFalse([k for k in off if k.startswith("hij_proxy")], "代理没开就不该报")
        pac = self._collect(dict(base, proxy={"enable": 0, "pac": "http://evil.example/p.pac"}))
        self.assertIn("hij_pac", pac)

    def test_policy_and_ie_findings(self):
        pol = [{"browser": "Chrome", "hive": "HKLM", "subkey": r"SOFTWARE\Policies\Google\Chrome",
                "name": "HomepageLocation", "value": "https://www.hao123.com/?tn=x"}]
        base = {"proxy": {}, "hosts": {}, "lnks": [], "ie": []}
        f = self._collect(dict(base, managed=False, policies=pol))["hij_policy@Chrome"]
        self.assertEqual(f["sev"], "high", "导航站主页应报高危")
        self.assertEqual(f["fix"]["items"][0]["action"], "delete")
        f2 = self._collect(dict(base, managed=True, policies=pol))["hij_policy@Chrome"]
        self.assertEqual(f2["sev"], "info")
        self.assertIsNone(f2["fix"])
        ie = self._collect(dict(base, managed=False, policies=[],
                                ie=[{"name": "Start Page", "value": "http://www.2345.com/?x"},
                                    {"name": "Search Page", "value": "https://www.bing.com"}]))
        self.assertEqual([i["name"] for i in ie["hij_ie_start"]["fix"]["items"]], ["Start Page"])

    def test_hosts_findings(self):
        text = ("127.0.0.1 localhost\n127.0.0.1 update.microsoft.com\n"
                "45.33.32.156 www.icbc.com.cn # x\n45.33.32.156 www.baidu.com\n140.82.112.3 github.com\n")
        d = {"managed": False, "proxy": {}, "policies": [], "ie": [], "lnks": [],
             "hosts": {"path": r"C:\x\hosts", "text": text, "database_path": ""}}
        got = self._collect(d)
        self.assertEqual({"hij_hosts_block", "hij_hosts_bank", "hij_hosts_popular", "hij_hosts_other"} & set(got),
                         {"hij_hosts_block", "hij_hosts_bank", "hij_hosts_popular", "hij_hosts_other"})
        self.assertIsNone(got["hij_hosts_other"].get("fix"), "github 加速这类不建议自动删")
        self.assertEqual(got["hij_hosts_bank"]["sev"], "high")
        d["hosts"]["database_path"] = r"D:\evil"
        self.assertIn("hij_hosts_path", self._collect(d))
        d["hosts"]["database_path"] = os.path.dirname(bc.HOSTS_PATH)
        self.assertNotIn("hij_hosts_path", self._collect(d), "默认位置不该报")

    def test_shortcut_scan_and_detect_real_files(self):
        with tempfile.TemporaryDirectory() as td:
            fake_chrome = os.path.join(td, "chrome.exe")
            shutil.copy(sys.executable, fake_chrome)
            bad = os.path.join(td, "Google Chrome.lnk")
            ok = os.path.join(td, "Microsoft Edge.lnk")
            other = os.path.join(td, "Notepad.lnk")
            _make_lnk(bad, fake_chrome, "https://www.hao123.com/?tn=x --profile-directory=Default")
            _make_lnk(ok, fake_chrome, "--profile-directory=Default")
            _make_lnk(other, os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                                          "System32", "notepad.exe"))
            found = {e["name"]: e for e in bc.scan_browser_shortcuts(roots=[(td, 1)])}
            self.assertEqual(set(found), {"Google Chrome", "Microsoft Edge"}, "不相干的快捷方式不该进来")
            r = bc.analyze_shortcut(found["Google Chrome"])
            self.assertEqual((r["verdict"], r["sev"]), ("nav_url", "high"))
            self.assertEqual(r["new_args"], "--profile-directory=Default", "只该去掉网址，别的参数留着")
            self.assertIsNone(bc.analyze_shortcut(found["Microsoft Edge"]))

    # ---------------- 处理：备份 → 执行 → 还原 ----------------
    def _roundtrip(self, findings, td):
        bdir = bc.make_backup(findings, backup_root=td, tag="ut")
        res = bc.apply_fixes(findings, bdir)
        self.assertTrue(all(r["ok"] for r in res), res)
        return bdir

    def test_reg_edit_backup_apply_restore(self):
        W = self.wr
        with W.CreateKeyEx(W.HKEY_CURRENT_USER, self.TESTKEY, 0, W.KEY_SET_VALUE) as k:
            W.SetValueEx(k, "ProxyEnable", 0, W.REG_DWORD, 1)
            W.SetValueEx(k, "ProxyServer", 0, W.REG_SZ, "127.0.0.1:7890")
            W.SetValueEx(k, "Multi", 0, W.REG_MULTI_SZ, ["a", "b"])
            W.SetValueEx(k, "Bin", 0, W.REG_BINARY, b"\x01\x02\xff")
        items = [
            {"hive": "HKCU", "subkey": self.TESTKEY, "name": "ProxyEnable", "action": "set", "type": W.REG_DWORD, "value": 0},
            {"hive": "HKCU", "subkey": self.TESTKEY, "name": "ProxyServer", "action": "delete"},
            {"hive": "HKCU", "subkey": self.TESTKEY, "name": "Multi", "action": "delete"},
            {"hive": "HKCU", "subkey": self.TESTKEY, "name": "Bin", "action": "delete"},
            {"hive": "HKCU", "subkey": self.TESTKEY, "name": "Brand", "action": "set", "type": W.REG_SZ, "value": "new"},
        ]
        f = {"id": "t", "title": "t", "fix": {"type": "reg_edit", "risk": "confirm", "items": items}}

        def read(n):
            try:
                with W.OpenKey(W.HKEY_CURRENT_USER, self.TESTKEY) as k:
                    return W.QueryValueEx(k, n)
            except OSError:
                return None
        with tempfile.TemporaryDirectory() as td:
            bdir = self._roundtrip([f], td)
            self.assertEqual(read("ProxyEnable")[0], 0)
            self.assertIsNone(read("ProxyServer"))
            self.assertIsNone(read("Multi"))
            self.assertEqual(read("Brand")[0], "new")
            reg = open(os.path.join(bdir, "restore-all.reg"), encoding="utf-16").read()
            self.assertIn('"ProxyEnable"=dword:00000001', reg)
            self.assertIn('"Brand"=-', reg, "原来没有的值，.reg 里应写成删除")
            self.assertIn("hex(7):", reg)
            rr = bc.restore_backup(bdir)
            self.assertTrue(all(r["ok"] for r in rr), rr)
        self.assertEqual(read("ProxyEnable"), (1, W.REG_DWORD))
        self.assertEqual(read("ProxyServer"), ("127.0.0.1:7890", W.REG_SZ))
        self.assertEqual(read("Multi"), (["a", "b"], W.REG_MULTI_SZ))
        self.assertEqual(read("Bin"), (b"\x01\x02\xff", W.REG_BINARY))
        self.assertIsNone(read("Brand"), "还原后应删掉新建的值")

    def test_hosts_clean_backup_apply_restore(self):
        import stat
        orig = ("# 注释\r\n127.0.0.1 localhost\r\n127.0.0.1 update.microsoft.com  # x\r\n"
                "45.33.32.156 www.icbc.com.cn\r\n10.0.0.1 nas\r\n").encode("utf-8")
        with tempfile.TemporaryDirectory() as td:
            hp = os.path.join(td, "hosts")
            with open(hp, "wb") as fp:
                fp.write(orig)
            os.chmod(hp, stat.S_IREAD)                     # 常见：hosts 被设成只读
            rows = bc.analyze_hosts(orig.decode("utf-8"))
            lines = [r["norm"] for r in rows if r["verdict"] in ("block_security", "redirect_bank")]
            self.assertEqual(len(lines), 2)
            f = {"id": "h", "title": "h", "fix": {"type": "hosts_clean", "risk": "confirm",
                                                  "items": [{"path": hp, "lines": lines}]}}
            bdir = self._roundtrip([f], os.path.join(td, "bak"))
            with open(hp, "rb") as fp:
                now = fp.read()
            self.assertEqual(now, b"# \xe6\xb3\xa8\xe9\x87\x8a\r\n127.0.0.1 localhost\r\n10.0.0.1 nas\r\n",
                             "只该删掉被标记的行，注释 / 其他行 / CRLF 原样保留")
            self.assertFalse(os.access(hp, os.W_OK), "只读属性应该还原回去")
            rr = bc.restore_backup(bdir)
            self.assertTrue(all(r["ok"] for r in rr), rr)
            with open(hp, "rb") as fp:
                self.assertEqual(fp.read(), orig, "还原后应与原文件逐字节一致")
            os.chmod(hp, stat.S_IWRITE)

    def test_hosts_clean_gbk_encoding_kept(self):
        orig = "# 中文注释\n127.0.0.1 www.360.cn\n10.0.0.1 nas\n".encode("gbk")
        with tempfile.TemporaryDirectory() as td:
            hp = os.path.join(td, "hosts")
            with open(hp, "wb") as fp:
                fp.write(orig)
            ok, msg = bc._clean_hosts_file(hp, ["127.0.0.1 www.360.cn"])
            self.assertTrue(ok, msg)
            with open(hp, "rb") as fp:
                self.assertEqual(fp.read(), "# 中文注释\n10.0.0.1 nas\n".encode("gbk"))

    def test_lnk_args_backup_apply_restore(self):
        with tempfile.TemporaryDirectory() as td:
            lnk = os.path.join(td, "Google Chrome.lnk")
            _make_lnk(lnk, sys.executable, "https://www.hao123.com/ --profile-directory=Default")
            f = {"id": "l", "title": "l", "fix": {"type": "lnk_args", "risk": "confirm", "items": [
                {"path": lnk, "args": "https://www.hao123.com/ --profile-directory=Default",
                 "new_args": "--profile-directory=Default"}]}}
            bdir = self._roundtrip([f], os.path.join(td, "bak"))
            self.assertEqual(bc.parse_lnk(lnk)["args"], "--profile-directory=Default")
            self.assertEqual(os.path.normcase(bc.parse_lnk(lnk)["target"]), os.path.normcase(sys.executable))
            rr = bc.restore_backup(bdir)
            self.assertTrue(all(r["ok"] for r in rr), rr)
            self.assertEqual(bc.parse_lnk(lnk)["args"], "https://www.hao123.com/ --profile-directory=Default")

    # ---------------- 接进体检 / 界面 ----------------
    def test_analyze_and_gui_integration(self):
        from PyQt5.QtWidgets import QApplication
        import boot_doctor as bd
        app = QApplication.instance() or QApplication([])  # noqa: F841
        raw = fake_raw()
        raw["hijack"] = {"managed": False, "proxy": {"enable": 1, "server": "127.0.0.1:7890"},
                         "listeners": [], "policies": [], "ie": [], "lnks": [],
                         "hosts": {"path": r"C:\x\hosts", "database_path": "",
                                   "text": "127.0.0.1 www.360.cn\n"}}
        res = bc.analyze(raw)
        hij = [f for f in res["findings"] if f["cat"] == "浏览器劫持"]
        self.assertEqual({f["id"] for f in hij}, {"hij_proxy_dead", "hij_hosts_block"})
        for f in hij:
            self.assertIn(f["fix"]["type"], bc.FIX_DESC)
            self.assertFalse(f["default"], "劫持类处理默认不勾选，由用户决定")
        self.assertLess(res["score"], bc.analyze(fake_raw())["score"], "有问题要扣分")
        win = bd.MainWindow(autoscan=False)
        try:
            win.on_scan_done(raw, res)
            cats = [win.tree.topLevelItem(i).text(0) for i in range(win.tree.topLevelItemCount())]
            self.assertTrue(any("浏览器劫持" in c for c in cats), cats)
        finally:
            win.close()


class TestInstantOpen(unittest.TestCase):
    """打开程序先显示上次的体检结果，后台再刷新。"""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._p = os.path.join(self._tmp, "last_scan.json")
        self._old_path = bc.last_scan_path
        bc.last_scan_path = lambda: self._p
        self._old_setting = bc.get_setting("show_last_scan", True)

    def tearDown(self):
        bc.last_scan_path = self._old_path
        bc.set_setting("show_last_scan", self._old_setting)
        shutil.rmtree(self._tmp, ignore_errors=True)

    @staticmethod
    def _ids(res):
        return sorted(f["id"] for f in res["findings"])

    def test_roundtrip_gives_same_analysis(self):
        raw = fake_raw_multi()
        self.assertTrue(bc.save_last_scan(raw))
        back, ts = bc.load_last_scan()
        self.assertIsNotNone(back)
        self.assertLess(abs(ts - __import__("time").time()), 30)
        self.assertEqual(self._ids(bc.analyze(back)), self._ids(bc.analyze(raw)))

    def test_roundtrip_real_machine_data(self):
        """真实采集的数据过一遍 JSON 再分析，结果必须一样——防止缓存里有 JSON 存不回来的东西。"""
        raw = bc.collect()
        self.assertTrue(bc.save_last_scan(raw), "真实数据存不进 JSON")
        back, _ts = bc.load_last_scan()
        self.assertIsNotNone(back)
        self.assertEqual(self._ids(bc.analyze(back)), self._ids(bc.analyze(raw)))
        print("  缓存文件 %d KB" % (os.path.getsize(self._p) // 1024))

    def test_bad_or_old_cache_is_ignored(self):
        import json
        import time as _t
        self.assertEqual(bc.load_last_scan(), (None, 0.0))                       # 没有
        with open(self._p, "w", encoding="utf-8") as fp:
            fp.write("{ 坏了")
        self.assertEqual(bc.load_last_scan(), (None, 0.0))                       # 损坏
        with open(self._p, "w", encoding="utf-8") as fp:
            json.dump({"saved": _t.time(), "raw": {"startup": []}}, fp)
        self.assertEqual(bc.load_last_scan(), (None, 0.0))                       # 缺关键字段
        with open(self._p, "w", encoding="utf-8") as fp:
            json.dump({"saved": _t.time() - 20 * 86400,
                       "raw": {"startup": [], "services": [], "sys": {}}}, fp)
        self.assertEqual(bc.load_last_scan(), (None, 0.0))                       # 超过 14 天
        self.assertEqual(bc.age_text(10), "刚刚")
        self.assertEqual(bc.age_text(600), "10 分钟前")
        self.assertEqual(bc.age_text(7200), "2 小时前")
        self.assertEqual(bc.age_text(3 * 86400), "3 天前")

    def _window(self):
        from PyQt5.QtWidgets import QApplication
        import boot_doctor as bd
        self.app = QApplication.instance() or QApplication([])
        win = bd.MainWindow(autoscan=False)
        win.start_scan = lambda: None                 # 别真去体检
        return win

    def test_cached_shown_then_fresh_keeps_user_checks(self):
        from PyQt5.QtCore import Qt
        win = self._window()
        try:
            old = fake_raw_multi()
            bc.save_last_scan(old)
            win._show_cached_then_scan()
            self.assertTrue(win._stale)
            self.assertGreater(win.tree.topLevelItemCount(), 0, "缓存结果没摆出来")
            self.assertTrue(win.lbl_status.text().startswith("上次体检"), win.lbl_status.text())
            self.assertIn("上次体检结果", win.lbl_summary.text())
            first_saved = os.path.getmtime(self._p)

            # 用户在缓存结果上勾了一项默认不勾的
            pick = None
            for i in range(win.tree.topLevelItemCount()):
                p = win.tree.topLevelItem(i)
                for j in range(p.childCount()):
                    ch = p.child(j)
                    f = win._finding_of_item(ch)
                    if f and f.get("fix") and not f.get("default"):
                        pick = (ch, f["id"])
                        break
                if pick:
                    break
            self.assertIsNotNone(pick, "样例里没有默认不勾的可处理项")
            win._check_items([pick[0]], True)

            import time as _t
            _t.sleep(0.05)
            new = fake_raw_multi()
            win.on_scan_done(new, bc.analyze(new))          # 新结果到了
            self.assertFalse(win._stale)
            checked = {f["id"] for f in win._checked_findings()}
            self.assertIn(pick[1], checked, "刷新后用户勾的项丢了")
            self.assertGreaterEqual(os.path.getmtime(self._p), first_saved)
            for i in range(win.tree.topLevelItemCount()):
                p = win.tree.topLevelItem(i)
                for j in range(p.childCount()):
                    if win._finding_of_item(p.child(j)) and win._finding_of_item(p.child(j))["id"] == pick[1]:
                        self.assertEqual(p.child(j).checkState(0), Qt.Checked)
        finally:
            win.close()

    def test_no_apply_while_refreshing(self):
        import types
        win = self._window()
        try:
            raw = fake_raw_multi()
            win.on_scan_done(raw, bc.analyze(raw))
            fs = [f for f in win.result["findings"] if f.get("fix")][:2]
            self.assertTrue(fs)
            win._check_items([it for it in [win.tree.topLevelItem(i).child(j)
                                            for i in range(win.tree.topLevelItemCount())
                                            for j in range(win.tree.topLevelItem(i).childCount())]
                              if win._finding_of_item(it) and win._finding_of_item(it).get("fix")][:2], True)
            win.scan_worker = types.SimpleNamespace(isRunning=lambda: True)   # 假装正在刷新
            old = bc.make_backup
            bc.make_backup = lambda *a, **k: (_ for _ in ()).throw(AssertionError("刷新中不该执行修复"))
            try:
                win.on_apply()
                win._run_findings(fs)
            finally:
                bc.make_backup = old
        finally:
            win.scan_worker = None
            win.close()

    def test_setting_can_turn_it_off(self):
        win = self._window()
        try:
            bc.save_last_scan(fake_raw_multi())
            bc.set_setting("show_last_scan", False)
            win._show_cached_then_scan()
            self.assertFalse(win._stale)
            self.assertIsNone(win.result, "关了开关还是显示了缓存")
        finally:
            win.close()


class _TestWindow(object):
    """在测试进程里开一个真的顶层窗口（独立线程 + 消息循环），用来喂给守护进程。

    窗口过程直接用 DefWindowProcW：收到 WM_CLOSE 默认就会 DestroyWindow，
    所以「守护发了 WM_CLOSE」的效果能从 IsWindow 直接看出来。
    """
    _n = 0

    def __init__(self, title, cls=None):
        import threading
        _TestWindow._n += 1
        self.title = title
        self.cls = cls or "BDE2EClass%d" % _TestWindow._n
        self.hwnd = 0
        self.tid = 0
        self.shown_at = 0.0
        self._ready = threading.Event()
        self._u = ctypes.WinDLL("user32", use_last_error=True)
        self._t = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        import ctypes.wintypes as wt
        u = self._u
        k = ctypes.WinDLL("kernel32")

        class WNDCLASSW(ctypes.Structure):
            _fields_ = [("style", wt.UINT), ("lpfnWndProc", ctypes.c_void_p),
                        ("cbClsExtra", ctypes.c_int), ("cbWndExtra", ctypes.c_int),
                        ("hInstance", wt.HANDLE), ("hIcon", wt.HANDLE), ("hCursor", wt.HANDLE),
                        ("hbrBackground", wt.HANDLE), ("lpszMenuName", wt.LPCWSTR),
                        ("lpszClassName", wt.LPCWSTR)]
        u.RegisterClassW.argtypes = [ctypes.POINTER(WNDCLASSW)]
        u.CreateWindowExW.restype = wt.HWND
        u.CreateWindowExW.argtypes = [wt.DWORD, wt.LPCWSTR, wt.LPCWSTR, wt.DWORD, ctypes.c_int,
                                      ctypes.c_int, ctypes.c_int, ctypes.c_int, wt.HWND, wt.HANDLE,
                                      wt.HANDLE, ctypes.c_void_p]
        u.ShowWindow.argtypes = [wt.HWND, ctypes.c_int]
        u.GetMessageW.argtypes = [ctypes.POINTER(wt.MSG), wt.HWND, wt.UINT, wt.UINT]
        k.GetModuleHandleW.restype = wt.HANDLE
        k.GetModuleHandleW.argtypes = [wt.LPCWSTR]
        hinst = k.GetModuleHandleW(None)
        wc = WNDCLASSW()
        wc.lpfnWndProc = ctypes.cast(u.DefWindowProcW, ctypes.c_void_p).value
        wc.hInstance = hinst
        wc.lpszClassName = self.cls
        u.RegisterClassW(ctypes.byref(wc))
        # 先建成隐藏的，再显式 ShowWindow：这样「窗口显示」事件是确定会发出的，量到的是钩子延迟
        self.hwnd = u.CreateWindowExW(0x8, self.cls, self.title, 0x00CF0000, 120, 120, 320, 200,
                                      None, None, hinst, None)
        self.tid = k.GetCurrentThreadId()
        self._ready.set()
        msg = wt.MSG()
        while u.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            u.TranslateMessage(ctypes.byref(msg))
            u.DispatchMessageW(ctypes.byref(msg))

    def start(self):
        self._t.start()
        assert self._ready.wait(10) and self.hwnd, "窗口没建出来：%s" % ctypes.get_last_error()
        return self

    def show(self):
        import time as _t
        self.shown_at = _t.perf_counter()
        self._u.ShowWindow(self.hwnd, 5)

    def alive(self):
        return bool(self._u.IsWindow(self.hwnd))

    def wait_closed(self, timeout):
        """等窗口被销毁，返回从 show() 起经过的秒数；超时返回 None。"""
        import time as _t
        end = _t.perf_counter() + timeout
        while _t.perf_counter() < end:
            if not self.alive():
                return _t.perf_counter() - self.shown_at
            _t.sleep(0.02)
        return None

    def stop(self):
        try:
            if self.alive():
                self._u.SendMessageTimeoutW(self.hwnd, 0x0010, 0, 0, 2, 500, None)   # WM_CLOSE
            self._u.PostThreadMessageW(self.tid, 0x0012, 0, 0)                       # WM_QUIT
        except Exception:
            pass


class _GuardE2EBase(unittest.TestCase):
    """真正的 popup_guard.py 进程的测试底座：数据隔离到临时目录，按真实平台（非离屏）启动守护。

    子类可覆盖 make_rules() / make_env() / before_start()。

    以前「守护」只有一个替身脚本的测试，真正的守护进程从没在 Windows 上跑过。
    数据（规则 / 日志 / pid）通过 BOOTDOC_DATA_DIR 隔离到临时目录。
    """
    PROBE = "BootDoctorE2EProbe"
    RUN = r"Software\Microsoft\Windows\CurrentVersion\Run"

    @classmethod
    def make_rules(cls):
        return {"enabled": True, "auto_adware": False, "poll_ms": 1200, "watch_autostart": True,
                "watch_process": False,
                "block": [{"kind": "title", "pattern": "BootDoctorE2EPopup", "note": "e2e"}],
                "allow": []}

    @classmethod
    def make_env(cls):
        return {}

    @classmethod
    def before_start(cls):
        pass

    @classmethod
    def setUpClass(cls):
        import time as _t
        cls.td = tempfile.mkdtemp(prefix="bd_e2e_")
        cls._env = os.environ.get("BOOTDOC_DATA_DIR")
        os.environ["BOOTDOC_DATA_DIR"] = cls.td                  # 子进程继承
        cls._saved = {k: getattr(bc, k) for k in ("DATA_DIR", "LOG_DIR", "POPUP_RULES_PATH",
                                                    "GUARD_PID_PATH", "GUARD_STOP_PATH",
                                                    "AUTOSTART_BASELINE", "AUTOSTART_WATCH_LOG",
                                                    "PROC_WATCH_LOG")}
        bc.DATA_DIR = cls.td
        bc.LOG_DIR = os.path.join(cls.td, "_logs")
        bc.POPUP_RULES_PATH = os.path.join(cls.td, "_popup_rules.json")
        bc.GUARD_PID_PATH = os.path.join(bc.LOG_DIR, "popup_guard.pid")
        bc.GUARD_STOP_PATH = os.path.join(bc.LOG_DIR, "popup_guard.stop")
        bc.AUTOSTART_BASELINE = os.path.join(bc.LOG_DIR, "autostart_baseline.json")
        bc.AUTOSTART_WATCH_LOG = os.path.join(bc.LOG_DIR, "autostart_watch.log")
        bc.PROC_WATCH_LOG = os.path.join(bc.LOG_DIR, "process_watch.log")
        os.makedirs(bc.LOG_DIR, exist_ok=True)
        cls.rules = cls.make_rules()
        assert bc.save_popup_rules(cls.rules)
        cls._extra_env = cls.make_env()
        cls._env_before = {k: os.environ.get(k) for k in cls._extra_env}
        os.environ.update(cls._extra_env)
        cls._qpa = os.environ.pop("QT_QPA_PLATFORM", None)        # 守护按真实平台跑，不是离屏
        cls.windows = []
        cls.before_start()
        try:
            ok, msg = bc.start_popup_guard()
        finally:
            if cls._qpa is not None:
                os.environ["QT_QPA_PLATFORM"] = cls._qpa
        if not ok:
            # 启动失败：前台跑一遍，把崩溃信息捞出来（正常启动时 stderr 是丢掉的）
            import subprocess
            env = dict(os.environ)
            env.pop("QT_QPA_PLATFORM", None)
            try:
                r = subprocess.run([sys.executable, bc.GUARD_SCRIPT, "--silent"], env=env, cwd=bc.BASE_DIR,
                                   capture_output=True, timeout=8)
                diag = "rc=%s\nstdout=%s\nstderr=%s" % (
                    r.returncode, r.stdout.decode("utf-8", "replace")[-1500:],
                    r.stderr.decode("utf-8", "replace")[-2500:])
            except subprocess.TimeoutExpired as e:
                diag = "8 秒内没退出（说明能启动，只是 pid 没写出来）\nstderr=%s" % (
                    (e.stderr or b"").decode("utf-8", "replace")[-2500:])
            assert False, "守护没起来：%s\n日志：%s\n前台诊断：%s" % (msg, cls.log(), diag)
        for _ in range(100):                                       # 等它把「启动」写进日志
            if "守护启动" in cls.log():
                break
            _t.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        for w in cls.windows:
            w.stop()
        try:
            bc.stop_popup_guard()
        finally:
            pid = bc.guard_pid()
            if pid:
                h = ctypes.windll.kernel32.OpenProcess(0x0001, False, pid)
                if h:
                    ctypes.windll.kernel32.TerminateProcess(h, 0)
                    ctypes.windll.kernel32.CloseHandle(h)
            for k, v in cls._saved.items():
                setattr(bc, k, v)
            for k, v in cls._env_before.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
            if cls._env is None:
                os.environ.pop("BOOTDOC_DATA_DIR", None)
            else:
                os.environ["BOOTDOC_DATA_DIR"] = cls._env
            shutil.rmtree(cls.td, ignore_errors=True)

    @classmethod
    def log(cls):
        try:
            with open(os.path.join(cls.td, "_logs", "popup_guard.log"), encoding="utf-8") as fp:
                return fp.read()
        except OSError:
            return ""

    def _win(self, title, cls=None):
        w = _TestWindow(title, cls).start()
        self.windows.append(w)
        return w


class TestGuardE2E(_GuardE2EBase):
    """弹窗拦截 / 自启监控 / 停止（原来的端到端用例）。"""

    def test_a_guard_is_running_with_hook(self):
        self.assertTrue(bc.guard_running())
        import time as _t
        end = _t.time() + 12                                   # 自启监控是延后几百毫秒才启动的
        while _t.time() < end and "自启监控已启动" not in self.log():
            _t.sleep(0.2)
        log = self.log()
        self.assertIn("事件钩子=on", log, "事件钩子没装上，守护退回了纯轮询：\n" + log)
        self.assertIn("自启监控已启动", log, "自启监控没起来：\n" + log)

    def test_b_matching_window_closed_by_event_hook(self):
        """轮询兜底是 5 秒一次：2.5 秒内被关掉，只能是事件钩子起的作用。"""
        w = self._win("BootDoctorE2EPopup 限时特惠")
        w.show()
        took = w.wait_closed(8)
        print("  事件钩子关窗耗时 %s" % ("%.2fs" % took if took is not None else "超时"))
        self.assertIsNotNone(took, "窗口一直没被关掉。日志：\n" + self.log())
        self.assertLess(took, 2.5, "关得太慢，像是靠轮询而不是事件钩子（%.2fs）" % took)
        self.assertIn("拦截「BootDoctorE2EPopup", self.log())

    def test_c_non_matching_window_left_alone(self):
        import time as _t
        w = self._win("BootDoctorE2EInnocent")
        w.show()
        _t.sleep(2.5)
        self.assertTrue(w.alive(), "没命中规则的窗口被关了")

    def test_d_system_window_class_never_closed(self):
        """规则命中了，但窗口类是系统外壳的（WorkerW）：必须放过。"""
        import time as _t
        w = self._win("BootDoctorE2EPopup but system class", cls="WorkerW")
        w.show()
        _t.sleep(3)
        self.assertTrue(w.alive(), "系统窗口类被关了")

    def test_e_rules_reload_without_restart(self):
        import time as _t
        w = self._win("BootDoctorE2ENewRule")
        w.show()
        _t.sleep(1.5)
        self.assertTrue(w.alive(), "规则还没加，不该被关")
        rules = dict(self.rules)
        rules["block"] = list(self.rules["block"]) + [
            {"kind": "title", "pattern": "BootDoctorE2ENewRule", "note": "e2e2"}]
        self.assertTrue(bc.save_popup_rules(rules))
        os.utime(bc.POPUP_RULES_PATH, (_t.time() + 5, _t.time() + 5))   # 保证 mtime 变了
        w2 = self._win("BootDoctorE2ENewRule again")
        w2.show()
        took = w2.wait_closed(8)
        self.assertIsNotNone(took, "新增的规则没生效（没热加载）。日志：\n" + self.log())

    def test_f_autostart_change_is_reported(self):
        """往 Run 键里写一项：守护应当在几秒内把它记进「新增自启」日志。"""
        import time as _t
        import winreg
        try:
            with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, self.RUN, 0, winreg.KEY_SET_VALUE) as k:
                winreg.SetValueEx(k, self.PROBE, 0, winreg.REG_SZ, r'"C:\BootDoctorUnitTest\not_exist.exe" --e2e')
            rows = []
            end = _t.time() + 20
            while _t.time() < end and not rows:
                _t.sleep(0.3)
                rows = [r for r in bc.autostart_watch_log(50) if r.get("name") == self.PROBE]
            self.assertTrue(rows, "守护没有报出新增的自启项。日志：\n" + self.log())
            self.assertEqual(rows[0]["change"], "added")
            self.assertIn("not_exist.exe", rows[0]["cmd"])
            self.assertIn("自启新增「%s」" % self.PROBE, self.log())
        finally:
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.RUN, 0, winreg.KEY_SET_VALUE) as k:
                    winreg.DeleteValue(k, self.PROBE)
            except OSError:
                pass

    def test_zz_stop_cleanly(self):
        import time as _t
        pid = bc.guard_pid()
        self.assertGreater(pid, 0)
        ok, msg = bc.stop_popup_guard()
        self.assertTrue(ok, msg)
        self.assertNotIn("强制", msg, "守护没有响应停止标记，被强杀了：" + msg)
        end = _t.time() + 5
        while _t.time() < end and bc._pid_alive(pid):
            _t.sleep(0.1)
        self.assertFalse(bc._pid_alive(pid), "守护进程还活着")
        self.assertFalse(os.path.exists(bc.GUARD_PID_PATH), "pid 文件没清理")


class TestSecurityStatus(unittest.TestCase):
    """Windows 自带防护 / 杀软状态 + 一键开启 Defender 的「潜在有害应用拦截」。"""

    @staticmethod
    def _run(sysd):
        got = []
        bc._security_findings(sysd, lambda **kw: got.append(kw))
        return {g["id"]: g for g in got}

    def test_collect_real_machine(self):
        d = bc.sys_info_native()
        self.assertIsInstance(d.get("security"), dict)
        sec = d["security"]
        print("  安全防护原始数据：%r" % (sec,))
        if sec.get("defender"):
            de = sec["defender"]
            for k in ("av", "rtp", "tamper"):
                self.assertIsInstance(de.get(k), bool, k)
            self.assertIsInstance(de.get("sigAge"), int)
        if "pua" in sec:
            self.assertIn(sec["pua"], (0, 1, 2))
        self.assertIsInstance(d["disks"], list)          # 磁盘结果没被这次改动弄坏

    def test_findings_logic(self):
        base = {"osName": "Microsoft Windows 11 专业版"}
        on = {"defender": {"av": True, "rtp": True, "sigAge": 0}, "av3": []}
        self.assertEqual(set(self._run(dict(base, security=dict(on, pua=0)))), {"sec_pua"})
        self.assertEqual(set(self._run(dict(base, security=dict(on, pua=1)))), set(), "已开启就不该报")
        r = self._run(dict(base, security=dict(on, pua=2)))
        self.assertEqual(set(r), {"sec_pua_audit"})
        old = dict(on, pua=1)
        old["defender"] = dict(on["defender"], sigAge=12, sigTime="2026-11-01 08:00")
        self.assertEqual(set(self._run(dict(base, security=old))), {"sec_sig_old"})
        # 装了第三方杀软：Defender 退居被动，不该再劝人开 PUA
        third = {"defender": {"av": False, "rtp": False}, "pua": 0,
                 "av3": [{"name": "Huorong", "state": 266240}, {"name": "Windows Defender", "state": 393216}]}
        self.assertEqual(set(self._run(dict(base, security=third))), {"sec_av3"})
        none = self._run(dict(base, security={"defender": {"av": False, "rtp": False}, "av3": []}))
        self.assertEqual(none["sec_no_av"]["sev"], "high")
        srv = self._run({"osName": "Microsoft Windows Server 2022", "security": {"defender": {"av": False, "rtp": False}}})
        self.assertEqual(srv["sec_no_av"]["sev"], "info", "服务器没杀软不该报高危")
        self.assertEqual(self._run(dict(base, security={})), {})
        self.assertEqual(self._run(base), {})

    def test_productstate_decode(self):
        self.assertTrue(bc._sp_enabled(266240))      # 0x041000 开启
        self.assertTrue(bc._sp_enabled(397312))      # 0x061000 开启
        self.assertFalse(bc._sp_enabled(262144))     # 0x040000 关闭
        self.assertFalse(bc._sp_enabled(393216))     # 0x060000 关闭
        self.assertFalse(bc._sp_enabled(None))

    def test_pua_backup_apply_restore_real_defender(self):
        old = bc._read_pua()
        if old is None:
            self.skipTest("这台机器上读不到 Defender 的 PUA 设置")
        f = {"id": "t", "title": "t", "fix": {"type": "defender_pua", "risk": "confirm",
                                              "items": [{"value": 1 if old != 1 else 2}]}}
        want = f["fix"]["items"][0]["value"]
        try:
            with tempfile.TemporaryDirectory() as td:
                bdir = bc.make_backup([f], backup_root=td, tag="ut")
                snap = json.load(open(os.path.join(bdir, "snapshot.json"), encoding="utf-8"))
                self.assertEqual(snap["items"][0]["old"], old, "备份里应记下原值")
                res = bc.apply_fixes([f], bdir)
                now = bc._read_pua()
                if res[0]["ok"]:
                    self.assertEqual(now, want)
                    print("  PUA 设置：%s -> %s（已生效）" % (old, now))
                    rr = bc.restore_backup(bdir)
                    self.assertTrue(all(r["ok"] for r in rr), rr)
                    self.assertEqual(bc._read_pua(), old, "还原后应回到原值")
                else:
                    # 被篡改保护 / 组策略锁住：必须如实失败，并告诉用户怎么手动改，且设置没被动
                    print("  PUA 设置被锁住：%s" % res[0]["msgs"])
                    self.assertIn("手动", " ".join(res[0]["msgs"]))
                    self.assertEqual(now, old)
        finally:
            if bc._read_pua() != old:
                bc._set_pua(old)

    def test_analyze_and_gui_show_security_category(self):
        from PyQt5.QtWidgets import QApplication
        import boot_doctor as bd
        app = QApplication.instance() or QApplication([])  # noqa: F841
        raw = fake_raw()
        raw["sys"]["security"] = {"defender": {"av": True, "rtp": True, "sigAge": 0}, "pua": 0, "av3": []}
        res = bc.analyze(raw)
        f = next((x for x in res["findings"] if x["id"] == "sec_pua"), None)
        self.assertIsNotNone(f)
        self.assertEqual(f["cat"], "安全防护")
        self.assertFalse(f["default"])
        self.assertEqual(f["fix"]["type"], "defender_pua")
        self.assertIn("defender_pua", bc.FIX_DESC)
        win = bd.MainWindow(autoscan=False)
        try:
            win.on_scan_done(raw, res)
            cats = [win.tree.topLevelItem(i).text(0) for i in range(win.tree.topLevelItemCount())]
            self.assertTrue(any("安全防护" in c for c in cats), cats)
        finally:
            win.close()


class TestFileHashAndVirusTotal(unittest.TestCase):
    def test_sha256_matches_hashlib_and_limit(self):
        import hashlib
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "x.bin")
            blob = os.urandom(3 * 1024 * 1024 + 17)            # 不是 1MB 的整数倍，测分块边界
            with open(p, "wb") as fp:
                fp.write(blob)
            self.assertEqual(bc.file_sha256(p), hashlib.sha256(blob).hexdigest())
            with self.assertRaises(ValueError):
                bc.file_sha256(p, max_mb=1)

    def test_url_has_only_the_hash(self):
        u = bc.virustotal_url("  ABCDEF0123  ")
        self.assertEqual(u, "https://www.virustotal.com/gui/file/abcdef0123")

    def test_gui_opens_url_without_uploading(self):
        from PyQt5.QtWidgets import QApplication, QMessageBox
        import hashlib
        import boot_doctor as bd
        app = QApplication.instance() or QApplication([])  # noqa: F841
        opened, infos = [], []
        old_open, old_info = bd.QDesktopServices.openUrl, QMessageBox.information
        bd.QDesktopServices.openUrl = staticmethod(lambda u: opened.append(u.toString()) or True)
        QMessageBox.information = staticmethod(lambda *a, **k: infos.append(a[2] if len(a) > 2 else ""))
        try:
            with tempfile.TemporaryDirectory() as td:
                p = os.path.join(td, "a.exe")
                with open(p, "wb") as fp:
                    fp.write(b"MZ-test-bytes")
                sha = bd.open_virustotal(None, p)
                self.assertEqual(sha, hashlib.sha256(b"MZ-test-bytes").hexdigest())
                self.assertEqual(opened, ["https://www.virustotal.com/gui/file/" + sha])
                self.assertEqual(bd.open_virustotal(None, os.path.join(td, "nope.exe")), "")
                self.assertEqual(len(opened), 1, "文件不存在时不该打开网页")
                self.assertTrue(infos, "文件不存在应当提示")
                win = bd.MainWindow(autoscan=False)
                try:
                    win.on_copy_sha({"path": p})
                    self.assertEqual(QApplication.clipboard().text(), sha)
                    win.on_virustotal({"path": p})
                    self.assertEqual(len(opened), 2)
                finally:
                    win.close()
        finally:
            bd.QDesktopServices.openUrl, QMessageBox.information = old_open, old_info


class TestRunningProcessScan(unittest.TestCase):
    """运行中的流氓软件进程：枚举 → 命中特征库 → 体检出条目 → 安全地结束。"""

    def setUp(self):
        import subprocess
        self.child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"],
                                      creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        self.kids = [self.child]
        self.old_check = bc.adware_check

    def tearDown(self):
        bc.adware_check = self.old_check
        for k in self.kids:
            try:
                k.kill()
            except Exception:
                pass

    def _find(self, procs, pid):
        return next((p for p in procs if p["pid"] == pid), None)

    def test_enum_sees_child_not_self_not_system(self):
        import time as _t
        _t.sleep(0.3)
        procs = bc.enum_processes()
        me = self._find(procs, self.child.pid)
        self.assertIsNotNone(me, "枚举不到刚起的子进程")
        self.assertEqual(os.path.normcase(me["path"]), os.path.normcase(sys.executable))
        self.assertEqual(me["ctime"], bc._proc_create_time(self.child.pid))
        self.assertGreater(me["ctime"], 0)
        self.assertIsNone(self._find(procs, os.getpid()), "把自己也枚举进来了")
        self.assertFalse([p for p in procs if bc._under_system_dir(p["path"])], "系统目录的进程不该在里面")
        for k in ("pid", "ppid", "name", "path", "company", "ctime"):
            self.assertIn(k, procs[0])

    def test_collect_includes_procs(self):
        raw = bc.collect()
        self.assertIsInstance(raw["procs"], list)
        self.assertTrue(raw["procs"], "一个进程都没枚举到")

    def test_scan_merges_by_path_and_analyze_builds_kill_item(self):
        import time as _t
        _t.sleep(0.3)
        p = self._find(bc.enum_processes(), self.child.pid)
        twin = dict(p, pid=p["pid"] + 100000, ctime=p["ctime"] + 1)       # 同一个程序的第二个进程（虚构）
        target = os.path.normcase(sys.executable)
        bc.adware_check = lambda path="", name="", company="", cmd="": (
            {"hit": True, "kind": "family", "family": "ludashi", "label": "鲁大师全家桶", "sev": "mid",
             "why": "测试命中"} if os.path.normcase(path or "") == target else self.old_check(path, name, company, cmd))
        raw = fake_raw()
        raw["procs"] = [p, twin]
        raw["adware"] = bc.adware_scan(raw)
        hits = [h for h in raw["adware"]["items"] if h["kind"] == "process"]
        self.assertEqual(len(hits), 1, "同一路径的两个进程应合并成一条")
        self.assertEqual(sorted(x["pid"] for x in hits[0]["procs"]), sorted([p["pid"], twin["pid"]]))
        res = bc.analyze(raw)
        f = next((x for x in res["findings"] if x["id"].startswith("proc_kill@")), None)
        self.assertIsNotNone(f, "没有生成「结束进程」条目")
        self.assertEqual(f["cat"], "流氓软件")
        self.assertFalse(f["default"], "结束进程默认不勾选")
        self.assertEqual(f["fix"]["type"], "proc_kill")
        self.assertEqual(len(f["fix"]["items"]), 2)
        fam = next(x for x in res["findings"] if x["id"] == "adware_ludashi")
        self.assertIn("正在运行", fam["detail"], "家族条目里应列出正在运行的进程")

    def test_kill_full_flow_and_identity_checks(self):
        import time as _t
        _t.sleep(0.3)
        p = self._find(bc.enum_processes(), self.child.pid)
        item = {"pid": p["pid"], "ctime": p["ctime"], "path": p["path"], "name": os.path.basename(p["path"])}

        # 1) 创建时间对不上（PID 被复用的情形）：不能动
        ok, msg = bc.kill_process(item["pid"], item["ctime"] + 12345, item["path"])
        self.assertTrue(ok)
        self.assertIn("换了", msg)
        self.assertIsNone(self.child.poll(), "身份对不上还是被结束了")
        # 2) 路径对不上：不能动
        ok, msg = bc.kill_process(item["pid"], item["ctime"], r"C:\somewhere\else.exe")
        self.assertIsNone(self.child.poll())
        # 3) 试运行：不动
        ok, msg = bc.kill_process(item["pid"], item["ctime"], item["path"], dry_run=True)
        self.assertTrue(ok and "试运行" in msg, msg)
        self.assertIsNone(self.child.poll())
        # 4) 走完整的 备份 → 执行 → 还原
        f = {"id": "k", "title": "k", "fix": {"type": "proc_kill", "risk": "confirm", "items": [item]}}
        with tempfile.TemporaryDirectory() as td:
            bdir = bc.make_backup([f], backup_root=td, tag="ut")
            res = bc.apply_fixes([f], bdir)
            self.assertTrue(res[0]["ok"], res)
            for _ in range(40):
                if self.child.poll() is not None:
                    break
                _t.sleep(0.1)
            self.assertIsNotNone(self.child.poll(), "进程没被结束")
            self.assertIn("结束过运行中的进程", open(os.path.join(bdir, "说明.txt"), encoding="utf-8").read(),
                          "备份说明里要如实写明进程无法还原")
            rr = bc.restore_backup(bdir)
            self.assertTrue(all(r["ok"] for r in rr), rr)
            self.assertIn("无法", " ".join(rr[0]["msgs"]))
        # 5) 已经不在了：不算失败
        ok, msg = bc.kill_process(item["pid"], item["ctime"], item["path"])
        self.assertTrue(ok)

    def test_never_kills_system_or_self(self):
        self.assertFalse(bc.proc_kill_allowed("explorer.exe", r"C:\Users\x\explorer.exe"), "系统外壳进程名要拦")
        self.assertFalse(bc.proc_kill_allowed("x.exe", os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "x.exe")))
        self.assertFalse(bc.proc_kill_allowed("x.exe", r"D:\a\x.exe", pid=os.getpid()), "本程序自己")
        self.assertFalse(bc.proc_kill_allowed("x.exe", r"D:\a\x.exe", pid=4))
        self.assertFalse(bc.proc_kill_allowed("x.exe", ""))
        self.assertTrue(bc.proc_kill_allowed("x.exe", r"D:\a\x.exe", pid=99999))
        ok, msg = bc.kill_process(os.getpid(), 0, sys.executable)
        self.assertFalse(ok)
        self.assertIn("不允许", msg)


class TestJudgeNewProcess(unittest.TestCase):
    """新进程判定：默认只报高把握的两类，严格模式才多报「未签名 + 从 Temp / AppData 启动」。"""

    def setUp(self):
        self._saved = (bc.adware_check, bc.ms_spoof_verdict, bc.app_signature)
        self.td = tempfile.mkdtemp()
        self.exe = os.path.join(self.td, "AppData", "Local", "Temp", "x.exe")
        os.makedirs(os.path.dirname(self.exe))
        with open(self.exe, "wb") as fp:
            fp.write(b"MZ")
        self.proc = {"pid": 4321, "ctime": 99, "name": "x.exe", "path": self.exe, "company": ""}
        bc.adware_check = lambda **kw: {"hit": False}
        bc.ms_spoof_verdict = lambda app: None
        bc.app_signature = lambda app: {"state": "unsigned"}

    def tearDown(self):
        bc.adware_check, bc.ms_spoof_verdict, bc.app_signature = self._saved
        shutil.rmtree(self.td, ignore_errors=True)

    def test_adware_hit(self):
        bc.adware_check = lambda **kw: {"hit": True, "family": "ludashi", "label": "鲁大师全家桶",
                                         "sev": "mid", "why": "测试"}
        v = bc.judge_new_process(self.proc)
        self.assertEqual((v["level"], v["sev"], v["label"], v["family"]), ("adware", "mid", "鲁大师全家桶", "ludashi"))
        self.assertEqual((v["pid"], v["ctime"], v["path"]), (4321, 99, self.exe))

    def test_spoof_hit(self):
        bc.ms_spoof_verdict = lambda app: ("high", "签名者是别人")
        v = bc.judge_new_process(dict(self.proc, company="Microsoft Corporation"))
        self.assertEqual((v["level"], v["sev"]), ("spoof", "high"))

    def test_unsigned_in_temp_only_in_strict_mode(self):
        self.assertIsNone(bc.judge_new_process(self.proc), "默认模式不该为「未签名」提醒")
        v = bc.judge_new_process(self.proc, strict=True)
        self.assertEqual((v["level"], v["sev"]), ("unsigned", "low"))
        bc.app_signature = lambda app: {"state": "valid", "signer": "Some Ltd"}
        self.assertIsNone(bc.judge_new_process(self.proc, strict=True), "有签名的不报")
        bc.app_signature = lambda app: {"state": "unsigned"}
        old_zone = bc._in_user_dropzone
        bc._in_user_dropzone = lambda p: False     # 临时目录本身就在 AppData\\Temp 下，所以打桩模拟「别处」
        try:
            self.assertIsNone(bc.judge_new_process(self.proc, strict=True), "不在 Temp / AppData 一类位置的不报")
        finally:
            bc._in_user_dropzone = old_zone

    def test_system_dir_and_missing_file_ignored(self):
        sysexe = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "cmd.exe")
        bc.adware_check = lambda **kw: {"hit": True, "label": "x", "sev": "high", "why": "x"}
        self.assertIsNone(bc.judge_new_process(dict(self.proc, path=sysexe)), "系统目录一律不判")
        bc.adware_check = lambda **kw: {"hit": False}
        self.assertIsNone(bc.judge_new_process(dict(self.proc, path=r"D:\gone\z.exe"), strict=True))

    def test_dropzone(self):
        z = bc._in_user_dropzone
        for p in (r"C:\Users\u\AppData\Local\Temp\a.exe", r"C:\Users\u\AppData\Roaming\x\a.exe",
                  os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "x", "a.exe"),
                  os.path.join(os.environ.get("PUBLIC", r"C:\Users\Public"), "a.exe")):
            self.assertTrue(z(p), p)
        for p in (r"C:\Users\u\Downloads\a.exe", r"C:\Program Files\x\a.exe", r"D:\Tools\a.exe"):
            self.assertFalse(z(p), p)

    def test_log_roundtrip_newest_first(self):
        lp = os.path.join(self.td, "pw.log")
        bc.append_proc_watch([{"t": "1", "name": "a"}, {"t": "2", "name": "b"}], path=lp)
        bc.append_proc_watch([{"t": "3", "name": "c"}], path=lp)
        self.assertEqual([r["name"] for r in bc.proc_watch_log(10, path=lp)], ["c", "b", "a"])
        self.assertEqual(bc.proc_watch_log(10, path=os.path.join(self.td, "none.log")), [])

    def test_rule_defaults_and_load(self):
        d = bc.DEFAULT_POPUP_RULES
        self.assertTrue(d["watch_process"])
        self.assertFalse(d["auto_kill_adware"], "自动结束进程必须默认关")
        self.assertFalse(d["watch_strict"])
        rp = os.path.join(self.td, "r.json")
        json.dump({"enabled": True, "auto_kill_adware": True, "watch_strict": True, "watch_process": False},
                  open(rp, "w", encoding="utf-8"))
        r = bc.load_popup_rules(rp)
        self.assertEqual((r["auto_kill_adware"], r["watch_strict"], r["watch_process"]), (True, True, False))

    def test_gui_tab_toggles_and_confirm(self):
        from PyQt5.QtWidgets import QApplication, QMessageBox
        import boot_doctor as bd
        app = QApplication.instance() or QApplication([])  # noqa: F841
        old = (bc.POPUP_RULES_PATH, bc.PROC_WATCH_LOG, QMessageBox.question)
        bc.POPUP_RULES_PATH = os.path.join(self.td, "_popup_rules.json")
        bc.PROC_WATCH_LOG = os.path.join(self.td, "process_watch.log")
        bc.append_proc_watch([{"t": "2026-11-22 12:00:00", "level": "adware", "sev": "mid", "label": "鲁大师",
                               "name": "lds.exe", "path": r"C:\x\lds.exe", "why": "命中", "action": "已结束"}])
        try:
            dlg = bd.PopupDialog()
            self.assertEqual(dlg.tabs.count(), 4)
            dlg.tabs.setCurrentIndex(3)
            self.assertEqual(dlg.pw_tree.topLevelItemCount(), 1)
            self.assertIn("(1)", dlg.tabs.tabText(3))
            self.assertTrue(dlg.chk_watch_proc.isChecked())
            self.assertFalse(dlg.chk_autokill.isChecked())
            dlg.chk_strict.setChecked(True)
            self.assertTrue(bc.load_popup_rules()["watch_strict"])
            QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.No)
            dlg.chk_autokill.setChecked(True)
            self.assertFalse(dlg.chk_autokill.isChecked(), "点了「否」应当回到未勾选")
            self.assertFalse(bc.load_popup_rules()["auto_kill_adware"])
            QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.Yes)
            dlg.chk_autokill.setChecked(True)
            self.assertTrue(bc.load_popup_rules()["auto_kill_adware"])
            dlg.chk_watch_proc.setChecked(False)
            self.assertFalse(bc.load_popup_rules()["watch_process"])
            dlg.close()
        finally:
            bc.POPUP_RULES_PATH, bc.PROC_WATCH_LOG, QMessageBox.question = old


class TestProcWatchE2E(_GuardE2EBase):
    """真守护进程 + 真子进程：基线不报、新进程命中特征库提醒、自动结束、总开关。

    用 BOOTDOC_ADWARE_DB 给守护一份只含「python 所在目录」的自定义特征库，
    这样真的 python.exe 子进程就是「命中特征库的新进程」。
    """
    @classmethod
    def _db_key(cls):
        segs = [x for x in os.path.dirname(sys.executable).split("\\") if len(x) >= 4]
        common = {"programs", "program", "windows", "local", "python", "users", "tools", "temp", "appdata"}
        good = [x for x in segs if x.lower() not in common]
        return max(good or segs, key=len)

    @classmethod
    def make_rules(cls):
        r = super().make_rules()
        r.update({"watch_process": True, "auto_kill_adware": False, "block": []})
        return r

    @classmethod
    def make_env(cls):
        db = os.path.join(cls.td, "e2e_db.json")
        with open(db, "w", encoding="utf-8") as fp:
            json.dump({"version": 2, "updated": "2026-11-22", "dirs": {cls._db_key(): "E2E 测试软件"},
                       "pubs": [], "families": [], "white": []}, fp, ensure_ascii=False)
        return {"BOOTDOC_ADWARE_DB": db}

    @classmethod
    def before_start(cls):
        import subprocess
        cls.kids = []
        cls.early = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(300)"],
                                     creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        cls.kids.append(cls.early)

    @classmethod
    def tearDownClass(cls):
        for k in getattr(cls, "kids", []):
            try:
                k.kill()
            except Exception:
                pass
        super().tearDownClass()

    def _spawn(self):
        import subprocess
        k = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(300)"],
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        self.kids.append(k)
        return k

    def _wait(self, cond, timeout=15):
        import time as _t
        end = _t.time() + timeout
        while _t.time() < end:
            v = cond()
            if v:
                return v
            _t.sleep(0.25)
        return None

    def _rows_for(self, pid_path=None):
        return [r for r in bc.proc_watch_log(200) if os.path.normcase(r.get("path", "")) == os.path.normcase(sys.executable)]

    def test_a_baseline_then_new_process_alerted(self):
        self.assertTrue(self._wait(lambda: "新进程监控已启动" in self.log()), "监控没启动：\n" + self.log())
        self.assertEqual(self._rows_for(), [], "守护启动前就在跑的进程不该提醒（基线）")
        self.assertIsNone(self.early.poll(), "基线里的进程还活着")
        k = self._spawn()
        row = self._wait(lambda: self._rows_for())
        self.assertTrue(row, "新进程没被提醒。日志：\n" + self.log())
        r = row[0]
        self.assertEqual((r["level"], r["action"]), ("adware", "提醒"))
        self.assertIn("E2E 测试软件", r["label"] + r["why"])
        self.assertIsNone(k.poll(), "没开自动结束，进程不该被动")
        self.assertIn("命中特征库", self.log())

    def test_b_auto_kill_only_new_processes(self):
        import time as _t
        rules = dict(self.rules, auto_kill_adware=True)
        self.assertTrue(bc.save_popup_rules(rules))
        os.utime(bc.POPUP_RULES_PATH, (_t.time() + 5, _t.time() + 5))
        _t.sleep(3.2)                                   # 守护每 1.5 秒重读一次规则
        before_alive = [k for k in self.kids if k.poll() is None]
        k = self._spawn()
        self.assertTrue(self._wait(lambda: k.poll() is not None), "开了自动结束，新进程还活着。日志：\n" + self.log())
        self.assertTrue(self._wait(lambda: any(r["action"] == "已结束" for r in self._rows_for())),
                        "记录里没有「已结束」：%r" % self._rows_for()[:3])
        # 守护启动前的进程、以及开自动结束之前就在的进程，都不该被追杀
        self.assertIsNone(self.early.poll(), "基线进程被追杀了")
        self.assertTrue(bc.guard_running(), "守护自己不能死")
        for b in before_alive:
            self.assertIsNone(b.poll(), "开自动结束之前就在运行的进程被追杀了")

    def test_c_master_switch_off(self):
        import time as _t
        rules = dict(self.rules, watch_process=False, auto_kill_adware=True)
        self.assertTrue(bc.save_popup_rules(rules))
        os.utime(bc.POPUP_RULES_PATH, (_t.time() + 10, _t.time() + 10))
        _t.sleep(3.2)
        n0 = len(self._rows_for())
        k = self._spawn()
        _t.sleep(5)
        self.assertIsNone(k.poll(), "关了新进程监控，进程不该被动")
        self.assertEqual(len(self._rows_for()), n0, "关了监控不该再有记录")


if __name__ == "__main__":
    unittest.main(verbosity=2)
