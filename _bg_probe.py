# -*- coding: utf-8 -*-
"""验证「后台运行」是不是真的：

1. 子进程调用 start_popup_guard() 后立刻退出 —— 守护必须活着（脱离父进程）
2. 守护不能有任何可见窗口 / 控制台（pythonw + DETACHED_PROCESS）
3. 开机自启项的读写
4. enabled=false 时 --silent 启动应当立刻退出，不留灰图标
"""
import ctypes
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
PY = sys.executable
user32 = ctypes.WinDLL("user32", use_last_error=True)
user32.GetWindowThreadProcessId.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
user32.IsWindowVisible.argtypes = [ctypes.c_void_p]
user32.GetWindowTextLengthW.argtypes = [ctypes.c_void_p]
user32.EnumWindows.argtypes = [ctypes.c_void_p, ctypes.c_void_p]


def windows_of(pid):
    out = []

    def cb(hwnd, _l):
        p = ctypes.c_ulong(0)
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(p))
        if p.value == pid and user32.IsWindowVisible(hwnd):
            out.append((int(hwnd), user32.GetWindowTextLengthW(hwnd)))
        return True

    user32.EnumWindows(ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p,
                                          ctypes.c_void_p)(cb), 0)
    return out


def main():
    import boot_core as bc

    print("=" * 64)
    print("[0] 清场")
    bc.stop_popup_guard()
    time.sleep(0.4)
    print("    running=%s" % bc.guard_running())

    # ---------- 1) 父进程退出后守护是否存活 ----------
    print("[1] 父进程只负责拉起守护，然后立刻退出")
    launcher = (
        "import sys;sys.path.insert(0,%r);import boot_core as bc;"
        "print(bc.start_popup_guard()[1])" % HERE
    )
    r = subprocess.run([PY, "-c", launcher], cwd=HERE, capture_output=True,
                       text=True, timeout=90)
    print("    拉起进程已退出 code=%s 输出=%s" % (r.returncode, (r.stdout or "").strip()))
    time.sleep(1.2)
    pid = bc.guard_pid()
    alive = bc.guard_running()
    print("    父进程没了之后：guard_running=%s pid=%s" % (alive, pid))
    if alive:
        wins = windows_of(pid)
        print("    该进程的可见顶层窗口：%d 个 %s" % (len(wins), wins[:4]))
        # 主子进程树：父 pid 应该是 0/已退出（pythonw 被 DETACHED 后就孤儿了）
        print("    进程命令行：", end="")
        try:
            q = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "(Get-CimInstance Win32_Process -Filter 'ProcessId=%d').CommandLine" % pid],
                capture_output=True, text=True, timeout=25)
            print((q.stdout or "").strip()[:180])
        except Exception as e:
            print("(查不到 %r)" % (e,))

    # ---------- 2) 真·关掉主程序后还在不在 ----------
    print("[2] 模拟「关掉主程序」：guard 与主程序无任何父子关系，主程序退出不影响它")
    time.sleep(8)
    print("    8 秒后仍在运行：%s" % bc.guard_running())

    # ---------- 3) 开机自启 ----------
    print("[3] 开机自启注册表")
    old_state = bc.guard_autostart()
    print("    当前状态：%s" % (old_state,))
    ok, msg = bc.set_guard_autostart(True)
    print("    写：ok=%s msg=%s" % (ok, msg))
    st, val = bc.guard_autostart()
    print("    读回：state=%s value=%s" % (st, val))
    print("    命令里带 pythonw：", "pythonw.exe" in val.lower())
    print("    命令里带 popup_guard.py：", "popup_guard.py" in val.lower())
    print("    命令里带 --silent：", "--silent" in val.lower())
    ok2, msg2 = bc.set_guard_autostart(False)
    print("    删：ok=%s state=%s" % (ok2, bc.guard_autostart()[0]))
    if old_state[0] != "off":                      # 原本有就恢复回去
        bc.set_guard_autostart(True)
        print("    已恢复原状态：on")

    # ---------- 4) silent + 关闭状态应当不驻留 ----------
    print("[4] enabled=false 时 --silent 启动应当自行退出")
    bc.stop_popup_guard()
    time.sleep(0.5)
    bc.set_popup_enabled(False)
    p = subprocess.Popen([bc._pythonw_path(), os.path.join(HERE, "popup_guard.py"), "--silent"],
                         cwd=HERE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         creationflags=0x00000008 | 0x08000000)
    for _ in range(40):
        time.sleep(0.15)
        if p.poll() is not None:
            break
    print("    退出码：%s（None 表示还赖着没走）" % p.poll())
    if p.poll() is None:
        p.kill()
    print("    pid 文件还在吗：%s" % os.path.exists(bc.GUARD_PID_PATH))

    # ---------- 收尾 ----------
    print("[5] 收尾，恢复为用户原来的样子")
    bc.set_popup_enabled(True)
    bc.stop_popup_guard()
    print("    running=%s  autostart=%s" % (bc.guard_running(), bc.guard_autostart()[0]))


if __name__ == "__main__":
    main()
