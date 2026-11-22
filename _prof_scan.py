# -*- coding: utf-8 -*-
"""逐阶段计时：找出体检慢在哪。用法：python _prof_scan.py"""
import time
import boot_core as bc

T = []


def step(name, fn, *a, **kw):
    t = time.perf_counter()
    try:
        r = fn(*a, **kw)
    except Exception as e:
        r = e
    dt = time.perf_counter() - t
    T.append((dt, name))
    print("  %-42s %6.2fs" % (name, dt), flush=True)
    return r


t0 = time.perf_counter()
print("开始计时（每步独立，总耗时=相加）", flush=True)
startup = step("启动项 enum_startup_items", bc.enum_startup_items)
services = step("服务 enum_services", bc.enum_services)
power = step("电源 read_power_state", bc.read_power_state)
sysinfo = step("系统信息 PS_SYS", lambda: bc._parse_json(bc.run_ps(bc.PS_SYS, timeout=120)))
events = step("事件日志 PS_EVENTS", lambda: bc._parse_json(bc.run_ps(bc.PS_EVENTS, timeout=180)))
filters = step("过滤驱动 get_filters", bc.get_filters)
extra = step("隐蔽启动点 enum_extra_autostarts", bc.enum_extra_autostarts)
raw = {"startup": startup, "services": services, "power": power,
       "sys": sysinfo, "events": events, "filters": filters, "extra": extra}
aw = step("特征库比对 adware_scan", lambda: bc.adware_scan(raw))
res = step("分析 analyze", lambda: bc.analyze(dict(raw, adware=aw)))
total = time.perf_counter() - t0
print("\n总耗时 %.2fs" % total, flush=True)
print("各阶段占比：")
for dt, name in sorted(T, reverse=True):
    print("  %5.1f%%  %6.2fs  %s" % (dt / total * 100, dt, name))
print("\n发现项 %d 个" % len(res.get("findings") or []))
