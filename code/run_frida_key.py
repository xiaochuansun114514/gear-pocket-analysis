#!/usr/bin/env python3
# run_frida_key.py — spawn 软件口袋，配合 hook_abcdstr.js 抓 AES 密钥
#
# 结论：没成功。spawn 完 attach 上去，进程立刻退出，脚本一条日志都没发回来。
# 后来换的路子是放弃 hook，改用 root 读 /proc/PID/mem 把内存整个扒下来，
# 再从内存里扫 dex 和明文配置 —— 那招一次就通了。
# 这个脚本留着，是为了记住"跟反调试硬刚"这条路当时是怎么走死的。
import frida, sys, time

SERIAL = "127.0.0.1:16416"
PKG = "com.rjkd.ruanku"

def on_message(msg, data):
    if msg.get("type") == "send":
        print(msg["payload"], flush=True)
    elif msg.get("type") == "error":
        print("[ERR]", msg.get("stack") or msg.get("description"), flush=True)
    else:
        print("[MSG]", msg, flush=True)

dev = frida.get_device(SERIAL, timeout=5)
print("[*] device:", dev, flush=True)

script = open(r"E:\gear_analysis\dl\hook_abcdstr.js", encoding="utf-8").read()

try:
    pid = dev.spawn([PKG])
    print("[*] spawned pid", pid, flush=True)
    session = dev.attach(pid)
    sc = session.create_script(script)
    sc.on("message", on_message)
    sc.load()
    dev.resume(pid)
    print("[*] resumed, waiting for abcdstr...", flush=True)
    time.sleep(40)
    print("[*] done", flush=True)
except Exception as e:
    print("[EXC]", repr(e), flush=True)
