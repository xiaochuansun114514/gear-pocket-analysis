#!/usr/bin/env python3
# run_frida_key.py — spawn 软件口袋 并 hook abcdstr 抓 AES 密钥
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
