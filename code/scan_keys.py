#!/usr/bin/env python3
# scan_keys.py — 分块扫 mem.bin，找加密特征和 URL 关键词，命中就把上下文打出来
#
# 3.8GB 没法一次性读进来，所以按 16MB 一块、块间重叠 256 字节地滚，
# 免得关键词正好卡在分块边界上被切断。
# NEEDLES 里那几条是我当时想找的东西：Cipher/SecretKeySpec 是想定位 AES 调用，
# RJKD/XL1/raw.gitcode 是想把配置源的线索串起来。
import re, sys

PATH = r"E:\gear_analysis\mem.bin"
NEEDLES = [
    b"SecretKeySpec", b"Cipher", b"getInstance", b"doFinal",
    b"AES/ECB/PKCS5Padding", b"MessageDigest", b"MD5",
    b"RJKD", b"XL1", b"raw.gitcode",
]
CHUNK = 16 * 1024 * 1024
OVERLAP = 256

def printable(buf):
    return ''.join(chr(b) if 32 <= b < 127 else ' ' for b in buf)

def clean(s):
    return re.sub(r'\s+', ' ', s).strip()

seen = set()
total = 0
with open(PATH, "rb") as f:
    prev = b""
    offset = 0
    while True:
        chunk = f.read(CHUNK)
        if not chunk:
            break
        buf = prev + chunk
        low = buf.lower()
        for needle in NEEDLES:
            n = needle.lower()
            idx = 0
            cnt = 0
            while True:
                i = low.find(n, idx)
                if i < 0:
                    break
                absoff = offset - len(prev) + i
                s = max(0, i - 100)
                e = min(len(buf), i + 200)
                ctx = clean(printable(buf[s:e]))
                if ctx not in seen:
                    seen.add(ctx)
                    print("\n--- off %d (%s) ---" % (absoff, needle.decode()))
                    print(ctx)
                idx = i + 1
                cnt += 1
                if cnt > 15:
                    break
        prev = chunk[-OVERLAP:] if len(chunk) >= OVERLAP else chunk
        offset += len(chunk)
        total += len(chunk)

print("\n[*] scanned %d bytes, unique contexts=%d" % (total, len(seen)))
