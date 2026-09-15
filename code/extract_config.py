#!/usr/bin/env python3
# extract_config.py — 从 mem.bin 里把明文配置和各种链接捞出来
#
# 内存是整个进程 3.8GB 全扒下来的，里面什么都有，所以干脆不写解析器了，直接扫。
# 扫的过程中发现明文落在两类编码区里：UTF-8 那片是 AppConfig 对象的 URL 字段，
# UTF-16LE 那片是个 VPN 导航 JSON。只扫 UTF-8 的话后面那个就漏了。
# 用法: python extract_config.py <mem.bin>
import mmap, re, json, sys

def main(path):
    f = open(path, 'rb')
    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

    print("=== 1. 所有蓝奏/图片/官网 URL（UTF-8 堆，AppConfig 对象字段）===")
    urls = set()
    for m in re.finditer(rb'https?://[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%-]{6,200}', mm):
        u = m.group().decode('utf-8', 'replace').rstrip('.,;)\"')
        if any(d in u for d in ['lanzou', 'imgos', 'meituan', 'gitcode', 'rjkd', 'ilanzou']):
            urls.add(u)
    for u in sorted(urls):
        print("  ", u)

    print("\n=== 2. UTF-16LE 配置（VPN 导航 JSON，Java String）===")
    # 定位 'lanzou' 的 UTF-16LE 编码，向前回溯 JSON 数组起点
    pos = mm.find('lanzou'.encode('utf-16-le'))
    if pos >= 0:
        window = mm[pos - 1000: pos + 200000].decode('utf-16-le', errors='replace')
        lb = window.find('[')
        dec = json.JSONDecoder()
        try:
            obj, end = dec.raw_decode(window, lb)
            print("  条目数:", len(obj))
            for e in obj:
                print("  [%s] %s -> %s" % (e.get("标题"), e.get("副标题"), e.get("链接")))
        except Exception as ex:
            print("  解析失败:", ex)

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else r"E:\gear_analysis\mem.bin")
