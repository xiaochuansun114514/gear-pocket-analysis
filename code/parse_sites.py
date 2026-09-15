#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# parse_sites.py — 把 raw/ 下抓回来的一堆 HTML 挨个扫一遍，把链接全抽出来
#
# 抓下来的页面太散，一个个点开看太慢，就写了这个：
# 目录下所有 .html 过一遍，正则捞链接、去重、打印。哪个页面里有外链一眼就能看出来。
import re, os, json
D = r"E:\gear_analysis\writeup\raw"
URLRE = re.compile(r"https?://[^\s\"'<>\\\)]+")
for f in sorted(os.listdir(D)):
    if not f.endswith(".html"):
        continue
    p = os.path.join(D, f)
    d = open(p, encoding="utf-8", errors="replace").read()
    links = sorted(set(URLRE.findall(d)))
    print("#" * 20, f, len(d))
    for l in links:
        print("   ", l)
