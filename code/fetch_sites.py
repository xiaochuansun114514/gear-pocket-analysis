#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""只读抓取官网 / 导航页 / 123pan 渠道，存下来留着慢慢看。纯标准库，不用装东西。

从内存里把链接清单捞出来之后，我拿这个脚本把每个官网和导航页都抓了一份本地副本。
后面那些页面里的跳转关系、发布时间，都是从这堆 HTML 里翻出来的。
"""
import re, sys, json, time, urllib.request, urllib.error, http.cookiejar

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

URLS = [
    "https://rjkd.top/",
    "http://rjkd.top/fxkd/",
    "https://rjkd.top/bdwt/",
    "https://rjkd.top/kdjs/",
    "https://rjkd.top/rjwt/",
    "https://rjkd.top/swhz/",
    "https://rjkd.top/yjdz1/",
    "https://rjkd.app/2/1/",
    "https://rjkd.app/2/2",
    "https://rjkd.app/2/3/",
    "https://rjkd.app/",
]


def get(url, referer=None, timeout=30):
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    h = {"User-Agent": UA, "Accept": "*/*"}
    if referer:
        h["Referer"] = referer
    req = urllib.request.Request(url, headers=h)
    try:
        r = op.open(req, timeout=timeout)
        return r.getcode(), r.geturl(), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, url, e.read().decode("utf-8", "replace")
    except Exception as e:
        return -1, url, repr(e)


out = {}
for u in URLS:
    code, final, body = get(u)
    meta = re.search(r'url=([^"\'\s>]+)', body)
    title = re.search(r"<title>(.*?)</title>", body, re.S)
    out[u] = {"code": code, "final": final,
              "refresh_to": meta.group(1) if meta else None,
              "title": title.group(1).strip() if title else None,
              "len": len(body)}
    print(json.dumps({u: out[u]}, ensure_ascii=False))
    open(r"E:\gear_analysis\writeup\raw\site_%s.html" %
         re.sub(r"[^a-z0-9]", "_", u), "w", encoding="utf-8").write(body)
    time.sleep(0.5)

open(r"E:\gear_analysis\writeup\raw\sites.json", "w",
     encoding="utf-8").write(json.dumps(out, ensure_ascii=False, indent=1))
