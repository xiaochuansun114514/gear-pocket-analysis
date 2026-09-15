#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""取蓝奏云单文件页里的「上传时间」。这个时间藏在 /fn 那个 iframe 里，得单独再请求一次。

当时是为了对时间线才写它的 —— 想看看这批文件是什么时候陆续传上去的，
好跟作者那边的动静对上。
"""
import re, sys, os, json, gzip, zlib, subprocess, tempfile
import http.cookiejar, urllib.request

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
HERE = os.path.dirname(os.path.abspath(__file__))
ACW = os.path.join(HERE, "..", "raw", "acw.js")


def _read(resp):
    raw = resp.read()
    ce = (resp.headers.get("Content-Encoding") or "").lower()
    if "gzip" in ce:
        raw = gzip.decompress(raw)
    elif "deflate" in ce:
        raw = zlib.decompress(raw, -zlib.MAX_WBITS)
    return raw.decode("utf-8", "replace")


def solve_acw(html, tag):
    m = re.search(r"<script>(.*)</script>", html, re.S)
    if not m:
        return None
    p = os.path.join(tempfile.gettempdir(), "acw_%s.js" % re.sub(r"\W", "_", tag)[:24])
    open(p, "w", encoding="utf-8").write(m.group(1))
    r = subprocess.run(["node", ACW, p], capture_output=True, text=True, timeout=30)
    mm = re.search(r"acw_sc__v2=([0-9a-f]+)", (r.stdout or ""))
    return mm.group(1) if mm else None


def session():
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    op.addheaders = [("User-Agent", UA), ("Accept-Language", "zh-CN,zh;q=0.9")]
    return op, cj


def get(op, cj, url, tag):
    html = _read(op.open(urllib.request.Request(url), timeout=40))
    if "acw_sc__v2" in html and "n_downlink" not in html and "user-title" not in html:
        v = solve_acw(html, tag)
        if v:
            host = url.split("/")[2]
            cj.set_cookie(http.cookiejar.Cookie(
                0, "acw_sc__v2", v, None, False, host, True, False, "/", True,
                False, None, True, None, None, {}, False))
            html = _read(op.open(urllib.request.Request(url), timeout=40))
    return html


def file_detail(url, tag):
    op, cj = session()
    h = get(op, cj, url, tag)
    d = {"_url": url, "raw_len": len(h)}
    m = re.search(r"<title>(.*?)</title>", h, re.S)
    d["title"] = m.group(1).strip() if m else ""
    m = re.search(r'<div class="fileinfo[^"]*">(.*?)</div>', h, re.S)
    m2 = re.search(r"大小：\s*([\d\.]+ ?[KMG]B)", h)
    d["size"] = m2.group(1) if m2 else None
    m3 = re.search(r"<iframe[^>]*src=\"(/fn[^\"]+)\"", h)
    if m3:
        f = get(op, cj, "https://" + url.split("/")[2] + m3.group(1), tag + "fn")
        d["fn_len"] = len(f)
        for lbl in ["上传时间", "分享时间", "文件名称", "文件大小", "下载次数", "提取码"]:
            mm = re.search(lbl + r"[：:]?\s*(?:</?\w+[^>]*>\s*)*([^<>\n]{1,60})", f)
            if mm:
                d[lbl] = mm.group(1).strip()
        d["fn_text"] = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", f)).strip()[:400]
    return d


if __name__ == "__main__":
    for u in sys.argv[1:]:
        try:
            r = file_detail(u, u.split("/")[-1])
        except Exception as e:
            r = {"_url": u, "error": repr(e)}
        print(json.dumps(r, ensure_ascii=False))
