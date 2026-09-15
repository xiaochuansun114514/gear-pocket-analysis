#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""抓蓝奏云页面。它前面挡了个 acw_sc__v2 的 WAF 挑战，这里顺手给解了。

一开始直接请求，返回的是一段 JS 挑战页，什么内容都没有。
把那段 JS 抠出来丢给 raw/acw.js 跑一遍（用 node），拿到 acw_sc__v2 这个 cookie 塞回去，
再请求就正常了。绕这一下花了点时间，但绕过去之后就一路顺。
"""
import re, os, subprocess, tempfile, http.cookiejar, urllib.request, json, sys

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
HERE = os.path.dirname(os.path.abspath(__file__))
ACW = os.path.join(HERE, "..", "raw", "acw.js")


def solve_acw(html, tag):
    m = re.search(r"<script>(.*)</script>", html, re.S)
    if not m:
        return None
    p = os.path.join(tempfile.gettempdir(), "acw_%s.js" % tag)
    open(p, "w", encoding="utf-8").write(m.group(1))
    r = subprocess.run(["node", ACW, p], capture_output=True, text=True, timeout=30)
    out = (r.stdout or "").strip()
    mm = re.search(r"acw_sc__v2=([0-9a-f]+)", out)
    return mm.group(1) if mm else None


def fetch(url, tag="t"):
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    op.addheaders = [("User-Agent", UA), ("Accept-Language", "zh-CN,zh;q=0.9")]
    def _read(resp):
        raw = resp.read()
        ce = (resp.headers.get("Content-Encoding") or "").lower()
        if "gzip" in ce:
            import gzip
            raw = gzip.decompress(raw)
        elif "deflate" in ce:
            import zlib
            raw = zlib.decompress(raw, -zlib.MAX_WBITS)
        return raw.decode("utf-8", "replace")

    req = urllib.request.Request(url)
    r = op.open(req, timeout=40)
    html = _read(r)
    if "acw_sc__v2" in html and "user-title" not in html and "上传时间" not in html:
        v = solve_acw(html, re.sub(r"\W", "_", tag)[:24])
        if v:
            cj.set_cookie(http.cookiejar.Cookie(
                version=0, name="acw_sc__v2", value=v, port=None, port_specified=False,
                domain=r.geturl().split("/")[2], domain_specified=True, domain_initial_dot=False,
                path="/", path_specified=True, secure=False, expires=None, discard=True,
                comment=None, comment_url=None, rest={}, rfc2109=False))
            html = _read(op.open(urllib.request.Request(url), timeout=40))
    return html


def file_info(url, tag):
    h = fetch(url, tag)
    d = {}
    for k, lbl in [("name", "文件名称"), ("size", "文件大小"), ("time", "上传时间"),
                   ("share", "分享时间"), ("dl", "下载次数")]:
        m = re.search(lbl + r"[：:<\s\w=\"']{0,80}?>\s*([^<>]{1,60})", h)
        if m:
            d[k] = re.sub(r"\s+", " ", m.group(1)).strip()
    m = re.search(r"<title>(.*?)</title>", h, re.S)
    d["title"] = m.group(1).strip() if m else ""
    d["_len"] = len(h)
    return d


if __name__ == "__main__":
    for u in sys.argv[1:]:
        print(json.dumps({u: file_info(u, u.split("/")[-1])}, ensure_ascii=False))
