#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""只读抓取蓝奏云分享文件夹目录清单 (安全防御用). 纯标准库. 不登录, 不下载文件本体."""
import re, sys, json, time, urllib.parse, urllib.request, http.cookiejar

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

FOLDERS = [
    "https://wwasl.lanzoul.com/b01bjff59c",
    "https://wwasl.lanzoul.com/b01bjff5ad",
    "https://wwasl.lanzoul.com/b01bjff5be",
    "https://wwasl.lanzoul.com/b01bjkow4d",
    "https://wwasl.lanzoul.com/b01bjmzm5c",
    "https://wwasl.lanzoul.com/b01bjmzrjg",
    "https://wwasb.lanzoul.com/b01bjfkdcd",
    "https://wwasb.lanzoux.com/b01bjfkdab",
    "https://wwasb.lanzoux.com/b01bjfkdbc",
    "https://wwasl.lanzoum.com/b01bjff50d",
]


def mkopener():
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    op.addheaders = [("User-Agent", UA),
                     ("Accept", "text/html,application/json,*/*")]
    return op


def fetch_folder(url):
    op = mkopener()
    out = {"url": url, "files": [], "note": ""}
    try:
        htm = op.open(url, timeout=40).read().decode("utf-8", "replace")
    except Exception as e:
        out["note"] = "HTTP_ERR " + repr(e)
        return out
    if "user-title" not in htm:
        m = re.search(r"<title>(.*?)</title>", htm, re.S)
        out["note"] = "EMPTY_OR_DEAD title=%r len=%d" % (
            (m.group(1).strip() if m else ""), len(htm))
        return out
    t = re.search(r'<div class="user-title">(.*?)</div>', htm, re.S)
    out["title"] = t.group(1).strip() if t else ""
    n = re.search(r'<div class="user-name">(.*?)<span', htm, re.S)
    out["owner"] = n.group(1).strip() if n else ""
    fid = re.search(r"url : '/filemoreajax\.php\?file=(\d+)'", htm)
    uid = re.search(r"'uid':'(\d+)'", htm)
    puid = re.search(r"'puid':'([^']+)'", htm)
    tk = re.search(r"var ibd3zz = '([^']+)'", htm)
    kk = re.search(r"var _hbg1s = '([^']+)'", htm)
    if not (fid and uid and puid and tk and kk):
        out["note"] = "PARSE_FAIL"
        return out
    fid, uid, puid, tk, kk = (fid.group(1), uid.group(1), puid.group(1),
                              tk.group(1), kk.group(1))
    ajax = urllib.parse.urljoin(url, "/filemoreajax.php?file=" + fid)
    pg = 1
    while True:
        body = urllib.parse.urlencode({
            "lx": "2", "fid": fid, "uid": uid, "puid": puid,
            "pg": str(pg), "rep": "0", "t": tk, "k": kk,
            "up": "1", "vip": "0", "webfoldersign": ""}).encode()
        req = urllib.request.Request(url=ajax, data=body,
                                     headers={"X-Requested-With": "XMLHttpRequest",
                                              "Referer": url})
        try:
            raw = op.open(req, timeout=40).read().decode("utf-8", "replace")
            j = json.loads(raw)
        except Exception as e:
            out["note"] = "AJAX_ERR pg=%d %r" % (pg, e)
            break
        if str(j.get("zt")) != "1":
            if pg == 1:
                out["note"] = "ZT=%s info=%s" % (j.get("zt"), j.get("info"))
            break
        items = j.get("text") or []
        for it in items:
            out["files"].append({
                "id": it.get("id"),
                "name": re.sub(r"<[^>]+>", "", it.get("name_all") or ""),
                "size": it.get("size"),
                "time": it.get("time"),
                "t": it.get("t"),
            })
        if len(items) < 50:
            break
        pg += 1
        time.sleep(0.6)
    return out


if __name__ == "__main__":
    res = []
    for u in FOLDERS:
        try:
            d = fetch_folder(u)
        except Exception as e:
            d = {"url": u, "error": repr(e), "files": [], "note": ""}
        res.append(d)
        print(json.dumps(d, ensure_ascii=False))
        sys.stdout.flush()
        time.sleep(1)
    open(r"E:\gear_analysis\writeup\raw\lanzou_folders.json", "w",
         encoding="utf-8").write(json.dumps(res, ensure_ascii=False, indent=1))
