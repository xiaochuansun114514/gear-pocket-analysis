# -*- coding: utf-8 -*-
"""iapp3 bundle 条目名「离线字典攻击」—— 不用跑设备、不用 hook

原理
----
每个条目在 bundle 里的布局是：

    [K1:16][AES-CBC 密文][K2:16]

其中 K1 = slky(名字, gdth+dngb)、K2 = slky(名字, dngb+gdth)，都是**名字的纯函数**。
所以 K1 相当于一枚 16 字节的、可被 find() 搜索的「条目名指纹」：

    拿候选名字算出 K1 -> 在解密后的 bundle 里 find(K1) -> 命中即名字正确

于是「枚举条目名」这个原本只能靠运行时 hook iapp::h3 抓的问题，
变成了一次离线字典查询。

字典怎么来
----------
不需要任何外部词表。有效候选名**本来就存在于样本自己身上**：

  1. 已解出的脚本（.iyu/.mjs）里出现的所有 token
  2. APK 内所有 dex / so / arsc 里的所有 token
  3. 上面每个 token 再拼上 iapp 的脚本后缀（.iyu/.myu/.mjs/.lua/.m）

实测这一套在冰糖雪梨上解出了 fx.myu / alms.myu / 分享.iyu / egaocl.iyu。

用法
----
    python dec_names.py btxl            # 扫冰糖雪梨
    python dec_names.py btxl --write    # 顺便把命中的条目写到 unpacked/

依赖同目录的 dec_all.py（提供 slky / asendn / djyj 与三款应用的身份常量）。
"""
import glob
import os
import re
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dec_all import APPS, DN, solve, entry  # noqa: E402

# iapp 认得出来的脚本后缀；'.iyu' 是界面、'.myu'/'.mjs' 是逻辑、'.lua' 是原引擎
EXTS = [b'', b'.iyu', b'.myu', b'.mjs', b'.lua', b'.m']
# 单个 token 的长度窗口：太短会撞出一堆垃圾候选，太长不是文件名
TOKEN_MIN, TOKEN_MAX = 2, 16
NAME_MIN, NAME_MAX = 4, 24
# 解出来至少得有这么多字节才算命中，避免 16 字节指纹撞库
MIN_PLAIN = 8
# 明文里「可打印字符」的最低占比；低于这个值说明名字猜错了（AES 解出乱码）
MIN_PRINTABLE = 0.45

TOKEN_RE = re.compile(rb'[A-Za-z0-9_\x80-\xff]{%d,%d}' % (TOKEN_MIN, TOKEN_MAX))


def harvest(dir_or_globs, apks):
    """从已解出的脚本 + APK 内的 dex/so 里收集 token 作为字典。"""
    toks = set()
    for p in dir_or_globs:
        for f in glob.glob(p):
            if os.path.isfile(f):
                toks |= set(TOKEN_RE.findall(open(f, 'rb').read()))
    for apk in apks:
        if not os.path.exists(apk):
            continue
        try:
            z = zipfile.ZipFile(apk)
        except Exception:
            continue
        for n in z.namelist():
            if n.endswith(('.dex', '.so', '.arsc', '.xml')):
                toks |= set(TOKEN_RE.findall(z.read(n)))
    return toks


def candidates(toks, extra=()):
    names = set(extra)
    for t in toks:
        for e in EXTS:
            names.add(t + e)
    return {n for n in names if NAME_MIN <= len(n) <= NAME_MAX}


def printable_ratio(b):
    if not b:
        return 0.0
    ok = sum(1 for ch in b if 32 <= ch < 127 or ch >= 0xC0)
    return ok / len(b)


def sweep(tag, write=False, extra=()):
    A, GDTH, sb, fp = solve(tag)
    DNGB = DN[tag]
    toks = harvest(
        [r'E:\gear_analysis\tb\unpacked\*'],
        glob.glob(r'E:\gear_analysis\apks\*.apk'),
    )
    names = candidates(toks, extra)
    print('[%s] bundle=%d B  字典 token=%d  候选名=%d' % (tag, len(fp), len(toks), len(names)))

    hits = {}
    for n in names:
        r = entry(fp, GDTH, n, DNGB)
        if not r:
            continue
        i1, i2, pt = r
        if len(pt) < MIN_PLAIN or printable_ratio(pt) < MIN_PRINTABLE:
            continue
        hits[i1] = (n, pt, i2)

    for i1 in sorted(hits):
        n, pt, i2 = hits[i1]
        print('  @%-7d -> %-7d %-22s %7d B' % (i1, i2, n.decode('utf-8', 'replace'), len(pt)))
        if write:
            dst = os.path.join(r'E:\gear_analysis\tb\unpacked',
                               '%s__%s' % (tag, n.decode('utf-8', 'replace').replace('/', '_')))
            open(dst, 'wb').write(pt)

    # 把已知条目的区间拼起来，算出哪些字节还没被认领
    cur, gaps = 0, []
    for i1 in sorted(hits, key=lambda k: hits[k][0]):
        if i1 > cur:
            gaps.append((cur, i1, i1 - cur))
        cur = max(cur, hits[i1][2])
    if cur < len(fp):
        gaps.append((cur, len(fp), len(fp) - cur))
    print('  未解区间: %s' % [(a, b, c) for a, b, c in gaps if c > 32])


if __name__ == '__main__':
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    tag = args[0] if args else 'btxl'
    if tag not in APPS:
        sys.exit('tag 只能是 %s' % list(APPS))
    sweep(tag, write='--write' in sys.argv)
