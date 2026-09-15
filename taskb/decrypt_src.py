#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# decrypt_src.py — 齿轮辅助(com.huage.egaocl) beingyi 壳 src/ 文件解密器
#
# 核心发现：beingyi(别疑惑) SubApp 壳把真实 dex 以「XOR 流」加密后放在 APK 的 src/ 目录，
# 文件名是 md5 风格随机串。密钥 = 包名 "com.huage.egaocl"（循环 XOR）。
# 外层还有 360 加固(libjiagu.so) + 云注入(armadillo)。
#
# 用法: python decrypt_src.py <apk路径> <输出目录>
import sys, os, zipfile

def xor(data, key):
    kb = key.encode('latin-1')
    return bytes(b ^ kb[i % len(kb)] for i, b in enumerate(data))

def main(apk, outdir):
    os.makedirs(outdir, exist_ok=True)
    z = zipfile.ZipFile(apk)
    key = 'com.huage.egaocl'
    for name in z.namelist():
        if not name.startswith('src/'):
            continue
        data = z.read(name)
        dec = xor(data, key)
        if dec[:4] == b'dex\n':
            out = os.path.join(outdir, os.path.basename(name) + '.dex')
            with open(out, 'wb') as f:
                f.write(dec)
            print('[OK]  %s -> %s  (%d 字节, dex 魔数验证通过)' % (name, out, len(dec)))
        else:
            out = os.path.join(outdir, os.path.basename(name) + '.bin')
            with open(out, 'wb') as f:
                f.write(dec)
            print('[? ]  %s -> %s  (%d 字节, 非 dex: %r)' % (name, out, len(dec), dec[:8]))

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else r'E:\gear_analysis\apks\huage_egaocl.apk',
         sys.argv[2] if len(sys.argv) > 2 else r'E:\gear_analysis\tb\decrypted')
