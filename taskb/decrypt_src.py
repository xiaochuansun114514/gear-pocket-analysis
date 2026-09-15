#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# decrypt_src.py — 齿轮辅助(com.huage.egaocl) beingyi 壳 src/ 文件解密器
#
# 当时 jadx 打不开 src/ 下这三个文件，直接报 "not a valid dex"，
# 那说明是被加密了，不是文件坏了。看了眼三个文件的开头 8 字节，完全一样：
#     07 0a 15 24 58 46 54 67
# 既然解密后都是 dex，开头就该是 "dex\n035\0"，拿魔数跟密文头逐字节异或一下，
# 出来正好是 "com.huag" —— 密钥就是包名，循环 XOR 一遍就完了。
#
# 外面还套着 360 加固(libjiagu.so) 和云注入(armadillo)，
# 但这一层是纯 Java + 自定义 XOR，四层壳里它最软，从这儿下手最省事。
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
