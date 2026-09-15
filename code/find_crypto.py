#!/usr/bin/env python3
# find_crypto.py — 在 dex 里捞用到 AES/Cipher/SecretKeySpec 的方法，捞到就反汇编

# 写这个是因为前面拿字符串常量的 XOR 流算法去暴力破 XL1，六万多种组合全试了都不对，
# 只解出前两个字节是 "[{"，第三个字节开始就乱码。那就说明 XL1 不是 XOR 流，
# 是正经的 AES。于是换方向：直接在 dump 出来的 dex 里搜 Cipher 相关的调用点。
# 用法: python find_crypto.py <dex 路径>
import sys, logging
logging.getLogger('androguard').setLevel(logging.CRITICAL)
from androguard.core.dex import DEX

def main(path):
    d = DEX(open(path, 'rb').read())
    for cls in d.get_classes():
        for m in cls.get_methods():
            code = m.get_code()
            if code is None:
                continue
            ins = list(code.get_bc().get_instructions())
            body = ' '.join(str(i) for i in ins)
            if any(x in body for x in ('SecretKeySpec', 'Cipher', 'AES', 'IvParameterSpec')):
                print('\n===== %s -> %s =====' % (cls.get_name(), m.get_name()))
                for i in ins:
                    print('   %s' % i)

if __name__ == '__main__':
    main(sys.argv[1])
