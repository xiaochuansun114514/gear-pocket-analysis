#!/usr/bin/env python3
# find_crypto.py — 定位 dex 里使用 AES/Cipher/SecretKeySpec 的加密方法并反汇编
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
