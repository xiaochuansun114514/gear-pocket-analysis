#!/usr/bin/env python3
# ag_findkey.py — 按字符串反查方法，找到了就把整段反汇编打出来
#
# 和 dex_disasm.py 干的是同一件事，区别是这个用 androguard，省事。
# 壳把类名方法名都换成卢恩字符了（ᛱᛱᛱᛷᛷ 这种），根本没法按名字找，
# 只能反过来先找到某个字符串，再顺着引用往上摸到方法。
import sys, logging
logging.disable(logging.CRITICAL)
from androguard.core.dex import DEX

def run(path, needle):
    d = DEX(open(path, 'rb').read())
    print('=== dex %s : looking for %r ===' % (path, needle))
    for m in d.get_methods():
        code = m.get_code()
        if code is None:
            continue
        try:
            instrs = list(code.get_bc().get_instructions())
        except Exception:
            continue
        body = '\n'.join(str(i) for i in instrs)
        if needle in body:
            print('\n===== %s -> %s =====' % (m.get_class_name(), m.get_name()))
            for i in instrs:
                print('   %s' % i)

if __name__ == '__main__':
    run(sys.argv[1], sys.argv[2])
