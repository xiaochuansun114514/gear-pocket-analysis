#!/usr/bin/env python3
# ag_findkey.py — locate methods whose code references a given string, print full disassembly.
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
