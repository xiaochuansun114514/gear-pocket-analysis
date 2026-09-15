# -*- coding: utf-8 -*-
"""通用 iapp3 bundle 解密器 —— 三个应用(egaocl/btxl/fangfeng)一次全解

算法全在 libygsiyu.so 里，这个脚本就是把它离线复现了一遍，跑起来不需要设备、不用开 app。
推导过程都记在 ../../逆向思路.md 了，这里只留我算过之后写下来的东西。

当初是先 readelf -s 翻了一眼符号表，看见 slky / asendn / djyj 这几个名字，
就知道该从哪儿下手了，省了读汇编的功夫。
"""
import hashlib, zipfile, os
from Crypto.Cipher import AES

DNGB_DEFAULT = b'5556367'
# 一开始我以为 DNGB 是 native 里的常量，三款应用应该共用同一个值，
# 就拿 egaocl 的 5556367 去解 btxl 和 fangfeng —— AES 出来全是垃圾。
# 回头才想明白 dngb() 是 to_string(com.iapp.app.f.b())，值是从 Java 侧传上来的，
# 每个 apk 的 classes.dex 各编各的。这也是为什么在 .so 里 grep 这几个数根本没有。
DN = {'egaocl': b'5556367', 'btxl': b'3401192', 'fangfeng': b'2405525'}

APPS = {
 'egaocl':   dict(pkg=b'com.huage.egaocl',        ver=b'11.1.0', vc=b'100005',
                  label='齿轮辅助',   gdth=b'A21FE8A824QQQQQQQQQQWWWWWWWWWWEE',
                  apk=r'E:\gear_analysis\apks\huage_egaocl.apk'),
 'btxl':     dict(pkg=b'com.huage.pubgm.btxl',    ver=b'2.3.0',  vc=b'100001',
                  label='冰糖雪梨',   gdth=b'8014598C3BQQQQQQQQQQWWWWWWWWWWEE',
                  apk=r'E:\gear_analysis\apks\huage_pubgm_btxl.apk'),
 'fangfeng': dict(pkg=b'com.huage.pink.fangfeng', ver=b'6.5.1',  vc=b'100005',
                  label='哔可防封',   gdth=b'883963988BQQQQQQQQQQWWWWWWWWWWEE',
                  apk=r'E:\gear_analysis\apks\huage_pink_fangfeng.apk'),
}

def cdiv(a,b):
    # slky 是在 C 里编的，C 的除法往零截断，Python 往下取整
    # （-7/2 在 C 里是 -3，在 Python 里是 -4）。所以照着汇编抄的时候，
    # // 和 % 都得换成这俩，不然密钥算出来是错的。
    q=abs(a)//abs(b); return q if (a<0)==(b<0) else -q
def cmod(a,b): return a-cdiv(a,b)*b
def s8(x):
    # 汇编里求和、取绝对值都是按有符号字节算的。
    # 我一开始按无符号写的，跑出来密钥不对，查了半天——因为大部分输入下两种算法结果一样，
    # 只有字节上了 128 才分叉，很难一眼看出来。
    return x-256 if x>=128 else x

def slky(a1,a2):
    """iapp::mete::slky —— 从汇编一行行抄下来的。

    不是标准 HMAC，是作者自己搓的加盐 MD5：先按长度和有符号字节和算个种子，
    再异或、MD5、然后来回换位。找现成实现是找不到的，只能照着抄。
    """
    L=len(a1)
    if L==0: return b''
    ssum=L+sum(s8(x) for x in a1); q=cdiv(ssum,L); rem=cmod(ssum,L)
    h=cdiv(s8(a1[-1])*s8(a1[0])+ssum,L)
    buf=bytearray(a1)+str(h).encode(); sl=rem+(len(a2) if a2 else 0)
    if a2: buf+=a2
    mask=(8+sl)&0xFF
    for i in range(len(buf)): buf[i]^=(q&0xFF)
    md=bytearray(hashlib.md5(bytes(buf)).digest())
    for i in range(16):
        j=abs(s8(md[i]))%16
        if j>8: md[i]=(md[i]^mask)&0xFF
        md[j],md[i]=md[i],md[j]
    return bytes(md)

def aes_dec(d,k):
    # asendn(mode=2)：AES-128-CBC/PKCS5。
    # IV 从汇编看像是跟 KEY 同一个值，但这假设猜错就全盘皆输，
    # 所以我在真机上挂了个只读 hook 抓了下参数，确认 IV 确实就是 KEY。
    return AES.new(k,AES.MODE_CBC,k).decrypt(d[:len(d)//16*16])
def xorrep(d,k): return bytes(b^k[i%len(k)] for i,b in enumerate(d))   # djyj：循环 XOR
def unpkcs5(d):
    # 靠这个确认密钥对不对。PKCS5 填充校验过了基本就没跑，
    # 比盯着乱码看可读性靠谱得多。
    n=d[-1] if d else 0
    return d[:-n] if 1<=n<=16 and d[-n:]==bytes([n])*n else None

def get_lib(apk):
    z=zipfile.ZipFile(apk)
    b=z.read('assets/lib.so')
    return b

def solve(tag):
    A=APPS[tag]; GDTH=A['gdth']; DNGB=DN[tag]; label=A['label'].encode('utf-8')
    lib=get_lib(A['apk'])
    S = GDTH + A['ver'] + A['pkg'] + label + A['vc'] + DNGB + b''
    sel=(S[-1]*S[0]+len(S)+sum(S))%6
    T=[A['ver'],A['pkg'],label,A['vc'],GDTH,DNGB][sel]
    r8=slky(S,T)
    sb=slky(r8,slky(r8,r8))
    fp=xorrep(aes_dec(lib,sb),sb)
    pad_ok = unpkcs5(aes_dec(lib,sb)) is not None
    print('='*72)
    print('[%s] %s  lib.so=%d B' % (tag, A['pkg'].decode(), len(lib)))
    print('  sel=%d -> T=%r' % (sel,T))
    print('  r8=%s' % r8.hex())
    print('  sb=%s   pkcs5存活=%s' % (sb.hex(), pad_ok))
    return A,GDTH,sb,fp

def entry(fp,GDTH,name,DNGB):
    """从解好的包里抠一个条目。

    格式是 [K1:16B][密文][K2:16B]：K1 是这个条目的开头标记，K2 是结尾标记，
    夹在中间那段密文再用 K3 解。所以我一开始的思路就是拿名字去算 K1，
    在包里 find 一下——能找到就说明名字猜对了，找不到就换个名再试。
    """
    s2c=GDTH+DNGB
    K1=slky(name,s2c); i1=fp.find(K1)
    if i1<0: return None
    K2=slky(name,DNGB+GDTH); i2=fp.find(K2,i1+16)
    if i2<0: return None
    K3=slky(name+s2c,name)
    return i1,i2,xorrep(aes_dec(fp[i1+16:i2],K3),K3)

# 这些是最早一批能猜到的名字。剩下的（xf.iyu / qzhtc.iyu 这种作者自造的缩写）
# 我暴力跑过二十多万种组合，一个都没中，才反应过来这类名字是猜不到的。
# 后来换成从已解出的脚本明文里正则扫引用，一层层往外滚，从 1 个滚到了 15 个。
NAMES=[b'mian.iyu',b'import.mjs',b'null.iyu',b'import.iyu',b'init.iyu',
       b'mian.mjs',b'main.iyu',b'a.iyu',b'b.iyu',b'c.iyu',b'lua.iyu',
       b'index.iyu',b'mian',b'import']

if __name__=='__main__':
    os.makedirs(r'E:\gear_analysis\tb\unpacked',exist_ok=True)
    for tag in APPS:
        try:
            A,GDTH,sb,fp=solve(tag); DNGB=DN[tag]
        except Exception as e:
            print('[%s] 失败: %s' % (tag,e)); continue
        open(r'E:\gear_analysis\tb\unpacked\%s_bundle.bin'%tag,'wb').write(fp)
        hits=0
        for n in NAMES:
            r=entry(fp,GDTH,n,DNGB)
            if r:
                i1,i2,pt=r
                pr=sum(1 for ch in pt if 32<=ch<127 or ch>=0xC0)/max(1,len(pt))
                print('  命中条目 %-12s marker@%-7d footer@%-7d 明文=%d B  可打印率=%.2f'
                      % (n.decode(),i1,i2,len(pt),pr))
                if pr>0.5:
                    fn=r'E:\gear_analysis\tb\unpacked\%s_%s'%(tag,n.decode().replace('.','_'))
                    open(fn,'wb').write(pt)
                    print('      -> 已存 %s' % fn)
                    print('      头: %r' % pt[:120])
                hits+=1
        if hits==0:
            print('  未命中任何候选条目名 —— fp 前 64B: %s' % fp[:64].hex())
