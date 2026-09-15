# -*- coding: utf-8 -*-
"""
iapp3 (.iyu) script decryption for com.huage.egaocl  --  VERIFIED
Fully reverses assets/lib.so (36896 bytes) -> iapp project bundle -> mian.iyu

Native logic recovered from libygsiyu.so (iapp engine, ARM32, full symtab):
  iapp::mete::slky(Interact*,jbyteArray,jbyteArray)  @0x8ccc   keyed MD5 scramble
  iapp::mete::slky(Interact*,string,string)          @0x9440   same, string args
  iapp::Interact::gdth()  @0x8bac  -> "A21FE8A824QQQQQQQQQQWWWWWWWWWWEE"  (it+8  == "")
  iapp::Interact::dngb()  @0x8afc  -> to_string(com.iapp.app.f.b()) = "5556367" (it+0x14 == "")
  iapp::Interact::idbfj(string const&) @0x965c -> builds S, picks salt T, returns slky(S,T)
  iapp::mete::asendn(Interact*,data,key,int) @0x8430 -> AES/CBC/PKCS5Padding, IV = key
  iapp::mete::djyj(Interact*,data,key)       @0x838c -> repeating-key XOR
  iapp::Interact::rkyan(jbyteArray)          @0x82d8 -> MD5
  iapp::burden::b(jstring,jstring)           @0xa1f4 -> whole load path
  iapp::h3(JNIEnv*,jobject,jclass,jstring)   @0xb26c -> Java entry, arg2 = "mian.iyu"
"""
import hashlib
from Crypto.Cipher import AES

APK = 'E:/gear_analysis/apks/huage_egaocl.apk'
LIB = 'E:/gear_analysis/tb/lib.so'

# ---- constants baked into libygsiyu.so -------------------------------------
GDTH = b'A21FE8A824QQQQQQQQQQWWWWWWWWWWEE'   # Interact::gdth() default (it+8 empty)
DNGB = b'5556367'                            # Interact::dngb() default = to_string(f.b())

def cdiv(a, b):                              # C truncating division
    q = abs(a) // abs(b)
    return q if (a < 0) == (b < 0) else -q
def cmod(a, b):
    return a - cdiv(a, b) * b
def s8(x):
    return x - 256 if x >= 128 else x

def slky(a1, a2):
    """iapp::mete::slky - args are byte arrays (raw bytes of the strings)."""
    L = len(a1)
    if L == 0:
        return b''
    ssum = L + sum(s8(x) for x in a1)                    # len + signed byte sum
    q    = cdiv(ssum, L)                                 # XOR seed (sum/len)
    rem  = cmod(ssum, L)                                 # goes into the mask
    h    = cdiv(s8(a1[-1]) * s8(a1[0]) + ssum, L)        # std::to_string(h)
    buf  = bytearray(a1) + str(h).encode()
    sl   = rem + (len(a2) if a2 is not None else 0)
    if a2:
        buf += a2
    mask = (8 + sl) & 0xFF
    for i in range(len(buf)):                            # XOR-in-place with q
        buf[i] ^= (q & 0xFF)
    md = bytearray(hashlib.md5(bytes(buf)).digest())     # Interact::rkyan = MD5
    for i in range(16):                                  # scramble pass
        j = abs(s8(md[i])) % 16
        if j > 8:
            md[i] = (md[i] ^ mask) & 0xFF
        md[j], md[i] = md[i], md[j]
    return bytes(md)

def aes_dec(data, key):                       # asendn(...,MODE=2): AES/CBC/PKCS5, key==IV
    return AES.new(key, AES.MODE_CBC, key).decrypt(data[:len(data) // 16 * 16])

def xorrep(d, k):                             # djyj
    return bytes(b ^ k[i % len(k)] for i, b in enumerate(d))

def unpkcs5(d):
    n = d[-1] if d else 0
    return d[:-n] if 1 <= n <= 16 and d[-n:] == bytes([n]) * n else None

def iapp_key():
    """Interact::idbfj("") -> the 16-byte root key (offline-deterministic)."""
    versionName = b'11.1.0'                  # PackageInfo.versionName
    packageName = b'com.huage.egaocl'        # Context.getPackageName()
    label       = b'\xe9\xbd\xbf\xe8\xbd\xae\xe8\xbe\x85\xe5\x8a\xa9'  # android:label="齿轮辅助"
    versionCode = b'100005'                  # to_string(PackageInfo.versionCode)
    arg         = b''                        # com.iapp.app.e.af(ctx) -> NULL offline
    S = GDTH + versionName + packageName + label + versionCode + DNGB + arg
    sel = (S[-1] * S[0] + len(S) + sum(S)) % 6            # idbfj switch selector
    T   = [versionName, packageName, label, versionCode, GDTH, DNGB][sel]
    return S, sel, T, slky(S, T)

def load_bundle():
    S, sel, T, r8 = iapp_key()
    sb = slky(r8, slky(r8, r8))              # burden::b: sl=slky(r8,r8); sb=slky(r8,sl)
    fp = xorrep(aes_dec(open(LIB, 'rb').read(), sb), sb)
    return S, sel, T, r8, sb, fp

def entry(fp, name):
    """Extract and decrypt one bundle entry (<name> -> plaintext)."""
    str2c = GDTH + DNGB
    K1 = slky(name, str2c)
    i1 = fp.find(K1)
    if i1 < 0:
        return None
    K2 = slky(name, DNGB + GDTH)
    i2 = fp.find(K2, i1 + 16)
    if i2 < 0:
        return None
    K3 = slky(name + str2c, name)
    return i1, i2, xorrep(aes_dec(fp[i1 + 16:i2], K3), K3)

def main():
    S, sel, T, r8, sb, fp = load_bundle()
    print('S      =', S)
    print('sel    =', sel, '-> salt =', T)
    print('r8     =', r8.hex())
    print('sb     =', sb.hex())
    print('lib.so : %d bytes, pkcs5 stage1 ok = %s' % (len(open(LIB, 'rb').read()),
          unpkcs5(aes_dec(open(LIB, 'rb').read(), sb)) is not None))
    i1, i2, mian = entry(fp, b'mian.iyu')
    print('mian.iyu: marker@%d footer@%d cipher=%d plain=%d bytes pkcs5 ok = %s'
          % (i1, i2, i2 - i1 - 16, len(mian),
             unpkcs5(aes_dec(fp[i1 + 16:i2], slky(b'mian.iyu' + GDTH + DNGB, b'mian.iyu'))) is not None))
    open('E:/gear_analysis/tb/w/mian_iyu.bin', 'wb').write(mian)
    open('E:/gear_analysis/tb/w/lib_bundle.bin', 'wb').write(fp)
    print('---- mian.iyu head ----')
    print(mian[:200].decode('utf-8', 'replace'))
    print('---- mian.iyu tail ----')
    print(mian[-200:].decode('utf-8', 'replace'))

if __name__ == '__main__':
    main()
