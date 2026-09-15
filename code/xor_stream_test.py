#!/usr/bin/env python3
# xor_stream_test.py — 试试 XL1 是不是也用字符串常量那套 XOR 流加密的
#
# 当时刚把壳的字符串解密算法还原出来，就想着配置文件会不会是同一个套路，
# 于是 salt 和 key 各从 0 试到 255，六万多种组合全跑了一遍。
#
# 结果：只有前两个字节能解出 "[{"（因为 JSON 开头固定，是被硬凑出来的），
# 从第三个字节起全是乱码。也就是说 XL1 根本不是 XOR 流。
# 这次白跑不算亏 —— 正是它把 AES 这个方向给逼出来了。
import binascii

def hex_decode(data: bytes) -> bytes:
    return binascii.unhexlify(data.strip())

def xor_stream_decrypt(data: bytes, salt: int, key: int) -> bytes:
    """字符串常量解密算法: b[0]^=salt; b[i] = b[i-1]^b[i]^key"""
    out = bytearray(data)
    if not out:
        return bytes(out)
    out[0] ^= salt
    prev = out[0]
    for i in range(1, len(out)):
        out[i] = prev ^ out[i] ^ key
        prev = out[i]
    return bytes(out)

def main(path):
    raw = hex_decode(open(path, 'rb').read())
    print("密文长度:", len(raw), " (16*%d + %d, 非块对齐)" % divmod(len(raw), 16))
    # 假设明文 JSON 以 "[{" 开头: '['=0x5B, '{'=0x7B
    s = raw[0] ^ 0x5B
    k = 0x5B ^ raw[1] ^ 0x7B
    p = xor_stream_decrypt(raw, s, k)
    print("salt=%d key=%d 解密前 16 字节: %r" % (s, k, p[:16]))
    print("=> 前两字节命中 '[{', 第三字节应为 '\"'(0x22) 实际为 0x%02x -> 算法不符" % p[2])

if __name__ == '__main__':
    main(r"E:\gear_analysis\XL1_config.txt")
