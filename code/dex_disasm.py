#!/usr/bin/env python3
# dex_disasm.py — minimal DEX parser + disassembler to locate decrypt methods.
# Usage: python dex_disasm.py <dex> <string_idx> [string_idx ...]
#   Finds all code items referencing the given string_ids and dumps their
#   const-string / const-class / invoke targets so we can read the method.
import struct, sys

def uleb128(d, off):
    r = 0; s = 0
    while True:
        b = d[off]; off += 1
        r |= (b & 0x7f) << s
        if not (b & 0x80): break
        s += 7
    return r, off

class Dex:
    def __init__(self, path):
        self.d = open(path, 'rb').read()
        self.h = {}
        offs = {'string_ids_size':0x38,'string_ids_off':0x3C,'type_ids_size':0x40,'type_ids_off':0x44,
                'proto_ids_size':0x48,'proto_ids_off':0x4C,'field_ids_size':0x50,'field_ids_off':0x54,
                'method_ids_size':0x58,'method_ids_off':0x5C,'class_defs_size':0x60,'class_defs_off':0x64,
                'data_size':0x68,'data_off':0x6C}
        for k, o in offs.items():
            self.h[k] = struct.unpack('<I', self.d[o:o+4])[0]
        self.h['header_size'] = struct.unpack('<I', self.d[0x24:0x28])[0]
    def string(self, idx):
        try:
            off = struct.unpack('<I', self.d[self.h['string_ids_off']+idx*4:self.h['string_ids_off']+idx*4+4])[0]
            _, p = uleb128(self.d, off)
            e = self.d.index(b'\x00', p)
            return self.d[p:e].decode('utf-8', 'replace')
        except Exception:
            return '<?%d>' % idx
    def type(self, idx):
        try:
            sidx = struct.unpack('<I', self.d[self.h['type_ids_off']+idx*4:self.h['type_ids_off']+idx*4+4])[0]
            return self.string(sidx)
        except Exception:
            return '<?type%d>' % idx
    def method_name(self, idx):
        try:
            o = self.h['method_ids_off'] + idx*8
            cls = struct.unpack('<H', self.d[o:o+2])[0]
            name = struct.unpack('<I', self.d[o+4:o+8])[0]
            return self.type(cls) + '->' + self.string(name)
        except Exception:
            return '<?m%d>' % idx
    def methods_referencing(self, sidx):
        """Scan every code item for const-string/const-string/jumbo referencing sidx."""
        hits = []
        cdo = self.h['class_defs_off']
        for c in range(self.h['class_defs_size']):
            o = cdo + c*32
            cls_idx = struct.unpack('<I', self.d[o:o+4])[0]
            cdata_off = struct.unpack('<I', self.d[o+24:o+28])[0]
            if cdata_off == 0: continue
            p = cdata_off
            static_f, p = uleb128(self.d, p)
            inst_f, p = uleb128(self.d, p)
            direct_m, p = uleb128(self.d, p)
            virt_m, p = uleb128(self.d, p)
            # skip fields
            for _ in range(static_f + inst_f):
                _, p = uleb128(self.d, p)  # field_idx_diff
                _, p = uleb128(self.d, p)  # access_flags
            # methods
            for k in range(direct_m + virt_m):
                midx_diff, p = uleb128(self.d, p)
                acc, p = uleb128(self.d, p)
                code_off, p = uleb128(self.d, p)
                if code_off == 0: continue
                # parse code_item at code_off
                co = code_off
                regs = struct.unpack('<H', self.d[co:co+2])[0]
                ins_size = struct.unpack('<H', self.d[co+2:co+4])[0]
                insns_size = struct.unpack('<I', self.d[co+12:co+16])[0]
                insns = self.d[co+16:co+16+insns_size*2]
                # scan insns for const-string referencing sidx
                found = False
                for i in range(0, len(insns)-1, 2):
                    op = insns[i] & 0xFF
                    if op == 0x1A and i+4 <= len(insns):  # const-string vAA, string@BBBB
                        sref = struct.unpack('<H', insns[i+2:i+4])[0]
                        if sref == sidx:
                            found = True; break
                    elif op == 0x1B and i+6 <= len(insns):  # const-string/jumbo
                        sref = struct.unpack('<I', insns[i+2:i+6])[0]
                        if sref == sidx:
                            found = True; break
                if found:
                    hits.append((cls_idx, k, midx_diff, code_off, insns_size, insns))
        return hits

def fmt_insn(d, insns, i):
    """Decode one 16-bit-code-unit instruction for readability."""
    op = insns[i] & 0xFF
    if op == 0x1A:
        v = insns[i+1] & 0x0F
        sref = struct.unpack('<H', insns[i+2:i+4])[0]
        return 'const-string v%d, "%s"' % (v, d.string(sref)), 2
    if op == 0x1B:
        v = insns[i+1] & 0x0F
        sref = struct.unpack('<I', insns[i+2:i+6])[0]
        return 'const-string/jumbo v%d, "%s"' % (v, d.string(sref)), 3
    if op == 0x1C:
        v = insns[i+1] & 0x0F
        tref = struct.unpack('<H', insns[i+2:i+4])[0]
        return 'const-class v%d, %s' % (v, d.type(tref)), 2
    if op == 0x22:
        v = insns[i+1] & 0x0F
        tref = struct.unpack('<H', insns[i+2:i+4])[0]
        return 'new-instance v%d, %s' % (v, d.type(tref)), 2
    if op == 0x70:
        cnt = insns[i+1] & 0x0F
        mref = struct.unpack('<H', insns[i+2:i+4])[0]
        return 'invoke-direct {%d args} %s' % (cnt, d.method_name(mref)), 3
    if op == 0x71:
        cnt = insns[i+1] & 0x0F
        mref = struct.unpack('<H', insns[i+2:i+4])[0]
        return 'invoke-static {%d args} %s' % (cnt, d.method_name(mref)), 3
    if op == 0x6E:
        cnt = insns[i+1] & 0x0F
        mref = struct.unpack('<H', insns[i+2:i+4])[0]
        return 'invoke-virtual {%d args} %s' % (cnt, d.method_name(mref)), 3
    if op == 0x0E:
        return 'return-void', 1
    if op == 0x0F:
        return 'return v%d' % (insns[i+1] & 0x0F), 1
    if op == 0x11:
        return 'return-object v%d' % (insns[i+1] & 0x0F), 1
    if op == 0x12:
        lit = struct.unpack('<i', insns[i+2:i+4])[0]
        return 'const/4 v%d, %d' % (insns[i+1] & 0x0F, lit), 2
    if op == 0x1D:
        return 'move v%d, v%d' % (insns[i+1] & 0x0F, (insns[i+1]>>4)&0x0F), 1
    if op == 0x1F:
        return 'check-cast', 2
    return 'op 0x%02x' % op, 1

if __name__ == '__main__':
    path = sys.argv[1]
    sidxs = [int(x) for x in sys.argv[2:]]
    d = Dex(path)
    print('dex:', path, 'classes=%d methods=%d' % (d.h['class_defs_size'], d.h['method_ids_size']))
    seen = set()
    for sidx in sidxs:
        print('\n===== string #%d = %r =====' % (sidx, d.string(sidx)))
        hits = d.methods_referencing(sidx)
        print('  referencing methods:', len(hits))
        for (cls_idx, k, midx_diff, code_off, insns_size, insns) in hits:
            print('  --- class %s (code_off=0x%x, insns=%d) ---' % (d.type(cls_idx), code_off, insns_size))
            i = 0
            while i < insns_size:
                txt, ncu = fmt_insn(d, insns, i)
                if 'const-string' in txt or 'const-class' in txt or 'invoke' in txt or 'new-instance' in txt:
                    print('     %04d: %s' % (i, txt))
                i += ncu
