# 语义级对比两个 dex 的 encoded_array —— 正确处理所有编码类型
import struct, sys

def uleb(b,p):
    r=0;s=0
    while True:
        x=b[p];p+=1
        r|=(x&0x7f)<<s
        if not(x&0x80):return r,p
        s+=7

class D:
    def __init__(self, path):
        b=open(path,'rb').read(); self.b=b
        f=struct.unpack_from('<20I',b,32)
        (self.file_size,self.hs,self.et,self.ls,self.lo,self.map_off,
         self.sids_size,self.sids_off,self.tids_size,self.tids_off,
         self.pids_size,self.pids_off,self.fids_size,self.fids_off,
         self.mids_size,self.mids_off,self.cds_size,self.cds_off,self.ds,self.do_)=f
        self.strs=[]
        for i in range(self.sids_size):
            (so,)=struct.unpack_from('<I',b,self.sids_off+i*4)
            _,p=uleb(b,so)
            e=b.index(b'\x00',p)
            self.strs.append(b[p:e].decode('utf-8','replace'))
        self.fields={}
        for i in range(self.fids_size):
            c,t,n=struct.unpack_from('<HHI',b,self.fids_off+i*8)
            self.fields[i]=(self.strs[c],self.strs[n])
    def type_desc(self,idx):
        (si,)=struct.unpack_from('<I',self.b,self.tids_off+idx*4)
        return self.strs[si]
    def class_static_offs(self):
        out={}
        for i in range(self.cds_size):
            f=struct.unpack_from('<8I',self.b,self.cds_off+i*32)
            out[self.type_desc(f[0])]=f[7]
        return out
    def _value(self,p):
        b=self.b
        head=b[p];p+=1
        vt=head&0x1f; varg=head>>5
        if vt==0x1f: return p,('null',None)
        if vt==0x20: return p,('bool',bool(varg))
        nb=varg+1
        raw=b[p:p+nb]; p+=nb
        u=int.from_bytes(raw,'little')
        if vt==0x18:  return p,('str', self.strs[u] if u<len(self.strs) else f'#{u}')
        if vt==0x19:  return p,('type', self.type_desc(u))
        if vt in (0x17,0x1c):
            c,n=self.fields.get(u,('?','?'))
            return p,('field', f'{c}.{n}')
        if vt in (0x00,0x02,0x03,0x04,0x06):  # 整数类: 符号扩展归一化
            bits=nb*8
            s=u-(1<<bits) if u>=(1<<(bits-1)) else u
            return p,('int', s)
        if vt==0x10:
            import struct as _s
            fl=_s.unpack('<f', (u<<(32-nb*8)).to_bytes(4,'little'))[0]
            return p,('float', round(fl,6))
        if vt==0x11:
            import struct as _s
            fl=_s.unpack('<d', (u<<(64-nb*8)).to_bytes(8,'little'))[0]
            return p,('double', round(fl,9))
        if vt==0x1d:  # ARRAY: size = value_arg+1, 直接跟 values
            n = varg+1
            items=[]
            for _ in range(n):
                p,v=self._value(p)
                items.append(v)
            return p,('array', items)
        if vt==0x1e:  # ANNOTATION: type_idx + size + values
            ti,q=uleb(b,p)
            n,q=uleb(b,q)
            items=[]
            for _ in range(n):
                ni,q=uleb(b,q)
                q,v=self._value(q)
                items.append((self.strs[ni], v))
            return q,('anno', (self.type_desc(ti), tuple(items)))
        return p,(f'?{vt:#x}', u)
    def parse_encoded_array(self, off):
        b=self.b
        n,p=uleb(b,off)
        vals=[]
        for _ in range(n):
            p,v=self._value(p)
            vals.append(v)
        return vals

a=D(sys.argv[1]); c=D(sys.argv[2])
oa=a.class_static_offs(); oc=c.class_static_offs()
diff=0; same=0; only_a=only_c=0
for cls in sorted(set(oa)|set(oc)):
    va_, vc_ = oa.get(cls,0), oc.get(cls,0)
    if va_==0 and vc_==0: continue
    if va_==0: only_c+=1; print(f"仅C有static_values: {cls}"); continue
    if vc_==0: only_a+=1; print(f"仅A有static_values: {cls}"); continue
    va=a.parse_encoded_array(va_); vc=c.parse_encoded_array(vc_)
    if va==vc: same+=1
    else:
        diff+=1
        print(f"== {cls}: {len(va)} vs {len(vc)} 项")
        for i,(x,y) in enumerate(zip(va,vc)):
            if x!=y: print(f"   [{i}] {x}  ->  {y}")
        if len(va)!=len(vc):
            extra = va[len(vc):] if len(va)>len(vc) else vc[len(va):]
            print(f"   项数不同, 多出: {str(extra)[:200]}")
print(f"\nstatic_values 语义对比: 一致={same} 有值差异={diff} 仅A={only_a} 仅C={only_c}")
