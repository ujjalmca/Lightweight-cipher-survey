"""Five additional lightweight ciphers, each verified against published test vectors.
GIFT-64, PRINCE, LED-64, RECTANGLE-80 (block ciphers); ASCON-AEAD128 via ascon_official.py.
"""
# ---------------- GIFT-64 ----------------
_GIFT_S=[1,10,4,12,6,15,3,9,2,13,11,7,5,0,8,14]
_GIFT_P=[0,17,34,51,48,1,18,35,32,49,2,19,16,33,50,3,4,21,38,55,52,5,22,39,36,53,6,23,20,37,54,7,
 8,25,42,59,56,9,26,43,40,57,10,27,24,41,58,11,12,29,46,63,60,13,30,47,44,61,14,31,28,45,62,15]
_GIFT_RC=[0x01,0x03,0x07,0x0F,0x1F,0x3E,0x3D,0x3B,0x37,0x2F,0x1E,0x3C,0x39,0x33,0x27,0x0E,0x1D,0x3A,
 0x35,0x2B,0x16,0x2C,0x18,0x30,0x21,0x02,0x05,0x0B]
def gift64_enc(pt,key):
    b=[(pt>>i)&1 for i in range(64)]
    ks=[(key>>(16*i))&0xFFFF for i in range(8)]
    for r in range(28):
        for n in range(16):
            nib=b[4*n]|(b[4*n+1]<<1)|(b[4*n+2]<<2)|(b[4*n+3]<<3)
            sv=_GIFT_S[nib]
            b[4*n],b[4*n+1],b[4*n+2],b[4*n+3]=sv&1,(sv>>1)&1,(sv>>2)&1,(sv>>3)&1
        nb=[0]*64
        for i in range(64): nb[_GIFT_P[i]]=b[i]
        b=nb
        u,v=ks[1],ks[0]
        for i in range(16):
            b[4*i+1]^=(u>>i)&1; b[4*i]^=(v>>i)&1
        rc=_GIFT_RC[r]
        for j in range(6): b[4*j+3]^=(rc>>j)&1
        b[63]^=1
        k0,k1=ks[0],ks[1]
        k0r=((k0>>2)|(k0<<14))&0xFFFF; k1r=((k1>>12)|(k1<<4))&0xFFFF
        ks=ks[2:]+[k0r,k1r]
    ct=0
    for i in range(64): ct|=b[i]<<i
    return ct

# ---------------- PRINCE ----------------
_PR_S=[0xb,0xf,0x3,0x2,0xa,0xc,0x9,0x1,0x6,0x7,0x8,0x0,0xe,0x5,0xd,0x4]
_PR_SI=[0xb,0x7,0x3,0x2,0xf,0xd,0x8,0x9,0xa,0x6,0x4,0x0,0x5,0xe,0xc,0x1]
_PR_SR=[0x4,0x9,0xe,0x3,0x8,0xd,0x2,0x7,0xc,0x1,0x6,0xb,0x0,0x5,0xa,0xf]
_PR_SRI=[0xc,0x9,0x6,0x3,0x0,0xd,0xa,0x7,0x4,0x1,0xe,0xb,0x8,0x5,0x2,0xf]
_PR_RC=[0x0000000000000000,0x13198a2e03707344,0xa4093822299f31d0,0x082efa98ec4e6c89,
 0x452821e638d01377,0xbe5466cf34e90c6c,0x7ef84f78fd955cb1,0x85840851f1ac43aa,
 0xc882d32f25323c54,0x64a51195e0e3610d,0xd3b5a399ca0c2399,0xc0ac29b7c97c50dd]
_PR_SRC=[0x7bde,0xbde7,0xde7b,0xe7bd]
def _pr_sbox(d,c):
    r=0
    for i in range(16): r|=c[(d>>(4*i))&0xf]<<(4*i)
    return r
def _pr_red16(x): return (x&0xf)^((x>>4)&0xf)^((x>>8)&0xf)^((x>>12)&0xf)
def _pr_mult(d):
    ret=0
    for blk in range(4):
        hw=(d>>(16*blk))&0xffff; start=0 if blk in(0,3) else 1
        for ni in range(4):
            ret|=_pr_red16(hw&_PR_SRC[(start+3-ni)%4])<<(16*blk+4*ni)
    return ret
def _pr_sr(d,inv):
    sh=_PR_SRI if inv else _PR_SR; r=0
    for ni in range(16): r|=((d>>(4*sh[ni]))&0xf)<<(4*ni)
    return r
def prince_enc(pt,k0,k1):
    k0p=(((k0&1)<<63)|(k0>>1))^(k0>>63)
    d=pt^k0^k1^_PR_RC[0]
    for i in range(1,6): d=_pr_sbox(d,_PR_S); d=_pr_mult(d); d=_pr_sr(d,False); d^=_PR_RC[i]^k1
    d=_pr_sbox(d,_PR_S); d=_pr_mult(d); d=_pr_sbox(d,_PR_SI)
    for i in range(6,11): d^=_PR_RC[i]^k1; d=_pr_sr(d,True); d=_pr_mult(d); d=_pr_sbox(d,_PR_SI)
    d^=_PR_RC[11]^k1^k0p
    return d&0xFFFFFFFFFFFFFFFF

# ---------------- LED-64 ----------------
_LED_S=[0xC,0x5,0x6,0xB,0x9,0x0,0xA,0xD,0x3,0xE,0xF,0x8,0x4,0x7,0x1,0x2]
_LED_M=[[4,1,2,2],[8,6,5,6],[0xB,0xE,0xA,9],[2,2,0xF,0xB]]
def _led_gmul(a,b):
    p=0
    for _ in range(4):
        if b&1: p^=a
        hi=a&0x8; a=(a<<1)&0xF
        if hi: a^=0x3
        b>>=1
    return p
def _led_rc():
    rc=0; seq=[]
    for _ in range(48):
        newbit=((rc>>5)&1)^((rc>>4)&1)^1
        rc=((rc<<1)|newbit)&0x3F; seq.append(rc)
    return seq
_LED_RCs=_led_rc()
def _led_ts(x):
    s=[[0]*4 for _ in range(4)]
    for i in range(16): s[i//4][i%4]=(x>>(4*(15-i)))&0xF
    return s
def _led_fs(s):
    x=0
    for i in range(16): x=(x<<4)|s[i//4][i%4]
    return x
def led64_enc(pt,key):
    s=_led_ts(pt); ks_hi,ks_lo=0x4,0x0; rc=0
    for step in range(8):
        k=_led_ts(key)
        s=[[s[i][j]^k[i][j] for j in range(4)] for i in range(4)]
        for _ in range(4):
            r=_LED_RCs[rc]; rc+=1; rh=(r>>3)&0x7; rl=r&0x7
            add=[[0^ks_hi,rh,0,0],[1^ks_hi,rl,0,0],[2^ks_lo,rh,0,0],[3^ks_lo,rl,0,0]]
            s=[[s[i][j]^add[i][j] for j in range(4)] for i in range(4)]
            s=[[_LED_S[v] for v in row] for row in s]
            s=[s[i][i:]+s[i][:i] for i in range(4)]
            ns=[[0]*4 for _ in range(4)]
            for j in range(4):
                for i in range(4):
                    v=0
                    for kk in range(4): v^=_led_gmul(_LED_M[i][kk],s[kk][j])
                    ns[i][j]=v
            s=ns
    k=_led_ts(key)
    s=[[s[i][j]^k[i][j] for j in range(4)] for i in range(4)]
    return _led_fs(s)

# ---------------- RECTANGLE-80 ----------------
_RC_S=[0x6,0x5,0xC,0xA,0x1,0xE,0x7,0x9,0xB,0x0,0x3,0xD,0x8,0xF,0x4,0x2]
_RC_RC=[0x01,0x02,0x04,0x09,0x12,0x05,0x0B,0x16,0x0C,0x19,0x13,0x07,0x0F,0x1F,0x1E,0x1C,0x18,0x11,
 0x03,0x06,0x0D,0x1B,0x17,0x0E,0x1D]
def _rc_rol(x,n): return ((x<<n)|(x>>(16-n)))&0xFFFF
def _rc_sub(rows):
    A0,A1,A2,A3=rows
    T1=(~A1)&0xFFFF; T2=A0&T1; T3=A2^A3; B0=T2^T3; T5=A3|T1; T6=A0^T5; B1=A2^T6
    T8=A1^A2; T9=T3&T6; B3=T8^T9; T11=B0|T8; B2=T6^T11
    return [B0&0xFFFF,B1&0xFFFF,B2&0xFFFF,B3&0xFFFF]
def _rc_ks(key):
    rows=[(key>>(16*i))&0xFFFF for i in range(5)]; sk=[]
    for i in range(25):
        sk.append(rows[0]|(rows[1]<<16)|(rows[2]<<32)|(rows[3]<<48))
        nr=rows[:]
        for j in range(4):
            col=((rows[0]>>j)&1)|(((rows[1]>>j)&1)<<1)|(((rows[2]>>j)&1)<<2)|(((rows[3]>>j)&1)<<3)
            s=_RC_S[col]
            for r in range(4): nr[r]=(nr[r]&~(1<<j))|(((s>>r)&1)<<j)
        r0=_rc_rol(nr[0],8)^nr[1]; r3=_rc_rol(nr[3],12)^nr[4]
        rows=[r0&0xFFFF,nr[2],nr[3],r3&0xFFFF,nr[0]]
        rows[0]^=_RC_RC[i]
    sk.append(rows[0]|(rows[1]<<16)|(rows[2]<<32)|(rows[3]<<48))
    return sk
def rectangle80_enc(pt,key):
    sk=_rc_ks(key)
    rows=[(pt>>(16*i))&0xFFFF for i in range(4)]
    for i in range(25):
        kr=[(sk[i]>>(16*r))&0xFFFF for r in range(4)]
        rows=[rows[r]^kr[r] for r in range(4)]
        rows=_rc_sub(rows)
        rows=[rows[0],_rc_rol(rows[1],1),_rc_rol(rows[2],12),_rc_rol(rows[3],13)]
    kr=[(sk[25]>>(16*r))&0xFFFF for r in range(4)]
    rows=[rows[r]^kr[r] for r in range(4)]
    x=0
    for i in range(4): x|=rows[i]<<(16*i)
    return x

if __name__=="__main__":
    t=[("GIFT-64",gift64_enc(0,0)==0xf62bc3ef34f775ac),
       ("PRINCE",prince_enc(0,0,0)==0x818665aa0d02dfda),
       ("LED-64",led64_enc(0,0)==0x39c2401003a0c798),
       ("RECTANGLE-80",rectangle80_enc(0,0)==0x0874e8b1e3542d96)]
    for n,ok in t: print(f"{n}: {'OK' if ok else 'FAIL'}")
