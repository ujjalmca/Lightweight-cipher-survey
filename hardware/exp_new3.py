import random, math, json
random.seed(4242)
def pc(x): return bin(x).count('1')

# Round-reduced variants: reimplement with a rounds parameter
from ciphers_new import _GIFT_S,_GIFT_P,_GIFT_RC
def gift_r(pt,key,R):
    b=[(pt>>i)&1 for i in range(64)]; ks=[(key>>(16*i))&0xFFFF for i in range(8)]
    for r in range(R):
        for n in range(16):
            nib=b[4*n]|(b[4*n+1]<<1)|(b[4*n+2]<<2)|(b[4*n+3]<<3); sv=_GIFT_S[nib]
            b[4*n],b[4*n+1],b[4*n+2],b[4*n+3]=sv&1,(sv>>1)&1,(sv>>2)&1,(sv>>3)&1
        nb=[0]*64
        for i in range(64): nb[_GIFT_P[i]]=b[i]
        b=nb
        u,v=ks[1],ks[0]
        for i in range(16): b[4*i+1]^=(u>>i)&1; b[4*i]^=(v>>i)&1
        rc=_GIFT_RC[r]
        for j in range(6): b[4*j+3]^=(rc>>j)&1
        b[63]^=1
        k0,k1=ks[0],ks[1]; ks=ks[2:]+[((k0>>2)|(k0<<14))&0xFFFF,((k1>>12)|(k1<<4))&0xFFFF]
    ct=0
    for i in range(64): ct|=b[i]<<i
    return ct

from ciphers_new import _RC_S,_RC_RC,_rc_rol,_rc_sub,_rc_ks
def rect_r(pt,key,R):
    sk=_rc_ks(key&((1<<80)-1))
    rows=[(pt>>(16*i))&0xFFFF for i in range(4)]
    for i in range(min(R,25)):
        kr=[(sk[i]>>(16*r))&0xFFFF for r in range(4)]
        rows=[rows[r]^kr[r] for r in range(4)]
        rows=_rc_sub(rows)
        rows=[rows[0],_rc_rol(rows[1],1),_rc_rol(rows[2],12),_rc_rol(rows[3],13)]
    return rows[0]|(rows[1]<<16)|(rows[2]<<32)|(rows[3]<<48)

def aval_at_round(encR,bits,kbits,R,trials=800):
    tot=0
    for _ in range(trials):
        pt=random.getrandbits(bits); key=random.getrandbits(kbits)
        c1=encR(pt,key,R); c2=encR(pt^(1<<random.randrange(bits)),key,R)
        tot+=pc(c1^c2)
    return tot/(trials*bits)*100

curves={}
curves['GIFT-64']=[round(aval_at_round(gift_r,64,128,R),2) for R in range(1,13)]
curves['RECTANGLE-80']=[round(aval_at_round(rect_r,64,80,R),2) for R in range(1,13)]
print("GIFT-64 rounds 1-12:",curves['GIFT-64'])
print("RECTANGLE-80 rounds 1-12:",curves['RECTANGLE-80'])
json.dump(curves,open('exp_new_rounds.json','w'),indent=2)

# differential decay: max output-diff prob for single-bit input diff, per round
def diff_strength(encR,bits,kbits,R,pairs=40000):
    from collections import Counter
    key=random.getrandbits(kbits); din=1<<random.randrange(bits)
    cnt=Counter()
    for _ in range(pairs):
        pt=random.getrandbits(bits)
        d=encR(pt,key,R)^encR(pt^din,key,R)
        cnt[d]+=1
    maxp=max(cnt.values())/pairs
    return -math.log2(maxp) if maxp>0 else 64.0
dd={}
dd['GIFT-64']=[round(diff_strength(gift_r,64,128,R),2) for R in range(1,6)]
dd['RECTANGLE-80']=[round(diff_strength(rect_r,64,80,R),2) for R in range(1,6)]
print("GIFT-64 diff-strength 1-5:",dd['GIFT-64'])
print("RECTANGLE-80 diff-strength 1-5:",dd['RECTANGLE-80'])
json.dump(dd,open('exp_new_diffdecay.json','w'),indent=2)
print("saved")
