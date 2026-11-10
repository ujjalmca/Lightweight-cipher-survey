import random, math, json
from ciphers_new import gift64_enc, prince_enc, led64_enc, rectangle80_enc
random.seed(999)
def pc(x): return bin(x).count('1')
def gift(pt,key): return gift64_enc(pt,key&((1<<128)-1))
def prince(pt,key): return prince_enc(pt,(key>>64)&0xFFFFFFFFFFFFFFFF,key&0xFFFFFFFFFFFFFFFF)
def led(pt,key): return led64_enc(pt,key&0xFFFFFFFFFFFFFFFF)
def rect(pt,key): return rectangle80_enc(pt,key&((1<<80)-1))
CIPHERS={'GIFT-64':(gift,64,128),'PRINCE':(prince,64,128),'LED-64':(led,64,64),'RECTANGLE-80':(rect,64,80)}

# --- NIST-style monobit + entropy on 1e6-bit ctr-mode stream ---
def nist_stream(enc,bits,kbits,nbits=1_000_000):
    key=random.getrandbits(kbits)
    stream=bytearray()
    ctr=0; need=nbits//8
    while len(stream)<need:
        c=enc(ctr & ((1<<bits)-1),key)
        stream+=c.to_bytes(8,'big')
        ctr+=1
    stream=bytes(stream[:need])
    # monobit
    ones=sum(bin(b).count('1') for b in stream)
    n=len(stream)*8
    s=abs(2*ones-n)/math.sqrt(n)
    p_monobit=math.erfc(s/math.sqrt(2))
    # entropy
    from collections import Counter
    cnt=Counter(stream); H=-sum((v/len(stream))*math.log2(v/len(stream)) for v in cnt.values())
    return round(p_monobit,4),round(H,4)

# --- key schedule diffusion (only ciphers with a schedule) ---
# GIFT: 128-bit key schedule; PRINCE: no schedule (k0,k1 fixed) -> expect ~ minimal; 
# LED: no schedule (Even-Mansour, key used directly); RECTANGLE: 80-bit schedule
# We measure: flip one key bit, compare all round-key material.
def gift_roundkeys(key):
    ks=[(key>>(16*i))&0xFFFF for i in range(8)]; out=[]
    for r in range(28):
        out.append((ks[1]<<16)|ks[0])
        k0,k1=ks[0],ks[1]
        k0r=((k0>>2)|(k0<<14))&0xFFFF; k1r=((k1>>12)|(k1<<4))&0xFFFF
        ks=ks[2:]+[k0r,k1r]
    return out
def rect_roundkeys(key):
    from ciphers_new import _rc_ks
    return _rc_ks(key & ((1<<80)-1))
def ks_diffusion(rk_fn,kbits,rk_bits_each,nrk,trials=200):
    tot=0; total_bits=rk_bits_each*nrk
    for _ in range(trials):
        key=random.getrandbits(kbits)
        rk1=rk_fn(key)
        flip=1<<random.randrange(kbits)
        rk2=rk_fn(key^flip)
        d=sum(pc(a^b) for a,b in zip(rk1,rk2))
        tot+=d/total_bits
    return tot/trials*100

results={}
for name,(enc,bits,kbits) in CIPHERS.items():
    p,H=nist_stream(enc,bits,kbits)
    results[name]={'nist_monobit_p':p,'entropy':H}
    print(f"{name:14s} monobit_p={p}  entropy={H}")

# key schedule diffusion
ksd={}
ksd['GIFT-64']=round(ks_diffusion(gift_roundkeys,128,32,28),2)
ksd['RECTANGLE-80']=round(ks_diffusion(rect_roundkeys,80,64,26),2)
# PRINCE and LED have no expanding key schedule; report structural note
print("GIFT-64 ks diffusion:",ksd['GIFT-64'],"%")
print("RECTANGLE-80 ks diffusion:",ksd['RECTANGLE-80'],"%")
for name in results: results[name]['ks_diffusion']=ksd.get(name)
results['PRINCE']['ks_diffusion']=None  # no key schedule (FX construction)
results['LED-64']['ks_diffusion']=None  # Even-Mansour, no schedule
json.dump(results,open('exp_new_stats.json','w'),indent=2)
print("saved")
