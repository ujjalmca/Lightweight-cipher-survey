import random, math, json
from ciphers_new import gift64_enc, prince_enc, led64_enc, rectangle80_enc

random.seed(12345)

# uniform enc interface: enc(pt64, key) -> ct64
def gift(pt,key):
    return gift64_enc(pt,key & ((1<<128)-1))
def prince(pt,key):
    k0=(key>>64)&0xFFFFFFFFFFFFFFFF; k1=key&0xFFFFFFFFFFFFFFFF
    return prince_enc(pt,k0,k1)
def led(pt,key):
    return led64_enc(pt,key&0xFFFFFFFFFFFFFFFF)
def rect(pt,key):
    return rectangle80_enc(pt,key & ((1<<80)-1))

CIPHERS={
 'GIFT-64':(gift,64,128),
 'PRINCE':(prince,64,128),
 'LED-64':(led,64,64),
 'RECTANGLE-80':(rect,64,80),
}

def popcount(x): return bin(x).count('1')

def avalanche(enc,bits,kbits,trials=5000):
    tot=0
    for _ in range(trials):
        pt=random.getrandbits(bits); key=random.getrandbits(kbits)
        c1=enc(pt,key)
        flip=1<<random.randrange(bits)
        c2=enc(pt^flip,key)
        tot+=popcount(c1^c2)
    return tot/(trials*bits)*100

def key_avalanche(enc,bits,kbits,trials=2000):
    tot=0
    for _ in range(trials):
        pt=random.getrandbits(bits); key=random.getrandbits(kbits)
        c1=enc(pt,key)
        flip=1<<random.randrange(kbits)
        c2=enc(pt,key^flip)
        tot+=popcount(c1^c2)
    return tot/(trials*bits)*100

def bit_balance(enc,bits,kbits,trials=5000):
    ones=0
    for _ in range(trials):
        pt=random.getrandbits(bits); key=random.getrandbits(kbits)
        ones+=popcount(enc(pt,key))
    return ones/(trials*bits)*100

results={}
for name,(enc,bits,kbits) in CIPHERS.items():
    a=avalanche(enc,bits,kbits)
    ka=key_avalanche(enc,bits,kbits)
    bb=bit_balance(enc,bits,kbits)
    results[name]={'plaintext_avalanche':round(a,2),'key_avalanche':round(ka,2),'bit_balance':round(bb,2)}
    print(f"{name:14s} pt_aval={a:.2f}%  key_aval={ka:.2f}%  bit_bal={bb:.2f}%")

json.dump(results,open('exp_new_avalanche.json','w'),indent=2)
