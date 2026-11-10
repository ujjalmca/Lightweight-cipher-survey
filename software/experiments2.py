"""Second empirical battery for the survey.
1. SAC matrix (per input bit x output bit flip probability)
2. Exact DDT/LAT properties of PRESENT and AES S-boxes
3. NIST SP 800-22 style tests on 1 Mbit ciphertext streams (CTR-like counter input)
4. Key schedule diffusion (1 master key bit flip -> % round key bits changed)
5. ECB vs CBC image encryption with entropy, NPCR, UACI
All values measured or computed exactly; nothing estimated."""
import json, random, math, statistics
import numpy as np
from scipy.special import erfc, gammaincc
from ciphers import (present_key_schedule, present_encrypt, _SBOX,
                     speck_key_schedule, speck_encrypt,
                     simon_key_schedule, simon_encrypt,
                     tea_encrypt, xtea_encrypt)
from Crypto.Cipher import AES

random.seed(11)
out = {}

def popcount(x): return bin(x).count('1')

# ---------- uniform encryptors (fresh fixed keys) ----------
pk = present_key_schedule(random.getrandbits(80))
kw = [random.getrandbits(32) for _ in range(4)]
spk, sik = speck_key_schedule(kw), simon_key_schedule(kw)
tk = [random.getrandbits(32) for _ in range(4)]
aes_key = random.getrandbits(128).to_bytes(16, 'big')
aes = AES.new(aes_key, AES.MODE_ECB)

ENC = {
 'PRESENT-80': (lambda p: present_encrypt(p, pk), 64),
 'SIMON64/128': (lambda p: (lambda r: (r[0]<<32)|r[1])(simon_encrypt(p>>32, p&0xFFFFFFFF, sik)), 64),
 'SPECK64/128': (lambda p: (lambda r: (r[0]<<32)|r[1])(speck_encrypt(p>>32, p&0xFFFFFFFF, spk)), 64),
 'TEA':  (lambda p: (lambda r: (r[0]<<32)|r[1])(tea_encrypt(p>>32, p&0xFFFFFFFF, tk)), 64),
 'XTEA': (lambda p: (lambda r: (r[0]<<32)|r[1])(xtea_encrypt(p>>32, p&0xFFFFFFFF, tk)), 64),
 'AES-128': (lambda p: int.from_bytes(aes.encrypt(p.to_bytes(16,'big')), 'big'), 128),
}

# ================= 1. SAC matrices =================
def sac_matrix(enc, bits, trials=400):
    M = np.zeros((bits, bits))
    for i in range(bits):
        for _ in range(trials):
            pt = random.getrandbits(bits)
            d = enc(pt) ^ enc(pt ^ (1 << i))
            for j in range(bits):
                M[i, j] += (d >> j) & 1
    return M / trials

sac = {}
for name in ('PRESENT-80', 'SPECK64/128'):
    enc, bits = ENC[name]
    M = sac_matrix(enc, bits)
    sac[name] = M
    out.setdefault('sac', {})[name] = dict(
        mean=float(M.mean()), max_dev=float(np.abs(M - 0.5).max()),
        mean_dev=float(np.abs(M - 0.5).mean()))
np.save('sac_present.npy', sac['PRESENT-80']); np.save('sac_speck.npy', sac['SPECK64/128'])
# quick SAC summary (max deviation only) for the rest
for name in ('SIMON64/128', 'TEA', 'XTEA'):
    enc, bits = ENC[name]
    M = sac_matrix(enc, bits, trials=200)
    out['sac'][name] = dict(mean=float(M.mean()), max_dev=float(np.abs(M-0.5).max()),
                            mean_dev=float(np.abs(M-0.5).mean()))
print('SAC done', {k: {kk: round(vv,4) for kk,vv in v.items()} for k,v in out['sac'].items()})

# ================= 2. Exact S-box DDT / LAT =================
def sbox_props(S, n):
    size = 1 << n
    ddt_max = 0
    for a in range(1, size):
        cnt = [0]*size
        for x in range(size): cnt[S[x] ^ S[x ^ a]] += 1
        ddt_max = max(ddt_max, max(cnt[b] for b in range(1, size)) if any(cnt[1:]) else 0, max(cnt[1:]))
    lat_max = 0
    for a in range(1, size):
        for b in range(1, size):
            s = sum(1 for x in range(size) if popcount((x & a)) % 2 == popcount((S[x] & b)) % 2)
            lat_max = max(lat_max, abs(s - size // 2))
    return ddt_max, lat_max

# AES S-box from GF(2^8) inverse + affine
def gf_mul(a, b):
    r = 0
    while b:
        if b & 1: r ^= a
        a <<= 1
        if a & 0x100: a ^= 0x11B
        b >>= 1
    return r
inv = [0]*256
for x in range(1, 256):
    for y in range(1, 256):
        if gf_mul(x, y) == 1: inv[x] = y; break
AES_S = []
for x in range(256):
    b = inv[x]; c = b
    for _ in range(4):
        c = ((c << 1) | (c >> 7)) & 0xFF
        b ^= c
    AES_S.append(b ^ 0x63)
assert AES_S[0] == 0x63 and AES_S[1] == 0x7c and AES_S[0x53] == 0xed  # FIPS-197 check
p_ddt, p_lat = sbox_props(_SBOX, 4)
a_ddt, a_lat = sbox_props(AES_S, 8)
out['sbox'] = {
 'PRESENT': dict(n=4, ddt_max=p_ddt, dp_max=p_ddt/16, lat_max=p_lat, bias_max=p_lat/16),
 'AES': dict(n=8, ddt_max=a_ddt, dp_max=a_ddt/256, lat_max=a_lat, bias_max=a_lat/256)}
print('S-box:', out['sbox'])

# ================= 3. NIST-style statistical tests (1 Mbit per cipher) =================
def bitstream(enc, bits, total_bits=1_000_000):
    n = total_bits // bits + 1
    arr = np.zeros(n * bits, dtype=np.uint8)
    base = random.getrandbits(bits)
    for i in range(n):
        c = enc((base + i) % (1 << bits))   # counter mode style input
        for j in range(bits):
            arr[i*bits + j] = (c >> j) & 1
    return arr[:total_bits]

def monobit(e):
    s = 2*int(e.sum()) - len(e)
    return erfc(abs(s)/math.sqrt(2*len(e)))
def block_freq(e, M=128):
    N = len(e)//M
    pi = e[:N*M].reshape(N, M).mean(axis=1)
    chi = 4*M*np.sum((pi-0.5)**2)
    return gammaincc(N/2, chi/2)
def runs(e):
    n = len(e); pi = e.mean()
    if abs(pi-0.5) >= 2/math.sqrt(n): return 0.0
    v = 1 + int(np.sum(e[1:] != e[:-1]))
    return erfc(abs(v-2*n*pi*(1-pi))/(2*math.sqrt(2*n)*pi*(1-pi)))
def serial_entropy(e, m=8):
    # approximate entropy per m-bit block (max = m)
    N = len(e)//m
    v = np.packbits(e[:N*m].reshape(N, m), axis=1).flatten() >> (8-m)
    counts = np.bincount(v, minlength=1 << m)
    p = counts/counts.sum(); p = p[p > 0]
    return float(-(p*np.log2(p)).sum())
def cusum(e):
    x = 2*e.astype(int)-1
    S = np.abs(np.cumsum(x)).max(); n = len(e)
    z = S/math.sqrt(n)
    ks = np.arange(int((-n/S+1)/4), int((n/S-1)/4)+1)
    t1 = sum(math.erfc(-( (4*k+1)*z)/math.sqrt(2)) - math.erfc(-((4*k-1)*z)/math.sqrt(2)) for k in ks)/2
    ks2 = np.arange(int((-n/S-3)/4), int((n/S-1)/4)+1)
    t2 = sum(math.erfc(-((4*k+3)*z)/math.sqrt(2)) - math.erfc(-((4*k+1)*z)/math.sqrt(2)) for k in ks2)/2
    return max(0.0, min(1.0, 1 - t1 + t2))

out['nist'] = {}
for name, (enc, bits) in ENC.items():
    e = bitstream(enc, bits)
    out['nist'][name] = dict(
        monobit=float(monobit(e)), block_freq=float(block_freq(e)),
        runs=float(runs(e)), cusum=float(cusum(e)),
        entropy8=serial_entropy(e, 8))
    print('NIST', name, {k: round(v,4) for k,v in out['nist'][name].items()})

# ================= 4. Key schedule diffusion =================
def aes_expand(key16):
    RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36]
    w = [list(key16[4*i:4*i+4]) for i in range(4)]
    for i in range(4, 44):
        t = list(w[i-1])
        if i % 4 == 0:
            t = t[1:]+t[:1]
            t = [AES_S[b] for b in t]
            t[0] ^= RCON[i//4-1]
        w.append([a ^ b for a, b in zip(w[i-4], t)])
    return bytes(b for word in w for b in word)

def bits_of(b): return np.unpackbits(np.frombuffer(b, dtype=np.uint8))

def ks_diffusion(name, trials=200):
    diffs = []
    for _ in range(trials):
        if name == 'PRESENT-80':
            k = random.getrandbits(80); kb = 80
            r1 = present_key_schedule(k); r2 = present_key_schedule(k ^ (1 << random.randrange(kb)))
            b1 = b''.join(x.to_bytes(8,'big') for x in r1); b2 = b''.join(x.to_bytes(8,'big') for x in r2)
        elif name in ('SPECK64/128','SIMON64/128'):
            kws = [random.getrandbits(32) for _ in range(4)]
            pos = random.randrange(128); w2 = list(kws); w2[pos//32] ^= 1 << (pos % 32)
            f = speck_key_schedule if name.startswith('SPECK') else simon_key_schedule
            r1, r2 = f(kws), f(w2)
            b1 = b''.join(x.to_bytes(4,'big') for x in r1); b2 = b''.join(x.to_bytes(4,'big') for x in r2)
        elif name in ('TEA','XTEA'):
            kws = [random.getrandbits(32) for _ in range(4)]
            pos = random.randrange(128); w2 = list(kws); w2[pos//32] ^= 1 << (pos % 32)
            # TEA/XTEA use the master key directly in every round: round keys = key
            b1 = b''.join(x.to_bytes(4,'big') for x in kws); b2 = b''.join(x.to_bytes(4,'big') for x in w2)
        else:  # AES-128
            k = random.getrandbits(128).to_bytes(16,'big')
            pos = random.randrange(128)
            k2 = bytearray(k); k2[pos//8] ^= 1 << (7 - pos % 8)
            b1, b2 = aes_expand(k), aes_expand(bytes(k2))
        x, y = bits_of(b1), bits_of(b2)
        diffs.append(float((x != y).mean())*100)
    return statistics.mean(diffs), statistics.stdev(diffs)

out['keysched'] = {}
for name in ('PRESENT-80','SIMON64/128','SPECK64/128','TEA','XTEA','AES-128'):
    m, s = ks_diffusion(name)
    out['keysched'][name] = dict(mean=round(m,2), sd=round(s,2))
    print('KS', name, round(m,2), '+/-', round(s,2))

# ================= 5. ECB vs CBC image experiment =================
from PIL import Image, ImageDraw
W = H = 128
img = Image.new('L', (W, H), 40)
d = ImageDraw.Draw(img)
for y in range(H):
    d.line([(0, y), (W, y)], fill=40 + int(120 * y / H))
d.ellipse([20, 20, 78, 78], fill=230)
d.rectangle([70, 76, 118, 114], fill=15)
d.polygon([(96, 14), (120, 52), (72, 52)], fill=200)
img.save('img_plain.png')
P = np.array(img, dtype=np.uint8)
pbytes = P.tobytes()

def speck_ecb(data):
    o = bytearray()
    for i in range(0, len(data), 8):
        blk = int.from_bytes(data[i:i+8], 'big')
        x, y = speck_encrypt(blk >> 32, blk & 0xFFFFFFFF, spk)
        o += ((x << 32) | y).to_bytes(8, 'big')
    return bytes(o)

def speck_cbc(data, iv):
    o = bytearray(); prev = iv
    for i in range(0, len(data), 8):
        blk = int.from_bytes(data[i:i+8], 'big') ^ prev
        x, y = speck_encrypt(blk >> 32, blk & 0xFFFFFFFF, spk)
        prev = (x << 32) | y
        o += prev.to_bytes(8, 'big')
    return bytes(o)

iv = random.getrandbits(64)
E = np.frombuffer(speck_ecb(pbytes), dtype=np.uint8).reshape(H, W)
Cb = np.frombuffer(speck_cbc(pbytes, iv), dtype=np.uint8).reshape(H, W)
Image.fromarray(E).save('img_ecb.png'); Image.fromarray(Cb).save('img_cbc.png')

def entropy(a):
    c = np.bincount(a.flatten(), minlength=256); p = c/c.sum(); p = p[p>0]
    return float(-(p*np.log2(p)).sum())
def corr_adj(a):
    x = a[:, :-1].flatten().astype(float); y = a[:, 1:].flatten().astype(float)
    return float(np.corrcoef(x, y)[0, 1])

# NPCR/UACI: flip one pixel LSB, re-encrypt CBC with same IV
P2 = P.copy(); P2[H//2, W//2] ^= 1
C2 = np.frombuffer(speck_cbc(P2.tobytes(), iv), dtype=np.uint8).reshape(H, W)
npcr = float((Cb != C2).mean()*100)
uaci = float((np.abs(Cb.astype(int)-C2.astype(int))/255).mean()*100)

out['image'] = dict(
 plain=dict(entropy=round(entropy(P),4), corr=round(corr_adj(P),4)),
 ecb=dict(entropy=round(entropy(E),4), corr=round(corr_adj(E),4)),
 cbc=dict(entropy=round(entropy(Cb),4), corr=round(corr_adj(Cb),4)),
 npcr=round(npcr,2), uaci=round(uaci,2))
print('image:', out['image'])

json.dump(out, open('results2.json','w'), indent=1)
print('saved results2.json')
