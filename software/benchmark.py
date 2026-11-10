"""Empirical benchmark of lightweight block ciphers (pure software, single thread).
Metrics: encryption time/block, throughput, plaintext avalanche, key avalanche,
ciphertext bit balance. All values measured, none estimated."""
import time, random, json, platform, statistics
from ciphers import (present_key_schedule, present_encrypt,
                     speck_key_schedule, speck_encrypt,
                     simon_key_schedule, simon_encrypt,
                     tea_encrypt, xtea_encrypt, verify_all)
from Crypto.Cipher import AES

random.seed(2026)
N_TIME = 20000      # blocks for timing
N_AVAL = 5000       # trials for avalanche
REPS = 5            # timing repetitions (median taken)

def popcount(x): return bin(x).count('1')

# --- uniform wrappers: encrypt(pt_int) -> ct_int, with fixed random key ---
def make_ciphers():
    key80 = random.getrandbits(80)
    pk = present_key_schedule(key80)
    sk = [random.getrandbits(32) for _ in range(4)]
    spk = speck_key_schedule(sk)
    sik = simon_key_schedule(sk)
    tk = [random.getrandbits(32) for _ in range(4)]
    aes_key = random.getrandbits(128).to_bytes(16, 'big')
    aes = AES.new(aes_key, AES.MODE_ECB)

    def enc_present(pt): return present_encrypt(pt, pk)
    def enc_speck(pt):
        x, y = speck_encrypt(pt >> 32, pt & 0xFFFFFFFF, spk); return (x << 32) | y
    def enc_simon(pt):
        x, y = simon_encrypt(pt >> 32, pt & 0xFFFFFFFF, sik); return (x << 32) | y
    def enc_tea(pt):
        x, y = tea_encrypt(pt >> 32, pt & 0xFFFFFFFF, tk); return (x << 32) | y
    def enc_xtea(pt):
        x, y = xtea_encrypt(pt >> 32, pt & 0xFFFFFFFF, tk); return (x << 32) | y
    def enc_aes(pt):
        return int.from_bytes(aes.encrypt(pt.to_bytes(16, 'big')), 'big')

    # rekey functions: given int key material, return fresh encryptor (for key avalanche)
    def rk_present(k): 
        ks = present_key_schedule(k & (2**80 - 1))
        return lambda pt: present_encrypt(pt, ks)
    def rk_speck(k):
        kw = [(k >> (32*i)) & 0xFFFFFFFF for i in (3,2,1,0)]
        ks = speck_key_schedule(kw)
        return lambda pt: (lambda r: (r[0] << 32) | r[1])(speck_encrypt(pt >> 32, pt & 0xFFFFFFFF, ks))
    def rk_simon(k):
        kw = [(k >> (32*i)) & 0xFFFFFFFF for i in (3,2,1,0)]
        ks = simon_key_schedule(kw)
        return lambda pt: (lambda r: (r[0] << 32) | r[1])(simon_encrypt(pt >> 32, pt & 0xFFFFFFFF, ks))
    def rk_tea(k):
        kw = [(k >> (32*i)) & 0xFFFFFFFF for i in (3,2,1,0)]
        return lambda pt: (lambda r: (r[0] << 32) | r[1])(tea_encrypt(pt >> 32, pt & 0xFFFFFFFF, kw))
    def rk_xtea(k):
        kw = [(k >> (32*i)) & 0xFFFFFFFF for i in (3,2,1,0)]
        return lambda pt: (lambda r: (r[0] << 32) | r[1])(xtea_encrypt(pt >> 32, pt & 0xFFFFFFFF, kw))
    def rk_aes(k):
        c = AES.new((k & (2**128 - 1)).to_bytes(16, 'big'), AES.MODE_ECB)
        return lambda pt: int.from_bytes(c.encrypt(pt.to_bytes(16, 'big')), 'big')

    return {
        'PRESENT-80':  dict(enc=enc_present, block=64, keybits=80,  rekey=rk_present, structure='SPN'),
        'SIMON64/128': dict(enc=enc_simon,   block=64, keybits=128, rekey=rk_simon,  structure='Feistel'),
        'SPECK64/128': dict(enc=enc_speck,   block=64, keybits=128, rekey=rk_speck,  structure='ARX (Feistel-like)'),
        'TEA':         dict(enc=enc_tea,     block=64, keybits=128, rekey=rk_tea,    structure='Feistel (ARX)'),
        'XTEA':        dict(enc=enc_xtea,    block=64, keybits=128, rekey=rk_xtea,   structure='Feistel (ARX)'),
        'AES-128':     dict(enc=enc_aes,     block=128, keybits=128, rekey=rk_aes,   structure='SPN'),
    }

def bench():
    ciphers = make_ciphers()
    results = {}
    for name, c in ciphers.items():
        enc, bits = c['enc'], c['block']
        pts = [random.getrandbits(bits) for _ in range(N_TIME)]
        # timing (median of REPS runs)
        times = []
        for _ in range(REPS):
            t0 = time.perf_counter()
            for pt in pts:
                enc(pt)
            times.append(time.perf_counter() - t0)
        t = statistics.median(times)
        us_per_block = t / N_TIME * 1e6
        kbps = (N_TIME * bits / 1000) / t

        # plaintext avalanche
        flips = []
        for _ in range(N_AVAL):
            pt = random.getrandbits(bits)
            bitpos = random.randrange(bits)
            d = enc(pt) ^ enc(pt ^ (1 << bitpos))
            flips.append(popcount(d) / bits * 100)
        aval_pt = statistics.mean(flips)
        aval_pt_sd = statistics.stdev(flips)

        # key avalanche
        kbits = c['keybits']
        kflips = []
        for _ in range(N_AVAL // 10):   # rekeying is costly
            k = random.getrandbits(kbits)
            pt = random.getrandbits(bits)
            e1 = c['rekey'](k)
            e2 = c['rekey'](k ^ (1 << random.randrange(kbits)))
            kflips.append(popcount(e1(pt) ^ e2(pt)) / bits * 100)
        aval_key = statistics.mean(kflips)
        aval_key_sd = statistics.stdev(kflips)

        # ciphertext bit balance (fraction of 1s over 5000 ciphertexts)
        ones = sum(popcount(enc(random.getrandbits(bits))) for _ in range(5000))
        balance = ones / (5000 * bits) * 100

        results[name] = dict(structure=c['structure'], block=bits, keybits=c['keybits'],
                             us_per_block=round(us_per_block, 2), kbps=round(kbps, 1),
                             aval_pt=round(aval_pt, 2), aval_pt_sd=round(aval_pt_sd, 2),
                             aval_key=round(aval_key, 2), aval_key_sd=round(aval_key_sd, 2),
                             balance=round(balance, 2))
        print(name, results[name])
    return results

if __name__ == '__main__':
    assert all(verify_all().values()), "test vector failure"
    print("All test vectors PASS\n")
    res = bench()
    meta = dict(platform=platform.platform(), python=platform.python_version(),
                n_timing=N_TIME, n_avalanche=N_AVAL, reps=REPS)
    json.dump(dict(meta=meta, results=res), open('bench_results.json', 'w'), indent=1)
    print("\nsaved bench_results.json")
