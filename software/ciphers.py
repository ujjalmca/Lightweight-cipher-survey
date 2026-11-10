"""Lightweight block cipher implementations for empirical benchmarking.
PRESENT-80, SPECK64/128, SIMON64/128, XTEA, TEA, AES-128 (pycryptodome).
Each implementation is verified against published test vectors."""
import struct

MASK64 = 0xFFFFFFFFFFFFFFFF
MASK32 = 0xFFFFFFFF

# ---------------- PRESENT-80 (Bogdanov et al., CHES 2007) ----------------
_SBOX = [0xC,5,6,0xB,9,0,0xA,0xD,3,0xE,0xF,8,4,7,1,2]
_PBOX = [(16*i) % 63 if i != 63 else 63 for i in range(64)]

def present_key_schedule(key80):
    ks = []
    k = key80
    for r in range(1, 33):
        ks.append((k >> 16) & MASK64)
        k = ((k & (2**19 - 1)) << 61) | (k >> 19)          # rotate left 61 over 80 bits
        k = (_SBOX[k >> 76] << 76) | (k & (2**76 - 1))     # S-box on top nibble
        k ^= r << 15                                        # round counter
    return ks

def present_encrypt(block, round_keys):
    state = block
    for r in range(31):
        state ^= round_keys[r]
        # sBoxLayer
        out = 0
        for i in range(16):
            out |= _SBOX[(state >> (4*i)) & 0xF] << (4*i)
        # pLayer
        state = 0
        for i in range(64):
            state |= ((out >> i) & 1) << _PBOX[i]
        # (63 maps to 63 via formula above)
    return state ^ round_keys[31]

# ---------------- SPECK64/128 (NSA, 2013) ----------------
def _ror32(x, r): return ((x >> r) | (x << (32 - r))) & MASK32
def _rol32(x, r): return ((x << r) | (x >> (32 - r))) & MASK32

def speck_key_schedule(key_words):  # key_words = [K3,K2,K1,K0] MSW first
    l = key_words[:3][::-1]  # l[0]=K1... per spec
    k = [key_words[3]]
    for i in range(26):
        l.append((k[i] + _ror32(l[i], 8)) & MASK32 ^ i)
        k.append(_rol32(k[i], 3) ^ l[i + 3])
    return k

def speck_encrypt(x, y, ks):
    for k in ks:
        x = ((_ror32(x, 8) + y) & MASK32) ^ k
        y = _rol32(y, 3) ^ x
    return x, y

# ---------------- SIMON64/128 (NSA, 2013) ----------------
_SIMON_Z3 = 0b11110000101100111001010001001000000111101001100011010111011011
def simon_key_schedule(key_words):  # [K3,K2,K1,K0] MSW first
    k = key_words[::-1]
    for i in range(4, 44):
        tmp = _ror32(k[i-1], 3) ^ k[i-3]
        tmp ^= _ror32(tmp, 1)
        k.append((~k[i-4] & MASK32) ^ tmp ^ ((_SIMON_Z3 >> ((i-4) % 62)) & 1) ^ 3)
    return k

def simon_encrypt(x, y, ks):
    for k in ks:
        x, y = y ^ (_rol32(x, 1) & _rol32(x, 8)) ^ _rol32(x, 2) ^ k, x
    return x, y

# ---------------- TEA / XTEA (Wheeler & Needham) ----------------
def tea_encrypt(v0, v1, key4, rounds=32):
    delta, s = 0x9E3779B9, 0
    k0, k1, k2, k3 = key4
    for _ in range(rounds):
        s = (s + delta) & MASK32
        v0 = (v0 + ((((v1 << 4) & MASK32) + k0) ^ (v1 + s) ^ ((v1 >> 5) + k1))) & MASK32
        v1 = (v1 + ((((v0 << 4) & MASK32) + k2) ^ (v0 + s) ^ ((v0 >> 5) + k3))) & MASK32
    return v0, v1

def xtea_encrypt(v0, v1, key4, rounds=32):
    delta, s = 0x9E3779B9, 0
    for _ in range(rounds):
        v0 = (v0 + (((((v1 << 4) & MASK32) ^ (v1 >> 5)) + v1) ^ (s + key4[s & 3]))) & MASK32
        s = (s + delta) & MASK32
        v1 = (v1 + (((((v0 << 4) & MASK32) ^ (v0 >> 5)) + v0) ^ (s + key4[(s >> 11) & 3]))) & MASK32
    return v0, v1

# ---------------- Verification against published test vectors ----------------
def verify_all():
    results = {}
    # PRESENT-80: all-zero key/plaintext -> 5579C1387B228445
    ks = present_key_schedule(0)
    results['PRESENT-80'] = present_encrypt(0, ks) == 0x5579C1387B228445
    # SPECK64/128: key 1b1a1918 13121110 0b0a0908 03020100, pt 3b726574 7475432d -> 8c6fa548 454e028b
    ks = speck_key_schedule([0x1b1a1918, 0x13121110, 0x0b0a0908, 0x03020100])
    results['SPECK64/128'] = speck_encrypt(0x3b726574, 0x7475432d, ks) == (0x8c6fa548, 0x454e028b)
    # SIMON64/128: same key, pt 656b696c 20646e75 -> 44c8fc20 b9dfa07a
    ks = simon_key_schedule([0x1b1a1918, 0x13121110, 0x0b0a0908, 0x03020100])
    results['SIMON64/128'] = simon_encrypt(0x656b696c, 0x20646e75, ks) == (0x44c8fc20, 0xb9dfa07a)
    # XTEA: key 000102...0f, pt 4142434445464748 -> 497df3d072612cb5
    results['XTEA'] = xtea_encrypt(0x41424344, 0x45464748,
        [0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f]) == (0x497df3d0, 0x72612cb5)
    # TEA: known vector key=0, pt=0 -> 41ea3a0a 94baa940
    results['TEA'] = tea_encrypt(0, 0, [0, 0, 0, 0]) == (0x41ea3a0a, 0x94baa940)
    # AES-128 FIPS-197
    from Crypto.Cipher import AES
    c = AES.new(bytes.fromhex('000102030405060708090a0b0c0d0e0f'), AES.MODE_ECB)
    results['AES-128'] = c.encrypt(bytes.fromhex('00112233445566778899aabbccddeeff')).hex() == '69c4e0d86a7b0430d8cdb78070b4c55a'
    return results

if __name__ == '__main__':
    for name, ok in verify_all().items():
        print(f"{name}: {'PASS' if ok else 'FAIL'}")
