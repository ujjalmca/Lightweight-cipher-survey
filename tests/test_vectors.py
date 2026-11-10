"""Known-answer tests for every cipher implementation in this repository.

Run from the repository root:  python3 tests/test_vectors.py
Exit status is 0 only if every check passes.
"""
import os, sys, random
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "software"))
sys.path.insert(0, os.path.join(ROOT, "hardware"))

import ciphers
from ciphers_new import gift64_enc, prince_enc, led64_enc, rectangle80_enc
from ascon_official import ascon_encrypt

results = []

# PRESENT-80, SPECK64/128, SIMON64/128, TEA, XTEA, AES-128 (published vectors)
for name, ok in ciphers.verify_all().items():
    results.append((name, ok, "published test vector"))

# GIFT-64, PRINCE, LED-64 (published all-zero vectors)
results.append(("GIFT-64", gift64_enc(0, 0) == 0xF62BC3EF34F775AC, "published test vector"))
results.append(("PRINCE", prince_enc(0, 0, 0) == 0x818665AA0D02DFDA, "published test vector"))
results.append(("LED-64", led64_enc(0, 0) == 0x39C2401003A0C798, "published test vector"))

# RECTANGLE-80: no published single-block vector was located, so this is a
# regression value produced by this implementation, plus a diffusion sanity check.
results.append(("RECTANGLE-80", rectangle80_enc(0, 0) == 0x0874E8B1E3542D96,
                "regression value (not a published vector)"))
random.seed(1)
flips = []
for _ in range(200):
    p, k = random.getrandbits(64), random.getrandbits(80)
    flips.append(bin(rectangle80_enc(p, k) ^ rectangle80_enc(p ^ 1, k)).count("1"))
mean_flip = sum(flips) / len(flips)
results.append(("RECTANGLE-80 avalanche", 28 <= mean_flip <= 36, f"mean flipped bits {mean_flip:.1f} of 64"))

# ASCON-AEAD128 (NIST SP 800-232), empty message and associated data, zero key and nonce
tag = ascon_encrypt(bytes(16), bytes(16), b"", b"").hex().upper()
results.append(("ASCON-AEAD128", tag == "F1E8DA91F9FBF090CAF3E37CCAD91BAE", "reference tag"))

width = max(len(n) for n, _, _ in results)
for name, ok, note in results:
    print(f"{name:<{width}}  {'PASS' if ok else 'FAIL'}  ({note})")
sys.exit(0 if all(ok for _, ok, _ in results) else 1)
