"""Fourth battery: standard image-cipher diagnostics.
1. Adjacent-pixel correlation in horizontal/vertical/diagonal directions (numbers + scatter plots)
2. Key sensitivity: one-bit key change must produce an unrelated ciphertext image
All computed from the actual SPECK64/128 CBC pipeline used in Section 9.9."""
import json, random
import numpy as np
from PIL import Image
from ciphers import speck_key_schedule, speck_encrypt

random.seed(11)
out = {}
P = np.array(Image.open('img_plain.png'), dtype=np.uint8)
H, W = P.shape

def cbc_encrypt(arr, spk, iv):
    data = arr.tobytes(); o = bytearray(); prev = iv
    for i in range(0, len(data), 8):
        blk = int.from_bytes(data[i:i+8], 'big') ^ prev
        x, y = speck_encrypt(blk >> 32, blk & 0xFFFFFFFF, spk)
        prev = (x << 32) | y
        o += prev.to_bytes(8, 'big')
    return np.frombuffer(bytes(o), dtype=np.uint8).reshape(H, W)

kw = [random.getrandbits(32) for _ in range(4)]
spk = speck_key_schedule(kw)
iv = random.getrandbits(64)
C = cbc_encrypt(P, spk, iv)
Image.fromarray(C).save('img_cbc_corr.png')

# ---------- 1. correlation in three directions ----------
def pairs(a, direction, n=3000):
    h, w = a.shape; xs = []; ys = []
    for _ in range(n):
        i = random.randrange(h - 1); j = random.randrange(w - 1)
        xs.append(int(a[i, j]))
        if direction == 'h': ys.append(int(a[i, j + 1]))
        elif direction == 'v': ys.append(int(a[i + 1, j]))
        else: ys.append(int(a[i + 1, j + 1]))
    return np.array(xs), np.array(ys)

def corr(a, d):
    x, y = pairs(a, d)
    return float(np.corrcoef(x, y)[0, 1]), x, y

out['correlation'] = {}
scatter_data = {}
for lbl, A in [('plain', P), ('cbc', C)]:
    out['correlation'][lbl] = {}
    scatter_data[lbl] = {}
    for d in ('h', 'v', 'd'):
        c, x, y = corr(A, d)
        out['correlation'][lbl][d] = round(c, 4)
        scatter_data[lbl][d] = (x, y)

print('correlation:', out['correlation'])

# ---------- 2. key sensitivity ----------
kw2 = list(kw); kw2[3] ^= 1  # flip a single key bit
spk2 = speck_key_schedule(kw2)
C2 = cbc_encrypt(P, spk2, iv)   # same IV, one-bit-different key
Image.fromarray(C2).save('img_cbc_key2.png')
diff_pct = float((C != C2).mean() * 100)
# also decrypt-with-wrong-key is symmetric here; report ciphertext divergence
mean_abs = float(np.abs(C.astype(int) - C2.astype(int)).mean())
out['key_sensitivity'] = dict(pixels_differing_pct=round(diff_pct, 2),
                              mean_abs_intensity_diff=round(mean_abs, 2),
                              key_bits_changed=1)
print('key sensitivity:', out['key_sensitivity'])

json.dump(out, open('results4.json', 'w'), indent=1)

# ---------- figures ----------
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
plt.rcParams.update({'font.size': 8.5, 'font.family': 'DejaVu Sans'})

# correlation scatter: 2 rows (plain, cbc) x 3 dirs
fig, axes = plt.subplots(2, 3, figsize=(7.6, 5.0))
dirnames = {'h': 'Horizontal', 'v': 'Vertical', 'd': 'Diagonal'}
for r, lbl in enumerate(('plain', 'cbc')):
    for cc, d in enumerate(('h', 'v', 'd')):
        ax = axes[r, cc]
        x, y = scatter_data[lbl][d]
        ax.scatter(x, y, s=2, alpha=0.35, color='#4C72B0' if lbl == 'plain' else '#C44E52', edgecolors='none')
        ax.set_xlim(0, 255); ax.set_ylim(0, 255)
        ax.set_title(f"{dirnames[d]}, r = {out['correlation'][lbl][d]:.3f}", fontsize=8.5)
        ax.set_xlabel('Pixel value at (i,j)', fontsize=7.5)
        if cc == 0:
            ax.set_ylabel(('Plaintext image\n' if lbl == 'plain' else 'CBC ciphertext\n') + 'neighbour value', fontsize=8)
        ax.tick_params(labelsize=7)
fig.tight_layout()
fig.savefig('fig_correlation.png', dpi=220); plt.close(fig)

# key sensitivity figure
fig, axes = plt.subplots(1, 3, figsize=(7.4, 2.7))
imgs = [C, C2, (C.astype(int) - C2.astype(int)) % 256]
titles = ['(a) Cipher under key K',
          '(b) Cipher under K with one bit flipped',
          f"(c) Difference: {out['key_sensitivity']['pixels_differing_pct']:.1f}% of pixels differ"]
for ax, A, t in zip(axes, imgs, titles):
    ax.imshow(A, cmap='gray', vmin=0, vmax=255); ax.set_title(t, fontsize=8.5); ax.axis('off')
fig.tight_layout()
fig.savefig('fig_keysens.png', dpi=220); plt.close(fig)
print('figures written')
