"""Generates the data figures of the survey from measured data."""
import json, random, statistics
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Rectangle
from ciphers import (present_key_schedule, _SBOX, _PBOX,
                     speck_key_schedule, simon_key_schedule,
                     _ror32, _rol32, MASK32, xtea_encrypt)

random.seed(7)
plt.rcParams.update({'font.size': 9, 'font.family': 'DejaVu Sans',
                     'axes.spines.top': False, 'axes.spines.right': False})
COL = {'PRESENT-80': '#4C72B0', 'SIMON64/128': '#DD8452', 'SPECK64/128': '#55A868',
       'TEA': '#C44E52', 'XTEA': '#8172B3', 'AES-128': '#937860'}

data = json.load(open('bench_results.json'))['results']
names = list(data.keys())

def popcount(x): return bin(x).count('1')

# ---------- round-reduced encryptors ----------
def present_r(pt, ks, r):
    s = pt
    for i in range(r):
        s ^= ks[i]
        o = 0
        for j in range(16): o |= _SBOX[(s >> (4*j)) & 0xF] << (4*j)
        s = 0
        for j in range(64): s |= ((o >> j) & 1) << _PBOX[j]
    return s ^ ks[r]

def speck_r(pt, ks, r):
    x, y = pt >> 32, pt & MASK32
    for k in ks[:r]:
        x = ((_ror32(x, 8) + y) & MASK32) ^ k
        y = _rol32(y, 3) ^ x
    return (x << 32) | y

def simon_r(pt, ks, r):
    x, y = pt >> 32, pt & MASK32
    for k in ks[:r]:
        x, y = y ^ (_rol32(x, 1) & _rol32(x, 8)) ^ _rol32(x, 2) ^ k, x
    return (x << 32) | y

def xtea_r(pt, key4, r):
    a, b = xtea_encrypt(pt >> 32, pt & MASK32, key4, rounds=r)
    return (a << 32) | b

pk = present_key_schedule(random.getrandbits(80))
kw = [random.getrandbits(32) for _ in range(4)]
spk, sik = speck_key_schedule(kw), simon_key_schedule(kw)
tk = [random.getrandbits(32) for _ in range(4)]

def aval_curve(enc, max_r, trials=800):
    ys = []
    for r in range(1, max_r + 1):
        f = []
        for _ in range(trials):
            pt = random.getrandbits(64)
            d = enc(pt, r) ^ enc(pt ^ (1 << random.randrange(64)), r)
            f.append(popcount(d) / 64 * 100)
        ys.append(statistics.mean(f))
    return ys

curves = {
    'PRESENT-80': aval_curve(lambda p, r: present_r(p, pk, r), 10),
    'SPECK64/128': aval_curve(lambda p, r: speck_r(p, spk, r), 10),
    'SIMON64/128': aval_curve(lambda p, r: simon_r(p, sik, r), 10),
    'XTEA': aval_curve(lambda p, r: xtea_r(p, tk, r), 10),
}
json.dump(curves, open('aval_curves.json', 'w'))

# ---------- Fig E1: performance (two panels) ----------
fig, (a1, a2) = plt.subplots(1, 2, figsize=(7.4, 2.9))
t = [data[n]['us_per_block'] for n in names]
th = [data[n]['kbps'] for n in names]
a1.bar(names, t, color=[COL[n] for n in names])
a1.set_yscale('log'); a1.set_ylabel('Time per block (microseconds, log scale)')
a1.set_title('(a) Encryption time per block', fontsize=9)
for i, v in enumerate(t): a1.text(i, v * 1.15, f'{v:g}', ha='center', fontsize=7)
a2.bar(names, th, color=[COL[n] for n in names])
a2.set_yscale('log'); a2.set_ylabel('Throughput (kbit/s, log scale)')
a2.set_title('(b) Software throughput', fontsize=9)
for i, v in enumerate(th): a2.text(i, v * 1.15, f'{v:,.0f}', ha='center', fontsize=7)
for a in (a1, a2): a.tick_params(axis='x', rotation=30)
fig.tight_layout(); fig.savefig('fig_perf.png', dpi=220); plt.close(fig)

# ---------- Fig E2: avalanche bars ----------
fig, ax = plt.subplots(figsize=(6.8, 3.0))
import numpy as np
x = np.arange(len(names)); w = 0.38
pt_v = [data[n]['aval_pt'] for n in names]; pt_e = [data[n]['aval_pt_sd'] for n in names]
k_v = [data[n]['aval_key'] for n in names]; k_e = [data[n]['aval_key_sd'] for n in names]
ax.bar(x - w/2, pt_v, w, yerr=pt_e, capsize=3, label='Plaintext avalanche', color='#4C72B0')
ax.bar(x + w/2, k_v, w, yerr=k_e, capsize=3, label='Key avalanche', color='#DD8452')
ax.axhline(50, ls='--', c='k', lw=1, label='Ideal (50%)')
ax.set_xticks(x); ax.set_xticklabels(names, rotation=25)
ax.set_ylabel('Ciphertext bits changed (%)'); ax.set_ylim(0, 62); ax.legend(fontsize=8, ncols=3)
fig.tight_layout(); fig.savefig('fig_avalanche.png', dpi=220); plt.close(fig)

# ---------- Fig E3: avalanche vs rounds ----------
fig, ax = plt.subplots(figsize=(6.4, 3.2))
for n, ys in curves.items():
    ax.plot(range(1, 11), ys, marker='o', ms=4, label=n, color=COL[n])
ax.axhline(50, ls='--', c='k', lw=1)
ax.set_xlabel('Number of rounds'); ax.set_ylabel('Mean avalanche (%)')
ax.set_xticks(range(1, 11)); ax.legend(fontsize=8)
fig.tight_layout(); fig.savefig('fig_rounds.png', dpi=220); plt.close(fig)

# ---------- Fig 1 redraw: IoT layered architecture ----------
fig, ax = plt.subplots(figsize=(5.6, 5.2)); ax.axis('off'); ax.set_xlim(0, 10); ax.set_ylim(0, 13)
def layer(y, title, items, fc):
    ax.add_patch(FancyBboxPatch((1, y), 8, 2.6, boxstyle='round,pad=0.12', fc=fc, ec='#333', lw=1.2))
    ax.text(5, y + 2.15, title, ha='center', fontsize=11, weight='bold')
    for i, it in enumerate(items):
        ax.text(1.6, y + 1.55 - i * 0.55, u'\u2022 ' + it, fontsize=9)
layer(9.9, 'Cloud / Data Center', ['Data aggregation', 'Analytics', 'Key management'], '#DCE9F7')
layer(5.4, 'Edge / Gateway', ['Protocol translation', 'Local encryption (AEAD)'], '#FBE7C6')
layer(0.9, 'Resource Constrained Devices', ['Sensors and actuators', 'Microcontroller (MCU)', 'Lightweight block cipher'], '#E6DEF2')
for y0, y1, lbl in [(9.9, 8.4, 'Secure channel (TLS / ECC)'), (5.4, 3.9, 'Encrypted communication')]:
    ax.add_patch(FancyArrowPatch((5, y0), (5, y1 + 0.4), arrowstyle='<->', mutation_scale=16, lw=1.6, color='#2A6AB0'))
    ax.text(5.25, (y0 + y1) / 2 + 0.15, lbl, fontsize=8.5, style='italic')
fig.tight_layout(); fig.savefig('fig1_arch.png', dpi=220); plt.close(fig)

# ---------- Fig 2 redraw: taxonomy tree ----------
fig, ax = plt.subplots(figsize=(7.6, 4.4)); ax.axis('off'); ax.set_xlim(0, 16); ax.set_ylim(0, 10)
def node(x, y, w, h, text, fc, fs=8.6, weight='normal'):
    ax.add_patch(FancyBboxPatch((x - w/2, y - h/2), w, h, boxstyle='round,pad=0.08', fc=fc, ec='#333', lw=1))
    ax.text(x, y, text, ha='center', va='center', fontsize=fs, weight=weight)
def edge(x1, y1, x2, y2):
    ax.plot([x1, x2], [y1, y2], c='#555', lw=1)
node(8, 9.2, 4.6, 0.95, 'Lightweight cryptography', '#D8D8D8', 10, 'bold')
node(3.2, 7.0, 3.9, 0.85, 'Symmetric primitives', '#BFD7F2', 9, 'bold')
node(8, 7.0, 3.6, 0.85, 'Asymmetric primitives', '#F6E3B4', 9, 'bold')
node(13, 7.0, 3.4, 0.85, 'Hash functions', '#D9C7EC', 9, 'bold')
for x in (3.2, 8, 13): edge(8, 8.75, x, 7.45)
node(1.7, 4.7, 2.9, 0.8, 'Block ciphers', '#DCEAF9')
node(4.8, 4.7, 2.9, 0.8, 'Stream ciphers', '#DCEAF9')
edge(3.2, 6.55, 1.7, 5.1); edge(3.2, 6.55, 4.8, 5.1)
node(1.7, 2.6, 3.1, 1.7, 'PRESENT\nGIFT\nSIMON / SPECK\nLED', '#EFF6FD', 8)
node(4.8, 2.8, 2.9, 1.3, 'Trivium\nGrain\nMICKEY', '#EFF6FD', 8)
edge(1.7, 4.3, 1.7, 3.5); edge(4.8, 4.3, 4.8, 3.45)
node(8, 4.7, 3.0, 0.8, 'ECC / NTRU', '#FBF1D8')
edge(8, 6.55, 8, 5.1)
node(8, 2.8, 3.4, 1.3, 'Lightweight AEAD:\nASCON, ACORN,\nTinyJAMBU', '#FDF7E5', 8)
edge(8, 4.3, 8, 3.45)
node(13, 4.6, 3.4, 1.4, 'SPONGENT\nPHOTON\nQUARK', '#F0E8F8', 8)
edge(13, 6.55, 13, 5.3)
fig.tight_layout(); fig.savefig('fig2_taxonomy.png', dpi=220); plt.close(fig)

# ---------- Fig 3: structure diagrams SPN / Feistel / ARX ----------
fig, axes = plt.subplots(1, 3, figsize=(8.6, 3.6))
for ax in axes: ax.axis('off'); ax.set_xlim(0, 10); ax.set_ylim(0, 12)
def box(ax, x, y, w, h, t, fc='#DCEAF9', fs=8):
    ax.add_patch(Rectangle((x - w/2, y - h/2), w, h, fc=fc, ec='#333', lw=1))
    ax.text(x, y, t, ha='center', va='center', fontsize=fs)
def arrow(ax, x1, y1, x2, y2):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle='->', mutation_scale=11, lw=1.2, color='#333'))
# SPN
a = axes[0]; a.set_title('(a) SPN round', fontsize=10)
box(a, 5, 11, 4.6, 1, 'State (n bits)', '#EEE')
arrow(a, 5, 10.5, 5, 9.6); box(a, 5, 9, 5.4, 1.1, 'Round key XOR', '#FBE7C6')
arrow(a, 5, 8.45, 5, 7.55)
for i, x in enumerate((2.4, 4.15, 5.9, 7.65)): box(a, x, 7, 1.5, 1, 'S', '#DCEAF9')
arrow(a, 5, 6.5, 5, 5.6); box(a, 5, 5, 6.4, 1.1, 'Bit permutation P', '#D9C7EC')
arrow(a, 5, 4.45, 5, 3.55); box(a, 5, 3, 4.6, 1, 'Next round', '#EEE')
# Feistel
a = axes[1]; a.set_title('(b) Feistel round', fontsize=10)
box(a, 3, 11, 2.6, 1, 'L(i)', '#EEE'); box(a, 7.4, 11, 2.6, 1, 'R(i)', '#EEE')
arrow(a, 7.4, 10.5, 7.4, 8.7); box(a, 7.4, 8, 2.8, 1.2, 'F(R, K(i))', '#FBE7C6')
arrow(a, 7.4, 7.4, 3.6, 6.2)
a.add_patch(plt.Circle((3, 6), 0.42, fc='w', ec='#333')); a.text(3, 6, '+', ha='center', va='center', fontsize=12)
arrow(a, 3, 10.5, 3, 6.45)
arrow(a, 3, 5.55, 7.4, 3.55); arrow(a, 7.4, 10.5, 8.9, 9.5); arrow(a, 8.9, 4.6, 3, 3.55)
a.plot([8.9, 8.9], [9.5, 4.6], c='#333', lw=1.2)
box(a, 3, 3, 2.6, 1, 'L(i+1)', '#EEE'); box(a, 7.4, 3, 2.6, 1, 'R(i+1)', '#EEE')
# ARX
a = axes[2]; a.set_title('(c) ARX round (SPECK style)', fontsize=10)
box(a, 3, 11, 2.6, 1, 'x(i)', '#EEE'); box(a, 7.4, 11, 2.6, 1, 'y(i)', '#EEE')
arrow(a, 3, 10.5, 3, 9.7); box(a, 3, 9.15, 3.2, 1, 'ROT right 8', '#D9C7EC')
arrow(a, 3, 8.65, 3, 7.95)
a.add_patch(plt.Circle((3, 7.5), 0.42, fc='w', ec='#333')); a.text(3, 7.5, '+', ha='center', va='center', fontsize=11); a.text(1.4, 7.5, 'mod add', fontsize=7, ha='center')
arrow(a, 7.4, 10.5, 7.4, 5.6); arrow(a, 7.4, 7.5, 3.45, 7.5)
arrow(a, 3, 7.05, 3, 6.3); box(a, 3, 5.75, 3.4, 1, 'XOR key K(i)', '#FBE7C6')
box(a, 7.4, 5.05, 3.2, 1, 'ROT left 3', '#D9C7EC')
arrow(a, 3, 5.25, 3, 3.55)
a.add_patch(plt.Circle((7.4, 3.9), 0.4, fc='w', ec='#333')); a.text(7.4, 3.9, '+', ha='center', va='center', fontsize=11); a.text(9.1, 3.9, 'XOR', fontsize=7, ha='center')
arrow(a, 7.4, 4.55, 7.4, 4.32); arrow(a, 3, 3.9, 6.98, 3.9)
box(a, 3, 3, 2.6, 1, 'x(i+1)', '#EEE'); box(a, 7.4, 2.6, 2.6, 1, 'y(i+1)', '#EEE')
arrow(a, 7.4, 3.5, 7.4, 3.12)
fig.tight_layout(); fig.savefig('fig3_structures.png', dpi=220); plt.close(fig)
print('figures done')
