"""Draws the interpreted-versus-compiled timing figure (fig_c_bench.png)
from bench_results.json (Python timings) and results_c.json (C timings)."""
import json
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

py = json.load(open('bench_results.json'))['results']
c = json.load(open('results_c.json'))
names = ['PRESENT-80', 'SIMON64/128', 'SPECK64/128', 'TEA', 'XTEA']
t_py = [py[n]['us_per_block'] for n in names]
t_c = [c[n]['ns_blk'] / 1000.0 for n in names]

x = np.arange(len(names)); w = 0.38
fig, ax = plt.subplots(figsize=(6.8, 3.2))
ax.bar(x - w / 2, t_py, w, color='#4C72B0', label='Python 3 (interpreted)')
ax.bar(x + w / 2, t_c, w, color='#55A868', label='C, gcc -O2 (compiled)')
for i, (a, b) in enumerate(zip(t_py, t_c)):
    ax.text(i + w / 2, b * 1.25, f'{int(a / b + 0.5)}x', ha='center', fontsize=7.5, color='#2B5F2E')
ax.set_yscale('log')
ax.set_ylabel('Time per 64-bit block (microseconds, log)', fontsize=8)
ax.set_xticks(x); ax.set_xticklabels(names, rotation=20, fontsize=8)
ax.spines['top'].set_visible(False); ax.spines['right'].set_visible(False)
ax.legend(fontsize=7.5, loc='upper right')
fig.tight_layout(); fig.savefig('fig_c_bench.png', dpi=220); plt.close(fig)
print('saved fig_c_bench.png')
