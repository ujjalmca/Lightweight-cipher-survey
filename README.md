# Lightweight cipher survey: implementation and benchmark code

Code and raw results for the empirical evaluation in the manuscript

> U. K. Das, M. Kule, S. Ghosh Samaddar, "A Survey of Lightweight Cipher Architectures for
> Resource Constrained IoT Devices: Design Principles, Efficiency Trade offs, Empirical
> Evaluation, and Open Research Gaps" (manuscript under review).

Every table and figure in the empirical section of the manuscript is produced by the scripts
in this repository.

## Ciphers

| Cipher | Family | Python | C | Verified against |
|---|---|---|---|---|
| PRESENT-80 | SPN | `software/ciphers.py` | `software/lwc.c` | published test vector |
| SIMON64/128 | Feistel | `software/ciphers.py` | `software/lwc.c` | published test vector |
| SPECK64/128 | ARX | `software/ciphers.py` | `software/lwc.c` | published test vector |
| TEA, XTEA | Feistel (ARX round) | `software/ciphers.py` | `software/lwc.c` | published test vectors |
| AES-128 (baseline) | SPN | PyCryptodome | | FIPS-197 vector |
| GIFT-64 | SPN | `hardware/ciphers_new.py` | `hardware/lwc_new.c` | published test vector |
| PRINCE | SPN | `hardware/ciphers_new.py` | `hardware/lwc_new.c` | published test vector |
| LED-64 | SPN | `hardware/ciphers_new.py` | `hardware/lwc_new.c` | published test vector |
| RECTANGLE-80 | SPN | `hardware/ciphers_new.py` | `hardware/lwc_new.c` | internal checks only (see below) |
| ASCON-AEAD128 (reference) | sponge AEAD | `hardware/ascon_official.py` | | NIST SP 800-232 reference tag |

No single-block test vector for RECTANGLE-80 was located in its design document. That
implementation is checked by agreement between the bit-sliced and nibble S-box forms, by
encrypt/decrypt inversion, and by a fixed regression value. It is not checked against a
published vector.

`hardware/ascon_official.py` is the third-party `pyascon` reference implementation by the
Ascon designers. It is included unchanged for convenience and remains under its upstream
licence; see https://github.com/meichlseder/pyascon.

## Quick check

```
pip install -r requirements.txt
python3 tests/test_vectors.py                       # all known-answer tests, Python
gcc -O2 -DTEST_MAIN -o kat hardware/lwc_new.c && ./kat   # C known-answer tests
gcc -O2 -o lwc software/lwc.c && ./lwc                   # C self-test and desktop benchmark
```

## Reproducing the results

Run the scripts from inside their own directory, since they read and write files by
relative path.

| Script | Produces |
|---|---|
| `software/benchmark.py` | timing, throughput, avalanche, bit balance (`bench_results.json`) |
| `software/experiments2.py` | SAC matrices, exact S-box differential and linear tables, statistical tests, key schedule diffusion, ECB and CBC image encryption |
| `software/experiments3.py` | differential probability decay, minimum active S-box count for PRESENT, avalanche z-test, statistical battery with a biased control |
| `software/experiments4.py` | pixel correlation and key sensitivity |
| `software/figures.py` | the data figures |
| `hardware/exp_new.py`, `exp_new2.py`, `exp_new3.py` | the same security metrics for GIFT-64, PRINCE, LED-64, RECTANGLE-80 |

### Constrained-device measurements

`hardware/hw_footprint/` holds one self-contained C file per cipher. The read only code
size is the `.text` size reported after cross-compiling with `-Os`:

```
avr-gcc -Os -mmcu=atmega328p -c present.c && avr-size present.o
arm-none-eabi-gcc -Os -mcpu=cortex-m0plus -mthumb -c present.c && arm-none-eabi-size present.o
```

`hardware/simavr/` holds the firmware and host program used for the cycle counts on the
simulated ATmega328P. Each firmware runs 100 encryptions between two port markers and the
host reads the cycle counter difference.

`hardware/reproduce_hardware.py` rebuilds all of this in one step and compares the outcome
with the stored values:

```
sudo apt-get install gcc-avr avr-libc gcc-arm-none-eabi simavr libsimavr-dev libelf-dev
cd hardware && python3 reproduce_hardware.py
```

The stored figures were obtained with avr-gcc 7.3.0 and arm-none-eabi-gcc 13.2.1. Code size
depends on the compiler version, so other versions may give slightly different byte counts.

`reproduce_results.ipynb` in the repository root runs the tests, every experiment script and
the hardware rebuild, and reports which values match the stored results.

## Scope and limits

- The C sources are portable reference implementations, not hand-optimised assembly.
- Timing figures depend on the machine. Run the scripts on your own hardware and report
  your own platform; the structural results (avalanche, SAC, S-box tables, key schedule
  diffusion, code size) do not depend on the machine.
- The AVR cycle counts come from simulation with simavr, not from a physical board.
- Energy per bit, gate-equivalent area, and physical side-channel leakage are not measured.

## Licence

MIT for the code written for this study (see `LICENSE`). The bundled `ascon_official.py`
keeps its upstream licence.
