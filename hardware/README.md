# Constrained-device measurement code

## Verified cipher implementations
- ciphers_new.py     : GIFT-64, PRINCE, LED-64, RECTANGLE-80 (Python, test-vector verified)
- ascon_official.py  : Ascon-AEAD128 (NIST SP 800-232 reference, KAT-verified)
- lwc_new.c          : C ports of GIFT/PRINCE/LED/RECTANGLE (same KATs)

## Test vectors verified
- GIFT-64:      all-zero key/PT -> F62BC3EF34F775AC (Banik et al., CHES 2017)
- PRINCE:       5 KATs matched against lowRISC OpenTitan reference
- LED-64:       all-zero -> 39C2401003A0C798; second mixed vector also matches
- RECTANGLE-80: bit-slice SubColumn == nibble S-box; enc/dec inversion over 2000 cases
- ASCON-AEAD128: empty PT/AD, zero key/nonce -> tag F1E8DA91F9FBF090CAF3E37CCAD91BAE

## Hardware footprint (hw_footprint/)
Cross-compile each *.c with:
  avr-gcc  -Os -mmcu=atmega328p   -c cipher.c   (then avr-size)   -> 8-bit AVR ROM
  arm-none-eabi-gcc -Os -mcpu=cortex-m0plus -mthumb -c cipher.c (then size) -> ARM ROM

## Cycle-accurate 8-bit simulation (simavr/)
  host.c drives libsimavr; fw_*.c run 100 encryptions between two PORTB markers;
  host reads avr->cycle delta. Build: gcc host.c -o host -lsimavr

## Results
- hw_results.json     : merged ROM + AVR cycles per cipher
- exp_new_*.json      : avalanche, NIST monobit/entropy, key-schedule diffusion,
                        round-reduced diffusion, differential decay for the new ciphers

## Honest scope
Portable C reference implementations, not hand-optimised assembly. No energy-per-bit,
gate-equivalent, or physical side-channel numbers are produced here; those require
instrumented hardware and are cited from the surveyed literature only.
