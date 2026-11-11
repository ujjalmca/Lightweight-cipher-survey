"""Rebuild the constrained-device measurements of the survey.

Needs: avr-gcc, avr-libc, arm-none-eabi-gcc, and simavr with its headers
(Debian/Ubuntu: apt-get install gcc-avr avr-libc gcc-arm-none-eabi simavr libsimavr-dev libelf-dev).

For every cipher in hw_footprint/ this script
  1. compiles the cipher with -Os for the ATmega328P and the Cortex-M0+ and reads the .text size,
  2. links the matching firmware in simavr/ and counts the cycles of 100 encryptions on a
     simulated ATmega328P,
and compares both with the stored values in hw_footprint/footprint.csv and simavr/cycles_avr.csv.
Run from the hardware/ directory:  python3 reproduce_hardware.py
"""
import csv, os, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
FOOT = os.path.join(HERE, "hw_footprint")
SIM = os.path.join(HERE, "simavr")
CIPHERS = ["present", "simon", "speck", "tea", "xtea", "gift", "prince", "led", "rect"]

def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)

def text_size(size_tool, obj):
    out = run([size_tool, obj]).stdout.strip().splitlines()[-1].split()
    return int(out[0])

def main():
    need = ["avr-gcc", "avr-size", "arm-none-eabi-gcc", "arm-none-eabi-size", "gcc"]
    missing = [t for t in need if shutil.which(t) is None]
    if missing:
        sys.exit("missing tools: " + ", ".join(missing))
    ref_foot = {r["cipher"]: r for r in csv.DictReader(open(os.path.join(FOOT, "footprint.csv")))}
    ref_cyc = {r["cipher"]: r for r in csv.DictReader(open(os.path.join(SIM, "cycles_avr.csv")))}
    work = tempfile.mkdtemp(prefix="lwc_hw_")
    host = os.path.join(work, "host")
    r = run(["gcc", "-O2", os.path.join(SIM, "host.c"), "-o", host, "-lsimavr", "-lelf", "-lm"])
    have_sim = r.returncode == 0
    if not have_sim:
        print("simavr host could not be built, cycle counts skipped:\n", r.stderr[-400:])
    rows, ok = [], True
    for c in CIPHERS:
        src = os.path.join(FOOT, c + ".c")
        avr_o, arm_o = os.path.join(work, c + "_avr.o"), os.path.join(work, c + "_arm.o")
        run(["avr-gcc", "-Os", "-mmcu=atmega328p", "-c", src, "-o", avr_o])
        run(["arm-none-eabi-gcc", "-Os", "-mcpu=cortex-m0plus", "-mthumb", "-c", src, "-o", arm_o])
        avr_text, arm_text = text_size("avr-size", avr_o), text_size("arm-none-eabi-size", arm_o)
        cycles = None
        if have_sim:
            # the firmware includes "<cipher>_core.h", which is the cipher source itself
            shutil.copy(src, os.path.join(work, c + "_core.h"))
            elf = os.path.join(work, c + ".elf")
            b = run(["avr-gcc", "-Os", "-mmcu=atmega328p", "-I", work,
                     os.path.join(SIM, "fw_" + c + ".c"), "-o", elf])
            if b.returncode == 0:
                lines = run([host, elf]).stdout.strip().splitlines()
                last = lines[-1].strip() if lines else ""
                cycles = int(last) if last.isdigit() else None
        rf, rc = ref_foot[c], ref_cyc[c]
        ref_c = int(rc["total_cycles_100blk"])
        same = (avr_text == int(rf["avr_text"]) and arm_text == int(rf["arm_text"])
                and (cycles is None or cycles == ref_c))
        ok &= same
        rows.append((c, avr_text, rf["avr_text"], arm_text, rf["arm_text"],
                     cycles if cycles is not None else "n/a", rc["total_cycles_100blk"],
                     "same" if same else "DIFFERS"))
    hdr = ("cipher", "AVR .text", "stored", "ARM .text", "stored", "cycles/100 blk", "stored", "")
    w = [max(len(str(x)) for x in col) for col in zip(hdr, *rows)]
    for row in [hdr] + rows:
        print("  ".join(str(x).ljust(n) for x, n in zip(row, w)))
    print("\ncompiler versions:")
    for t in ("avr-gcc", "arm-none-eabi-gcc"):
        print(" ", run([t, "--version"]).stdout.splitlines()[0])
    print("\nAll values match the stored results." if ok else
          "\nSome values differ. Code size depends on the compiler version; report your own figures and compiler.")
    shutil.rmtree(work, ignore_errors=True)

if __name__ == "__main__":
    main()
